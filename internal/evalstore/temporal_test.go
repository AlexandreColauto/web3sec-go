package evalstore

// I1b (Wave I, Task 2): the scoring-time temporal + near-dup discipline.
//
// PartitionHealth answers TWO questions about the stored suite, and
// answers them with exclusions, never with mutations:
//
//   - TEMPORAL — is a held-out row older than the dev rows it is scored
//     against? `deployed_at` governs when BOTH rows carry a parseable
//     YYYY-MM-DD; otherwise the comparison falls back to `created_at`
//     (always present). A deployed_at that cannot be parsed makes the row
//     unorderable: it is excluded and reported, never guessed at.
//   - NEAR-DUP — does a held-out row restate a dev/training row? The key
//     is class + root-cause narrative + file basenames + repo, compared
//     with the EXISTING bigram-Jaccard rule at nearDupThreshold. That rule
//     lives in internal/textsim (archetypes.Jaccard delegates to it — this
//     package cannot import archetypes, which reaches evalstore through
//     structidx -> orchestrator -> risk).
//
// Same-partition pairs are NOT scanned: dev-dev duplication is the
// loader's problem, not the scorecard's.
//
// The scores in the near-dup tests are hand-computed in the comments:
// identical keys share every bigram, so |A∩B| = |A∪B| and Jaccard = 1.0.

import (
	"reflect"
	"strings"
	"testing"

	"websec/assets"
	"websec/internal/textsim"
	"websec/internal/validation"
)

// tc builds one evaluation case for the partition-health tests. The two
// dates are explicit because they ARE the rule under test, and the four
// near-dup key components (class, root-cause narrative, file, repo) are
// explicit so a test can make two rows duplicates deliberately — or
// deliberately not.
func tc(id, partition, deployed, created, class, rootCause, file, repo string) validation.Value {
	over := []validation.KV{
		kv("partition", validation.VStr(partition)),
		kv("created_at", validation.VStr(created)),
		kv("gold", validation.VObj(
			kv("outcome", validation.VStr("confirmed-exploitable")),
			kv("bug_class", validation.VStr(class)),
			kv("severity", validation.VStr("high")),
			kv("root_cause", validation.VStr(rootCause)),
			kv("locations", validation.VArr(validation.VObj(
				kv("file", validation.VStr(file)),
				kv("line", validation.VInt(1)))))),
		),
		kv("code", validation.VObj(
			kv("repo", validation.VStr(repo)),
			kv("commit", validation.VStr(strings.Repeat("c", 40))),
			kv("files", validation.VArr(validation.VStr(file))))),
	}
	if deployed != "" {
		over = append(over, kv("deployed_at", validation.VStr(deployed)))
	}
	return caseVal(id, over...)
}

// keyOf is the near-dup key the tests reason about.
func keyOf(t *testing.T, c validation.Value) string {
	t.Helper()
	return dupKey(c)
}

// excludedIDs lists the excluded case ids in report order (report order
// is canonical: sorted by case id, so two input orders agree).
func excludedIDs(h Health) []string {
	if len(h.Excluded) == 0 {
		return nil
	}
	out := make([]string, 0, len(h.Excluded))
	for _, e := range h.Excluded {
		out = append(out, objStr(e.Case, "case_id"))
	}
	return out
}

// reasonsOf tallies the exclusions by reason.
func reasonsOf(h Health) map[ExclusionReason]int {
	out := map[ExclusionReason]int{}
	for _, e := range h.Excluded {
		out[e.Reason]++
	}
	return out
}

// ---- temporal -----------------------------------------------------------

// TestDupKeyShape pins the near-dup key: lowercase class + root-cause
// narrative + file BASENAMES + repo, space-joined. The basename rule is
// what makes `src/Vault.sol` and `contracts/Vault.sol` the same anchor.
func TestDupKeyShape(t *testing.T) {
	c := tc("CASE-0000000000k1", "dev", "", "2026-01-01T00:00:00+00:00",
		"Reentrancy", "Funds Leave Before The Balance Zeroes",
		"src/deep/Vault.sol", "Acme/Vault")
	want := "reentrancy funds leave before the balance zeroes vault.sol acme/vault"
	if got := keyOf(t, c); got != want {
		t.Fatalf("dupKey = %q\nwant %q", got, want)
	}
}

// TestTemporalExcludesHeldOutStrictlyOlderThanDev: deployed_at governs
// when both rows carry one. The held-out row's created_at is NEWER than
// the dev row's, so a created_at comparison would keep the row — only
// the deployed_at comparison can produce the exclusion under test.
func TestTemporalExcludesHeldOutStrictlyOlderThanDev(t *testing.T) {
	dev := tc("CASE-0000000000d1", "dev", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	heldOld := tc("CASE-0000000000h1", "held-out", "2026-01-01",
		"2026-12-01T00:00:00+00:00", "oracle-manipulation",
		"the borrow limit is priced off spot reserves", "src/Lender.sol", "acme/lender")
	heldTie := tc("CASE-0000000000h2", "held-out", "2026-05-01",
		"2026-12-01T00:00:00+00:00", "flash-loan",
		"repayment is checked at a manipulable spot price", "src/Flash.sol", "acme/flash")

	h := PartitionHealthFull([]validation.Value{dev, heldOld, heldTie})
	if got := excludedIDs(h); !reflect.DeepEqual(got, []string{"CASE-0000000000h1"}) {
		t.Fatalf("excluded = %v, want only the strictly older held-out row", got)
	}
	if got := h.Excluded[0].Reason; got != ReasonTemporal {
		t.Fatalf("reason = %q, want %q", got, ReasonTemporal)
	}
	if len(h.Problems) != 0 {
		t.Fatalf("problems = %v, want empty (a temporal exclusion is a count, not a problem line)", h.Problems)
	}
	// The tie row ranks: the rule is STRICTLY older.
	if got := reasonsOf(h)[ReasonTemporal]; got != 1 {
		t.Fatalf("temporal count = %d, want 1", got)
	}
}

// TestTemporalFallsBackToCreatedAt: with no parseable deployed_at on both
// sides the comparison is created_at-vs-created_at, in BOTH directions.
// The second half pins the mixed case: ONE side parseable is not enough
// — the pair falls back too.
func TestTemporalFallsBackToCreatedAt(t *testing.T) {
	// Both absent: created_at decides (held older => excluded).
	devNoDep := tc("CASE-0000000000d1", "dev", "",
		"2026-06-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	heldNoDep := tc("CASE-0000000000h1", "held-out", "",
		"2026-01-01T00:00:00+00:00", "oracle-manipulation",
		"the borrow limit is priced off spot reserves", "src/Lender.sol", "acme/lender")
	h := PartitionHealthFull([]validation.Value{devNoDep, heldNoDep})
	if got := excludedIDs(h); !reflect.DeepEqual(got, []string{"CASE-0000000000h1"}) {
		t.Fatalf("both-absent excluded = %v, want the older held-out row", got)
	}

	// Mixed: dev parseable, held-out absent. Not "both parseable", so the
	// pair falls back to created_at — and by created_at the held-out row
	// is NEWER, so it ranks even though its deployed_at is unknown.
	devDep := tc("CASE-0000000000d2", "dev", "2026-01-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	heldMixed := tc("CASE-0000000000h2", "held-out", "",
		"2026-12-01T00:00:00+00:00", "oracle-manipulation",
		"the borrow limit is priced off spot reserves", "src/Lender.sol", "acme/lender")
	h = PartitionHealthFull([]validation.Value{devDep, heldMixed})
	if len(h.Excluded) != 0 {
		t.Fatalf("mixed-regime excluded = %v, want none (created_at fallback keeps it)",
			excludedIDs(h))
	}
}

// TestUnparseableDeployedAtExcludesTheRow: an unorderable date is
// fail-closed on the ROW (it does not rank, and an unparseable DEV row
// leaves the dev pool it would otherwise anchor) and fail-open on the RUN
// (the remaining rows still score). The problem line names the case.
func TestUnparseableDeployedAtExcludesTheRow(t *testing.T) {
	badShape := tc("CASE-0000000000h1", "held-out", "2026-1-1",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	badCalendar := tc("CASE-0000000000d1", "dev", "2026-02-30",
		"2026-01-01T00:00:00+00:00", "oracle-manipulation",
		"the borrow limit is priced off spot reserves", "src/Lender.sol", "acme/lender")
	badKind := caseVal("CASE-0000000000d2",
		kv("partition", validation.VStr("dev")),
		kv("created_at", validation.VStr("2026-01-01T00:00:00+00:00")),
		kv("deployed_at", validation.VInt(20260101)))
	// An ancient held-out row that would be excluded if the dev pool still
	// had an anchor — the two unusable dev rows must NOT anchor it.
	ancient := tc("CASE-0000000000h2", "held-out", "2020-01-01",
		"2020-01-01T00:00:00+00:00", "flash-loan",
		"repayment is checked at a manipulable spot price", "src/Flash.sol", "acme/flash")

	h := PartitionHealthFull([]validation.Value{badShape, badCalendar, badKind, ancient})
	wantProblems := []string{
		"unparseable-deployed_at CASE-0000000000d1",
		"unparseable-deployed_at CASE-0000000000d2",
		"unparseable-deployed_at CASE-0000000000h1",
	}
	if !reflect.DeepEqual(h.Problems, wantProblems) {
		t.Fatalf("problems = %v\nwant %v", h.Problems, wantProblems)
	}
	wantExcluded := []string{
		"CASE-0000000000d1", "CASE-0000000000d2", "CASE-0000000000h1",
	}
	if got := excludedIDs(h); !reflect.DeepEqual(got, wantExcluded) {
		t.Fatalf("excluded = %v\nwant %v", got, wantExcluded)
	}
	r := reasonsOf(h)
	if r[ReasonUnparseable] != 3 || r[ReasonTemporal] != 0 || r[ReasonNearDup] != 0 {
		t.Fatalf("reasons = %v, want 3 unparseable and nothing else", r)
	}
}

// ---- near-dup -----------------------------------------------------------

// TestNearDupExcludesHeldOutAgainstDev: the held-out row restates the dev
// row's key exactly. Hand-computed: both keys are the same string, so
// every bigram of A is a bigram of B and vice versa; |A∩B| = |A∪B|;
// Jaccard = 1.0 ≥ nearDupThreshold (0.8).
func TestNearDupExcludesHeldOutAgainstDev(t *testing.T) {
	dev := tc("CASE-0000000000d1", "dev", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	held := tc("CASE-0000000000h1", "held-out", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	if j := textsim.Jaccard(keyOf(t, dev), keyOf(t, held)); j < nearDupThreshold {
		t.Fatalf("fixture drift: Jaccard = %v, want >= %v by construction", j, nearDupThreshold)
	}
	h := PartitionHealthFull([]validation.Value{dev, held})
	if got := excludedIDs(h); !reflect.DeepEqual(got, []string{"CASE-0000000000h1"}) {
		t.Fatalf("excluded = %v, want the duplicate held-out row", got)
	}
	e := h.Excluded[0]
	if e.Reason != ReasonNearDup || e.Other != "CASE-0000000000d1" || e.Score != 1.0 {
		t.Fatalf("exclusion = %+v, want near-dup against the dev row at 1.0", e)
	}
	want := []string{"near-dup CASE-0000000000h1 ~ CASE-0000000000d1 1.0"}
	if !reflect.DeepEqual(h.Problems, want) {
		t.Fatalf("problems = %v\nwant %v", h.Problems, want)
	}
}

// TestNearDupIsAFuzzyMatchNotAnEquality: same class, same narrative, same
// repo, DIFFERENT file basename (Vault.sol vs Vault2.sol). Hand-computed
// with the bigram rule: the two keys differ only in the extra "2" bigram
// pair, and Jaccard lands at 0.9559 — well above the 0.8 cut, and well
// below exact equality. The threshold has to catch this.
func TestNearDupIsAFuzzyMatchNotAnEquality(t *testing.T) {
	dev := tc("CASE-0000000000d1", "dev", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	held := tc("CASE-0000000000h1", "held-out", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault2.sol", "acme/vault")
	j := textsim.Jaccard(keyOf(t, dev), keyOf(t, held))
	if j < nearDupThreshold || j >= 1.0 {
		t.Fatalf("fixture drift: Jaccard = %v, want [%v, 1.0)", j, nearDupThreshold)
	}
	h := PartitionHealthFull([]validation.Value{dev, held})
	if got := excludedIDs(h); !reflect.DeepEqual(got, []string{"CASE-0000000000h1"}) {
		t.Fatalf("excluded = %v, want the fuzzy duplicate", got)
	}
}

// TestNearDupBelowThresholdRanks: unrelated rows share nothing that
// matters. Hand-computed: the two keys differ in class, narrative, file
// AND repo, and Jaccard = 0.382979 — under the cut, so the held-out row
// ranks.
func TestNearDupBelowThresholdRanks(t *testing.T) {
	dev := tc("CASE-0000000000d1", "dev", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"the queue reverts the whole batch on one failing target",
		"src/Queue.sol", "acme/queue")
	held := tc("CASE-0000000000h1", "held-out", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "dos-griefing",
		"a signature digest omits the chain id so it replays",
		"src/Bridge.sol", "acme/bridge")
	if j := textsim.Jaccard(keyOf(t, dev), keyOf(t, held)); j >= nearDupThreshold {
		t.Fatalf("fixture drift: Jaccard = %v, want < %v", j, nearDupThreshold)
	}
	h := PartitionHealthFull([]validation.Value{dev, held})
	if len(h.Excluded) != 0 || len(h.Problems) != 0 {
		t.Fatalf("excluded = %v, problems = %v, want none", excludedIDs(h), h.Problems)
	}
}

// TestNearDupTrainingRowsAreReferences: a TRAINING row is a reference for
// the near-dup scan (dev/training), and the problem names it.
func TestNearDupTrainingRowsAreReferences(t *testing.T) {
	training := tc("CASE-0000000000t1", "training", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	held := tc("CASE-0000000000h1", "held-out", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	h := PartitionHealthFull([]validation.Value{training, held})
	if len(h.Excluded) != 1 || h.Excluded[0].Other != "CASE-0000000000t1" {
		t.Fatalf("excluded = %+v, want a near-dup against the training row",
			h.Excluded)
	}
}

// TestNearDupIgnoresSamePartitionPairs: dev-dev duplication is the
// loader's problem, not the scorecard's — nothing is excluded for it, and
// two identical HELD-OUT rows are not scanned against each other either.
func TestNearDupIgnoresSamePartitionPairs(t *testing.T) {
	dev1 := tc("CASE-0000000000d1", "dev", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	dev2 := tc("CASE-0000000000d2", "dev", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	held1 := tc("CASE-0000000000h1", "held-out", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "oracle-manipulation",
		"the borrow limit is priced off spot reserves", "src/Lender.sol", "acme/lender")
	held2 := tc("CASE-0000000000h2", "held-out", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "oracle-manipulation",
		"the borrow limit is priced off spot reserves", "src/Lender.sol", "acme/lender")
	h := PartitionHealthFull([]validation.Value{dev1, dev2, held1, held2})
	if len(h.Excluded) != 0 || len(h.Problems) != 0 {
		t.Fatalf("excluded = %v, problems = %v — same-partition pairs are not scanned",
			excludedIDs(h), h.Problems)
	}
}

// TestExclusionPrecedence: one reason per row, in the locked order
// unparseable > temporal > near-dup, so the counts can never
// double-count a row (and a row already out of the scorecard is not
// re-reported as a duplicate of the rows it was already dropped against).
func TestExclusionPrecedence(t *testing.T) {
	// Undatable AND a duplicate of the dev row: unparseable wins.
	dev := tc("CASE-0000000000d1", "dev", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	bad := tc("CASE-0000000000h1", "held-out", "not-a-date",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	// Older than dev AND a duplicate of it: temporal wins.
	old := tc("CASE-0000000000h2", "held-out", "2026-01-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	h := PartitionHealthFull([]validation.Value{dev, bad, old})
	r := reasonsOf(h)
	if r[ReasonUnparseable] != 1 || r[ReasonTemporal] != 1 || r[ReasonNearDup] != 0 {
		t.Fatalf("reasons = %v, want 1 unparseable + 1 temporal, no double count", r)
	}
}

// TestPartitionHealthIsOrderIndependent: the report is canonical. Same
// rows, two input orders, identical bytes — the problems sorted, the
// exclusions sorted by case id, and the counts unchanged.
func TestPartitionHealthIsOrderIndependent(t *testing.T) {
	dev := tc("CASE-0000000000d1", "dev", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	old := tc("CASE-0000000000h1", "held-out", "2026-01-01",
		"2026-01-01T00:00:00+00:00", "oracle-manipulation",
		"the borrow limit is priced off spot reserves", "src/Lender.sol", "acme/lender")
	dup := tc("CASE-0000000000z9", "held-out", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	bad := tc("CASE-0000000000a1", "held-out", "2026-13-40",
		"2026-01-01T00:00:00+00:00", "flash-loan",
		"repayment is checked at a manipulable spot price", "src/Flash.sol", "acme/flash")

	forward := PartitionHealthFull([]validation.Value{dev, old, dup, bad})
	reverse := PartitionHealthFull([]validation.Value{bad, dup, old, dev})
	if !reflect.DeepEqual(forward.Problems, reverse.Problems) {
		t.Fatalf("problems differ by input order:\n%v\n%v",
			forward.Problems, reverse.Problems)
	}
	if !reflect.DeepEqual(excludedIDs(forward), excludedIDs(reverse)) {
		t.Fatalf("exclusions differ by input order: %v vs %v",
			excludedIDs(forward), excludedIDs(reverse))
	}
	want := []string{
		"CASE-0000000000a1", // unparseable
		"CASE-0000000000h1", // temporal
		"CASE-0000000000z9", // near-dup
	}
	if got := excludedIDs(forward); !reflect.DeepEqual(got, want) {
		t.Fatalf("excluded = %v\nwant %v", got, want)
	}
}

// TestPartitionHealthLockedWrapper: the locked signature returns exactly
// the report's two halves.
func TestPartitionHealthLockedWrapper(t *testing.T) {
	dev := tc("CASE-0000000000d1", "dev", "2026-05-01",
		"2026-01-01T00:00:00+00:00", "reentrancy",
		"funds leave before the balance is zeroed", "src/Vault.sol", "acme/vault")
	held := tc("CASE-0000000000h1", "held-out", "2026-01-01",
		"2026-01-01T00:00:00+00:00", "oracle-manipulation",
		"the borrow limit is priced off spot reserves", "src/Lender.sol", "acme/lender")
	excluded, problems := PartitionHealth([]validation.Value{dev, held})
	if len(excluded) != 1 || objStr(excluded[0], "case_id") != "CASE-0000000000h1" {
		t.Fatalf("excluded = %v, want the older held-out row", excluded)
	}
	if len(problems) != 0 {
		t.Fatalf("problems = %v, want empty", problems)
	}
}

// TestSuiteHealthIsClean: the shipped 17-row pack carries parseable,
// uniform deployed_at dates and no held-out duplicate of a dev row — so
// the discipline moves ZERO bytes on the real store (this is what keeps
// the golden runs and the real --backtest output unchanged).
func TestSuiteHealthIsClean(t *testing.T) {
	cases, err := assets.LoadEvalCases()
	if err != nil {
		t.Fatalf("LoadEvalCases: %v", err)
	}
	excluded, problems := PartitionHealth(cases)
	if len(excluded) != 0 || len(problems) != 0 {
		t.Fatalf("shipped suite is not partition-clean: excluded=%v problems=%v",
			excludedIDs(PartitionHealthFull(cases)), problems)
	}
}
