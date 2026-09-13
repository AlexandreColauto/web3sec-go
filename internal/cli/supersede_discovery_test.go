package cli

// supersede_discovery_test.go: wave N, T5 — the three discoverability
// surfaces of `supersede`, each pinned:
//
//  1. `dedup`'s zero-action discovery line (exact bytes, stderr only, and
//     ABSENT the moment the sweep does anything — plus the JSON report the
//     command has always printed, unchanged and still parseable).
//  2. the false-positive adjudication nudge: names the live twin, stays
//     silent without one (different key, no twin, non-live twin, and the
//     adjudicated finding itself is never its own twin), never refuses, and
//     leaves BOTH the recorded row and the --json projection untouched.
//  3. the RUNBOOK cross-references (read through the embedded asset pack, so
//     the test proves the sentences SHIP with the binary, not merely that a
//     repo file contains them).
//
// No test here asserts anything about the precision math: T5 changes no
// accounting (the plan's ruling: no new basis, no second exclusion path).

import (
	"websec/internal/evalscore"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"websec/assets"
)

// assertDedupReport pins the dedup report's key set/order and returns the
// parsed object, so every case below also proves the discovery line never
// touched the machine-readable report.
func assertDedupReport(t *testing.T, out string) map[string]any {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("dedup stdout is not the JSON report: %v\n%s", err, out)
	}
	want := []string{"tier1_merges", "tier2_clusters", "tier3_flags",
		"cross_snapshot_flags", "untouched"}
	got := keyOrder(t, out)
	if len(got) != len(want) {
		t.Fatalf("key order %v, want %v", got, want)
	}
	for i, k := range want {
		if got[i] != k {
			t.Fatalf("key order %v, want %v", got, want)
		}
	}
	return report
}

// TestDedupZeroActionPrintsSupersedeHint: two live findings that no tier can
// prove equal (different classes, no signatures) — the sweep touches nothing,
// and the operator gets the ONE line that names the honest op instead of the
// false-positive adjudication. stdout stays the pure JSON report.
func TestDedupZeroActionPrintsSupersedeHint(t *testing.T) {
	c, root := t15Campaign(t, "dedup")
	t15Finding(t, c, "the first hypothesis", "logic-error")
	t15Finding(t, c, "the second hypothesis", "oracle-manipulation")

	code, out, errS := run(t, "--root", root, "dedup", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	report := assertDedupReport(t, out)
	if report["untouched"] != float64(2) {
		t.Fatalf("untouched = %v, want 2", report["untouched"])
	}
	// Exact bytes: one line, no color, no prefix, nothing else on stderr.
	if want := dedupZeroActionHint + "\n"; errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	// The line must actually say what the plan pinned it to say.
	for _, part := range []string{"manual self-duplicates",
		"webv2 supersede <C> F-new --of F-old", "evidence copied",
		"costs you precision instead"} {
		if !strings.Contains(errS, part) {
			t.Errorf("hint missing %q: %q", part, errS)
		}
	}
	if strings.Contains(out, "manual self-duplicates") {
		t.Error("the hint leaked into the JSON report on stdout")
	}
}

// TestDedupActionTakenPrintsNoHint: identical technical signatures merge in
// tier 1, so the sweep DID something and the discovery line must be absent —
// the action-taken path is byte-unchanged (same report, empty stderr).
func TestDedupActionTakenPrintsNoHint(t *testing.T) {
	c, root := t15Campaign(t, "dedup")
	t15Finding(t, c, "the first hypothesis", "logic-error")
	t15Finding(t, c, "the same hypothesis again", "logic-error")

	code, out, errS := run(t, "--root", root, "dedup", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	report := assertDedupReport(t, out)
	merges, _ := report["tier1_merges"].([]any)
	if len(merges) != 1 {
		t.Fatalf("tier1_merges = %v, want exactly 1 merge", report["tier1_merges"])
	}
	if report["untouched"] != float64(1) {
		t.Fatalf("untouched = %v, want 1", report["untouched"])
	}
	if errS != "" {
		t.Fatalf("action-taken sweep printed a hint: %q", errS)
	}
}

// TestDedupEmptyCampaignPrintsNoHint: zero actions over zero live findings is
// not the operator pain this hint exists for — "manual self-duplicates" with
// no findings would name a duplicate that cannot exist. (Pins the predicate's
// second clause.)
func TestDedupEmptyCampaignPrintsNoHint(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "dedup", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	report := assertDedupReport(t, out)
	if report["untouched"] != float64(0) {
		t.Fatalf("untouched = %v, want 0", report["untouched"])
	}
	if errS != "" {
		t.Fatalf("empty campaign printed a hint: %q", errS)
	}
}

// --- (2) the false-positive adjudication nudge ------------------------------

// adjFP is the false-positive record every case below uses (the reason must
// clear evalscore.AdjudicationReasonMin).
func adjFP(cid, finding string) []string {
	a := adjCmd{campaign: cid, finding: finding, verdict: "false-positive",
		basis: "reproduction", actor: "alice",
		reason: "the PoC reverts on the caller's own guard"}
	return a.args()
}

// TestAdjudicateFalsePositiveNudgeNamesTwin: two live findings sharing
// (root_cause.class, affected[0].path) — a manual self-duplicate no tier can
// prove. The FP adjudication is ACCEPTED exactly as before; the nudge names
// the twin on stderr.
func TestAdjudicateFalsePositiveNudgeNamesTwin(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	f1 := adjudicateFinding(t, c, "logic-error", "src/Other.sol")
	f2 := adjudicateFinding(t, c, "logic-error", "src/Other.sol")

	code, out, errS := run(t, append([]string{"--root", root},
		adjFP(c.CampaignID, f1)...)...)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "adjudicated "+f1+" as false-positive") {
		t.Fatalf("the FP was not accepted: %q", out)
	}
	// The tally the record prints is the same accounting the audit renders:
	// the FP is IN it, on its own bucket (the nudge downgrades nothing).
	if !strings.Contains(out, "false-positive 1") {
		t.Fatalf("the tally did not count the FP:\n%s", out)
	}
	want := fmt.Sprintf("this looks like a self-duplicate of %s: webv2 "+
		"supersede may be the honest op — FP stays recorded either way\n", f2)
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	// "FP stays recorded either way": the row is in the store.
	code, out, errS = run(t, "--root", root, "adjudicate", c.CampaignID)
	if code != 0 {
		t.Fatalf("list exit %d: %q", code, errS)
	}
	if !strings.Contains(out, f1) || !strings.Contains(out, "false-positive") {
		t.Fatalf("the recorded row is missing:\n%s", out)
	}
}

// TestAdjudicateFalsePositiveNonDuplicateIsSilent: same file, different class
// (and same class, different file) is NOT a self-duplicate — no match, no
// nudge, no noise.
func TestAdjudicateFalsePositiveNonDuplicateIsSilent(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	f1 := adjudicateFinding(t, c, "logic-error", "src/Other.sol")
	// (a) different class, same path; (b) same class, different path.
	adjudicateFinding(t, c, "reentrancy", "src/Other.sol")
	adjudicateFinding(t, c, "logic-error", "src/Elsewhere.sol")

	code, out, errS := run(t, append([]string{"--root", root},
		adjFP(c.CampaignID, f1)...)...)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if errS != "" {
		t.Fatalf("non-duplicate FP printed a nudge: %q", errS)
	}
}

// TestAdjudicateFalsePositiveSingleFindingIsSilent: the adjudicated finding
// is never its own twin (the row is still live when the nudge runs).
func TestAdjudicateFalsePositiveSingleFindingIsSilent(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	f1 := adjudicateFinding(t, c, "logic-error", "src/Other.sol")

	code, _, errS := run(t, append([]string{"--root", root},
		adjFP(c.CampaignID, f1)...)...)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("a lone finding was nudged against itself: %q", errS)
	}
}

// TestAdjudicateFalsePositiveNonLiveTwinIsSilent: the twin leaves the live set
// (OUT_OF_SCOPE) — the nudge reads live findings only, so it goes quiet; the
// retired row is not a candidate for `supersede`.
func TestAdjudicateFalsePositiveNonLiveTwinIsSilent(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	f1 := adjudicateFinding(t, c, "logic-error", "src/Other.sol")
	f2 := adjudicateFinding(t, c, "logic-error", "src/Other.sol")

	if code, _, errS := run(t, "--root", root, "move", c.CampaignID, f2,
		"OUT_OF_SCOPE", "--reason", "same mechanism, tracked by "+f1); code != 0 {
		t.Fatalf("move exit %d: %q", code, errS)
	}
	code, out, errS := run(t, append([]string{"--root", root},
		adjFP(c.CampaignID, f1)...)...)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if errS != "" {
		t.Fatalf("a non-live twin produced a nudge: %q", errS)
	}
}

// TestAdjudicateFalsePositiveNudgeIsStderrOnlyJSONUnchanged: with --json the
// nudge must not touch stdout — same key set, same key ORDER, no nudge text,
// and the verdict still counted. The control campaign (no twin) must print the
// identical key order, so the nudge provably adds no key anywhere.
func TestAdjudicateFalsePositiveNudgeIsStderrOnlyJSONUnchanged(t *testing.T) {
	wantKeys := []string{"campaign_id", "adjudications", "adjusted_precision",
		"unanchored", "additional_true_positive", "false_positive",
		"assumption_gated", "unadjudicated"}

	twin, twinRoot := adjudicateCampaign(t, "ES03BankReentrancy")
	tf1 := adjudicateFinding(t, twin, "logic-error", "src/Other.sol")
	tf2 := adjudicateFinding(t, twin, "logic-error", "src/Other.sol")
	code, out, errS := run(t, append(append([]string{"--root", twinRoot},
		adjFP(twin.CampaignID, tf1)...), "--json")...)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if want := fmt.Sprintf("this looks like a self-duplicate of %s: webv2 "+
		"supersede may be the honest op — FP stays recorded either way\n",
		tf2); errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json stdout is not JSON: %v\n%s", err, out)
	}
	got := keyOrder(t, out)
	if len(got) != len(wantKeys) {
		t.Fatalf("key order %v, want %v", got, wantKeys)
	}
	for i, k := range wantKeys {
		if got[i] != k {
			t.Fatalf("key order %v, want %v", got, wantKeys)
		}
	}
	if report["false_positive"] != float64(1) {
		t.Fatalf("false_positive = %v, want 1", report["false_positive"])
	}
	for _, leak := range []string{"self-duplicate", "supersede"} {
		if strings.Contains(out, leak) {
			t.Errorf("the nudge leaked into the JSON projection: %q", leak)
		}
	}

	// Control: no twin => no nudge, and the SAME key order.
	ctrl, ctrlRoot := adjudicateCampaign(t, "ES03BankReentrancy")
	cf1 := adjudicateFinding(t, ctrl, "logic-error", "src/Other.sol")
	code, out2, errS2 := run(t, append(append([]string{"--root", ctrlRoot},
		adjFP(ctrl.CampaignID, cf1)...), "--json")...)
	if code != 0 {
		t.Fatalf("control exit %d: %q", code, errS2)
	}
	if errS2 != "" {
		t.Fatalf("control printed a nudge: %q", errS2)
	}
	got2 := keyOrder(t, out2)
	if strings.Join(got2, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("control key order %v, want %v", got2, wantKeys)
	}
}

// TestAdjudicateOtherVerdictsNeverNudge: only the false-positive verdict
// claims the finding is wrong, so the other two are never nudged — even with a
// live twin sitting right there.
func TestAdjudicateOtherVerdictsNeverNudge(t *testing.T) {
	for _, verdict := range []string{"additional-true-positive",
		"assumption-gated"} {
		t.Run(verdict, func(t *testing.T) {
			c, root := adjudicateCampaign(t, "ES03BankReentrancy")
			f1 := adjudicateFinding(t, c, "logic-error", "src/Other.sol")
			adjudicateFinding(t, c, "logic-error", "src/Other.sol")

			a := adjCmd{campaign: c.CampaignID, finding: f1, verdict: verdict,
				basis: "author-review", actor: "alice",
				reason: "this is a real bug the suite has no case for"}
			if verdict == "assumption-gated" {
				a.assumption = "the oracle is updatable by any caller"
			}
			code, _, errS := run(t, append([]string{"--root", root},
				a.args()...)...)
			if code != 0 {
				t.Fatalf("exit %d: %q", code, errS)
			}
			if errS != "" {
				t.Fatalf("%s printed a nudge: %q", verdict, errS)
			}
		})
	}
}

// --- (3) the RUNBOOK cross-references ---------------------------------------

// TestSupersedeRunbookCrossrefs: the two cross-references (the dedup paragraph
// and the adjudication section) must SHIP — the test reads the embedded asset
// pack the binary actually carries.
func TestSupersedeRunbookCrossrefs(t *testing.T) {
	raw, err := assets.RunbookFS.ReadFile("runbook/RUNBOOK.md")
	if err != nil {
		t.Fatalf("embedded runbook: %v", err)
	}
	doc := string(raw)
	// One cross-reference each: the dedup paragraph (§6) and the adjudication
	// section (§6b, where FP/precision is discussed) — and the adjudication
	// one must actually spell out the op, not just allude to it.
	for _, want := range []string{
		"Adjudicating it false-positive is not that op",
		"nudges the twin's id on stderr",
		"is double-booked — `webv2 supersede <C-xxx>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("runbook is missing the cross-reference %q", want)
		}
	}
}

// TestNudgeVerdictConstantMatchesEvalscore is the reviewer's self-healing
// cross-check: the nudge keys on the string evalscore adjudicates as
// false-positive; if either side ever renames it, this fails at compile-adjacent
// test time instead of silently dead-ending the hook.
func TestNudgeVerdictConstantMatchesEvalscore(t *testing.T) {
	for _, v := range evalscore.Verdicts {
		if v == adjudicateFalsePositive {
			return
		}
	}
	t.Fatalf("nudge constant %q is no longer an evalscore verdict",
		adjudicateFalsePositive)
}
