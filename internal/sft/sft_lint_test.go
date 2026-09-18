package sft

// Port of tests/test_sft_lint.py (Task B): a minimal passing confirmed-critical
// trace mutated per test pins every lint rule — arc markers and order, the
// per-taxonomy requirements, reason completeness, pivot accounting, impact
// specificity, name anchoring, and dedup (hard for curation, warn for drafts).

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// lintTrace is `_trace(**over)`: a minimal passing confirmed-critical trace.
// Only IMPACT / OBSERVATION / PIVOT / INVARIANT are overridable, exactly as
// the Python fixture.
func lintTrace(over map[string]string) string {
	base := map[string]string{
		"OBSERVATION": "deposit() mints shares against the totalAssets " +
			"counter, never reading balanceOf(this).",
		"INITIAL FRAMING": "reentrancy hypothesis checked first.",
		"A1": "A1 (callback path): does transferFrom allow callback before " +
			"state settles?\n  -> REFUTED. state updates precede the external " +
			"call in both functions, so no callback window exists here.",
		"PIVOT": "the counter, not the call ordering, is the interesting property.",
		"A2": "A2 (direct transfer): can tokens reach the vault outside " +
			"deposit()?\n  -> CONFIRMED. ERC20 transfer is open to anyone and " +
			"nothing resyncs the counter.",
		"INVARIANT": "shares minted must be proportional to value contributed.",
		"IMPACT": "victim deposits 50,000 tokens and receives zero shares; " +
			"attacker drains 150,001 tokens from the pool.",
	}
	for k, v := range over {
		base[k] = v
	}
	parts := []string{
		"OBSERVATION: " + base["OBSERVATION"],
		"INITIAL FRAMING: " + base["INITIAL FRAMING"],
		base["A1"],
	}
	if _, hasPivot := base["PIVOT"]; hasPivot {
		parts = append(parts, "PIVOT: "+base["PIVOT"])
	}
	parts = append(parts,
		base["A2"],
		"INVARIANT: "+base["INVARIANT"],
		"IMPACT: "+base["IMPACT"])
	return strings.Join(parts, "\n\n")
}

type lintOpts struct {
	trace      string
	status     string
	taxonomy   string
	pivotCount *int
	stOver     []validation.KV
}

// lintEx is `_example(...)`.
func lintEx(t *testing.T, o lintOpts) validation.Value {
	t.Helper()
	tax := o.taxonomy
	if tax == "" {
		tax = "confirmed-critical"
	}
	status := o.status
	if status == "" {
		status = "draft"
	}
	pivots := 1 // the default trace has one PIVOT
	if o.pivotCount != nil {
		pivots = *o.pivotCount
	}
	trace := o.trace
	if trace == "" {
		trace = lintTrace(nil)
	}
	st := validation.VObj(
		kv("bug_class", validation.VStr("first-depositor-inflation")),
		kv("claim", validation.VStr("attacker inflates the share price "+
			"before a victim deposit so the victim mints zero shares")),
		kv("assumptions", validation.VArr(
			validation.VObj(
				kv("id", validation.VStr("A1")),
				kv("text", validation.VStr("callback path via transferFrom")),
				kv("status", validation.VStr("REFUTED")),
				kv("reason", validation.VStr("state updates precede the "+
					"external call in both functions"))),
			validation.VObj(
				kv("id", validation.VStr("A2")),
				kv("text", validation.VStr("direct ERC20 transfer reaches "+
					"the vault outside deposit()")),
				kv("status", validation.VStr("CONFIRMED")),
				kv("reason", validation.VStr("transfer is open to anyone; "+
					"the counter is never resynced"))))),
		kv("invariants", validation.VArr(validation.VObj(
			kv("statement", validation.VStr("shares minted must be "+
				"proportional to value contributed")),
			kv("status", validation.VStr("VIOLATED"))))),
		kv("expected_impact", validation.VStr("victim receives zero shares; "+
			"attacker drains the pool")),
		kv("next_test", validation.VStr("fork PoC: 1 wei deposit, direct "+
			"transfer, victim deposit, assert zero shares")),
		kv("pivot_count", validation.VInt(int64(pivots))))
	if len(o.stOver) > 0 {
		st = validation.VObj(mergeKV(st.O, o.stOver)...)
	}
	return validation.VObj(
		kv("id", validation.VStr("SFT-9001")),
		kv("version", validation.VInt(1)),
		kv("source", validation.VObj(
			kv("kind", validation.VStr("historical")),
			kv("ref", validation.VStr("lint-fixture")),
			kv("cluster", validation.VStr("lint-fixture")))),
		kv("taxonomy", validation.VStr(tax)),
		kv("status", validation.VStr(status)),
		kv("rejection_reasons", validation.VArr()),
		kv("partition", validation.VNull()),
		kv("messages", validation.VArr(
			validation.VObj(
				kv("role", validation.VStr("system")),
				kv("content", validation.VStr(promptText(t)))),
			validation.VObj(
				kv("role", validation.VStr("user")),
				kv("content", validation.VStr("<bundle>"))),
			validation.VObj(
				kv("role", validation.VStr("assistant")),
				kv("content", validation.VStr(trace))))),
		kv("structured", st),
		kv("provenance", validation.VObj(
			kv("bundle_provenance", validation.VStr("hand-written")))),
		kv("created_at", validation.VStr("2026-07-15T00:00:00Z")))
}

func hasPrefixReason(reasons []string, prefix string) bool {
	for _, r := range reasons {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

func hasContainsReason(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

func TestSFTLintCleanTracePasses(t *testing.T) {
	if got := LintExample(lintEx(t, lintOpts{}), nil, "draft"); len(got) != 0 {
		t.Fatalf("reasons = %v", got)
	}
}

func TestSFTLintSchemaFailureShortCircuits(t *testing.T) {
	ex := lintEx(t, lintOpts{})
	assumptions := atPath(ex, "structured", "assumptions").A
	assumptions[0] = setKey(assumptions[0], "id", validation.VStr("B1"))
	ex = setAt(ex, validation.VArr(assumptions...), "structured", "assumptions")
	reasons := LintExample(ex, nil, "draft")
	if len(reasons) != 1 || !strings.HasPrefix(reasons[0], "schema:") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestSFTLintSystemPromptDriftRejected(t *testing.T) {
	ex := lintEx(t, lintOpts{})
	msgs := atPath(ex, "messages").A
	msgs[0] = setKey(msgs[0], "content",
		validation.VStr(validation.ObjStr(msgs[0], "content")+"\n# extra instruction\n"))
	ex = setAt(ex, validation.VArr(msgs...), "messages")
	if !hasPrefixReason(LintExample(ex, nil, "draft"), "system-prompt drift") {
		t.Fatal("drift not rejected")
	}
}

func TestSFTLintMissingArcMarkersRejected(t *testing.T) {
	ex := lintEx(t, lintOpts{trace: "OBSERVATION: deposit() does things.\n" +
		"IMPACT: 5,000 tokens lost."})
	reasons := LintExample(ex, nil, "draft")
	if !hasContainsReason(reasons, "INITIAL FRAMING") {
		t.Fatalf("reasons = %v", reasons)
	}
	if !hasContainsReason(reasons, "assumption entry") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestSFTLintMissingReasonRejected(t *testing.T) {
	ex := lintEx(t, lintOpts{stOver: []validation.KV{}})
	assumptions := atPath(ex, "structured", "assumptions").A
	assumptions[1] = setKey(assumptions[1], "reason", validation.VStr("yes"))
	ex = setAt(ex, validation.VArr(assumptions...), "structured", "assumptions")
	reasons := LintExample(ex, nil, "draft")
	if !hasPrefixReason(reasons, "reason:") ||
		!hasContainsReason(reasons, "A2") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestSFTLintPivotCountMismatchRejected(t *testing.T) {
	// The default trace has one PIVOT while pivot_count says 0.
	ex := lintEx(t, lintOpts{pivotCount: intPtr(0)})
	if !hasPrefixReason(LintExample(ex, nil, "draft"), "pivot:") {
		t.Fatal("pivot mismatch not rejected")
	}
}

func TestSFTLintVagueImpactWithoutQuantifierRejected(t *testing.T) {
	ex := lintEx(t, lintOpts{trace: lintTrace(map[string]string{
		"IMPACT": "funds could be at risk if the counter is wrong."})})
	if !hasPrefixReason(LintExample(ex, nil, "draft"), "impact:") {
		t.Fatal("vague impact not rejected")
	}
}

func TestSFTLintVagueImpactWithQuantifierPasses(t *testing.T) {
	ex := lintEx(t, lintOpts{trace: lintTrace(map[string]string{
		"IMPACT": "funds could be at risk: the attacker extracts 150,001 " +
			"tokens from the pool."})})
	if hasPrefixReason(LintExample(ex, nil, "draft"), "impact:") {
		t.Fatal("quantified impact rejected")
	}
}

func TestSFTLintNameAnchoringRejected(t *testing.T) {
	ex := lintEx(t, lintOpts{trace: lintTrace(map[string]string{
		"OBSERVATION": "the vault looks suspicious because of how it is named."})})
	if !hasPrefixReason(LintExample(ex, nil, "draft"), "name-anchoring:") {
		t.Fatal("name anchoring not rejected")
	}
}

func TestSFTLintDedupCuratedCollisionHard(t *testing.T) {
	other := lintEx(t, lintOpts{})
	other = setKey(other, "id", validation.VStr("SFT-9002"))
	other = setKey(other, "status", validation.VStr("curated"))
	reasons := LintExample(lintEx(t, lintOpts{}), []validation.Value{other},
		"curated")
	if !hasPrefixReason(reasons, "dedup:") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestSFTLintDedupDraftCollisionIsWarning(t *testing.T) {
	other := lintEx(t, lintOpts{})
	other = setKey(other, "id", validation.VStr("SFT-9002"))
	other = setKey(other, "status", validation.VStr("curated"))
	reasons := LintExample(lintEx(t, lintOpts{}), []validation.Value{other},
		"draft")
	if !hasPrefixReason(reasons, "warn:dedup:") {
		t.Fatalf("reasons = %v", reasons)
	}
	if hasPrefixReason(reasons, "dedup:") {
		t.Fatalf("hard dedup on a draft: %v", reasons)
	}
}

func TestSFTLintDedupDifferentClaimNoCollision(t *testing.T) {
	other := lintEx(t, lintOpts{})
	other = setKey(other, "id", validation.VStr("SFT-9002"))
	other = setKey(other, "status", validation.VStr("curated"))
	other = setAt(other, validation.VStr("an oracle feed divergence lets an "+
		"attacker liquidate healthy positions below the true price"),
		"structured", "claim")
	reasons := LintExample(lintEx(t, lintOpts{}), []validation.Value{other},
		"curated")
	if hasPrefixReason(reasons, "dedup:") {
		t.Fatalf("false collision: %v", reasons)
	}
}

func TestSFTLintRealWeaknessRequiresRefutedAndHolds(t *testing.T) {
	ex := lintEx(t, lintOpts{taxonomy: "real-weakness-non-exploitable",
		pivotCount: intPtr(0)})
	// current trace has A1 REFUTED + VIOLATED invariant -> must fail on HOLDS
	if !hasContainsReason(LintExample(ex, nil, "draft"), "HOLDS") {
		t.Fatal("HOLDS not required")
	}
	inv := atPath(ex, "structured", "invariants").A
	inv[0] = setKey(inv[0], "status", validation.VStr("HOLDS"))
	ex = setAt(ex, validation.VArr(inv...), "structured", "invariants")
	if hasPrefixReason(LintExample(ex, nil, "draft"), "taxonomy:") {
		t.Fatalf("reasons = %v", LintExample(ex, nil, "draft"))
	}
}

func TestSFTLintInvalidHypothesisRequiresNamedMisread(t *testing.T) {
	ex := lintEx(t, lintOpts{taxonomy: "invalid-hypothesis",
		pivotCount: intPtr(0)})
	reasons := LintExample(ex, nil, "draft")
	if !hasContainsReason(reasons, "misread") &&
		!hasContainsReason(reasons, "actually") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestSFTLintBelowThresholdRequiresThresholdNote(t *testing.T) {
	ex := lintEx(t, lintOpts{taxonomy: "exploitable-below-threshold"})
	if !hasContainsReason(LintExample(ex, nil, "draft"), "threshold") {
		t.Fatal("threshold note not required")
	}
	msgs := atPath(ex, "messages").A
	msgs[2] = setKey(msgs[2], "content", validation.VStr(lintTrace(
		map[string]string{"IMPACT": "attacker extracts 50 tokens; below the " +
			"bounty threshold of 1,000 tokens, so it does not clear the bar."})))
	ex = setAt(ex, validation.VArr(msgs...), "messages")
	if hasContainsReason(LintExample(ex, nil, "draft"), "threshold") {
		t.Fatalf("reasons = %v", LintExample(ex, nil, "draft"))
	}
}

func TestSFTLintLintGateWired(t *testing.T) {
	useStore(t)
	bad := lintEx(t, lintOpts{})
	assumptions := atPath(bad, "structured", "assumptions").A
	assumptions[1] = setKey(assumptions[1], "reason", validation.VStr(""))
	bad = setAt(bad, validation.VArr(assumptions...), "structured", "assumptions")
	_, err := AddExample(bad, "draft")
	if err == nil || !strings.Contains(err.Error(), "lint failed") {
		t.Fatalf("err = %v", err)
	}
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	if len(validation.ObjAt(store, "examples").A) != 0 {
		t.Fatal("partial write")
	}
}

func TestSFTLintTraceAssumptionsLastArrowWins(t *testing.T) {
	content := "OBSERVATION: liquidate() reads latestRoundData().\n" +
		"INITIAL FRAMING: stale price.\n" +
		"A1 (stale feed): can the feed go stale?\n  -> OPEN initially. " +
		"checking math.\n" +
		"  -> REFUTED. a TWAP bound closes the window, so this framing dies here."
	if got := traceAssumptions(content)["A1"]; got != "REFUTED" {
		t.Fatalf("A1 = %q", got)
	}
}

func TestSFTLintArcSectionsMultiplePivotsJoined(t *testing.T) {
	content := "OBSERVATION: f() does x.\nINITIAL FRAMING: y.\nPIVOT: first " +
		"turn.\nPIVOT: second turn.\nINVARIANT: z.\nIMPACT: 10 wei lost."
	secs := arcSections(content)
	if strings.Count(secs["PIVOT"], "\n") < 1 ||
		!strings.Contains(secs["PIVOT"], "first turn") {
		t.Fatalf("PIVOT = %q", secs["PIVOT"])
	}
}

func TestSFTLintArcMarkersOutOfOrderRejected(t *testing.T) {
	rev := strings.Join([]string{
		"IMPACT: victim deposits 50,000 tokens and receives zero shares; " +
			"attacker drains 150,001 tokens.",
		"INVARIANT: shares minted must be proportional to value contributed.",
		"A2 (direct transfer): can tokens reach the vault outside deposit()?\n" +
			"  -> CONFIRMED. ERC20 transfer is open to anyone and nothing " +
			"resyncs the counter.",
		"PIVOT: the counter, not the call ordering, is the interesting property.",
		"A1 (callback path): does transferFrom allow callback before state " +
			"settles?\n  -> REFUTED. state updates precede the external call " +
			"in both functions.",
		"INITIAL FRAMING: reentrancy hypothesis checked first.",
		"OBSERVATION: deposit() mints shares against the totalAssets counter, " +
			"never reading balanceOf(this).",
	}, "\n\n")
	reasons := LintExample(lintEx(t, lintOpts{trace: rev}), nil, "draft")
	if !hasPrefixReason(reasons, "arc:") ||
		!hasContainsReason(reasons, "out of order") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestSFTLintArcAssumptionsBeforeFramingRejected(t *testing.T) {
	bad := "A1 (callback path): does transferFrom allow callback?\n" +
		"  -> REFUTED. no window exists here.\n\n" + lintTrace(nil)
	reasons := LintExample(lintEx(t, lintOpts{trace: bad}), nil, "draft")
	if !hasPrefixReason(reasons, "arc:") ||
		!hasContainsReason(reasons, "out of order") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestSFTLintArcIndentedAssumptionBeforeFramingRejected(t *testing.T) {
	bad := "  A0 (early): is there a callback window?\n" +
		"  -> CONFIRMED. state settles late here.\n\n" + lintTrace(nil)
	reasons := LintExample(lintEx(t, lintOpts{trace: bad}), nil, "draft")
	if !hasPrefixReason(reasons, "arc:") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestSFTLintArcRepeatedObservationAfterPivotRejected(t *testing.T) {
	trace := lintTrace(nil) +
		"\n\nOBSERVATION: late recheck of deposit() reads balanceOf(this)."
	reasons := LintExample(lintEx(t, lintOpts{trace: trace}), nil, "draft")
	if !hasPrefixReason(reasons, "arc:") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestSFTLintArcCanonicalOrderWithIndentedAssumptionPasses(t *testing.T) {
	trace := strings.Replace(lintTrace(nil), "\nA1 (callback path):",
		"\n  A1 (callback path):", 1)
	reasons := LintExample(lintEx(t, lintOpts{trace: trace}), nil, "draft")
	if hasPrefixReason(reasons, "arc:") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestSFTLintDedupAdversaryRenameStillCollides(t *testing.T) {
	repoStore(t)
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	var seed validation.Value
	for _, e := range validation.ObjAt(store, "examples").A {
		if validation.ObjStr(e, "id") == "SFT-0001" {
			seed = e
		}
	}
	if !strings.Contains(validation.ObjStr(atPath(seed, "structured"), "claim"), "attacker") {
		t.Fatal("seed claim missing 'attacker'")
	}
	modified := cloneValue(seed)
	modified = setKey(modified, "id", validation.VStr("SFT-9009"))
	modified = setAt(modified, validation.VStr(strings.Replace(
		validation.ObjStr(atPath(seed, "structured"), "claim"), "attacker", "adversary", 1)),
		"structured", "claim")
	reasons := LintExample(modified, []validation.Value{seed}, "curated")
	if !hasPrefixReason(reasons, "dedup:") {
		t.Fatalf("reasons = %v", reasons)
	}
}
