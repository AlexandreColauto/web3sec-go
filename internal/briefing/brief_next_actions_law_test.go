package briefing

// brief_next_actions_law_test.go — Task 7 fix round 1 (review I-2): the law
// covers every minter that reaches the render boundary, not only the
// orchestrator catalog. briefing.NextActions mints its own lines (probe
// rows, lens routing, attention leads, the E6 queue, corpus/stuck/bounty/
// memory/terminal advisories, the closed-pass branch); every one of them
// must be a command-first `webv2 …` line with NO parenthesis anywhere in
// the line — the plan's own test regex is `\(`, and it does not exempt the
// `# reason` suffix.

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// lawBrief is one hand-built brief exercising every independent mint block
// of NextActions in a single pass (the blocks are keyed separately, so
// their lines never interfere).
func lawBrief() validation.Value {
	cid := t35ProbeCID
	rowEmitted := validation.VObj( // no priority_id: the emit branch
		kv("row_id", validation.VStr("row-emitted")),
		kv("lens", validation.VStr("L-01")),
		kv("axis", validation.VStr("liveness")),
		kv("name", validation.VStr("sweep the vault")))
	rowWorked := validation.VObj( // has priority_id: the work branch
		kv("row_id", validation.VStr("row-worked")),
		kv("lens", validation.VStr("L-03")),
		kv("axis", validation.VStr("reentrancy")),
		kv("name", validation.VStr("check the guard")),
		kv("priority_id", validation.VStr("Q-001")),
		kv("why", validation.VStr("untouched consensus surface")))
	queueLead := validation.VObj(
		kv("kind", validation.VStr("queue")),
		kv("priority_id", validation.VStr("Q-002")),
		kv("age", validation.VStr("2d1h")),
		kv("invariant_id", validation.VNull()),
		kv("severity_if_broken", validation.VNull()),
		kv("command", validation.VStr("webv2 answered "+cid+
			" Q-002 answered --reason R --actor A")))
	invariantLead := validation.VObj(
		kv("kind", validation.VStr("invariant")),
		kv("invariant_id", validation.VStr("INV-008")),
		kv("age", validation.VStr("3h12m")),
		kv("high_consequence", validation.VBool(true)),
		kv("command", validation.VStr("webv2 invariant-verify "+cid+
			" INV-008 --exec EXEC-*")))
	invariantDebt := validation.VObj(
		kv("invariant_id", validation.VStr("INV-009")),
		kv("high_consequence", validation.VBool(true)),
		kv("command", validation.VStr("webv2 invariant-verify "+cid+
			" INV-009 --exec EXEC-*")))
	materializable := validation.VObj(
		kv("members", validation.VArr(
			validation.VStr("F-000000000001"),
			validation.VStr("F-000000000002"))))
	stuck := validation.VObj(
		kv("finding_id", validation.VStr("F-000000000003")),
		kv("level", validation.VStr("E3")),
		kv("floor", validation.VStr("E6")),
		kv("missing", validation.VArr(validation.VStr("no pinned target"))))
	deficit := validation.VObj(
		kv("finding_id", validation.VStr("F-000000000004")),
		kv("status", validation.VStr("POSSIBLE")),
		kv("level", validation.VStr("E3")),
		kv("deficit", validation.VStr("needs E5")))
	readyF := validation.VObj(
		kv("finding_id", validation.VStr("F-000000000001")),
		kv("submission_ready", validation.VBool(true)))
	eligibleF := validation.VObj(
		kv("finding_id", validation.VStr("F-000000000004")),
		kv("eligible", validation.VBool(true)),
		kv("blocking_reasons", validation.VArr(
			validation.VStr("repro missing"))))
	memoryRow := validation.VObj(
		kv("memory_id", validation.VStr("M-1")),
		kv("kind", validation.VStr("lesson")),
		kv("status", validation.VStr("PENDING")))
	terminal := validation.VObj(
		kv("terminal_capability", validation.VStr("drain")),
		kv("path", validation.VArr(
			validation.VStr("F-000000000001"),
			validation.VStr("F-000000000002"))),
		kv("capital_usd", validation.VFloat(1000)))
	return validation.VObj(
		kv("campaign", validation.VObj(
			kv("closed", validation.VBool(false)),
			kv("campaign_id", validation.VStr(cid)))),
		kv("integrity", validation.VObj(
			kv("ok", validation.VBool(false)),
			kv("problems", validation.VArr(
				validation.VStr("state hash mismatch for campaigns/x"))))),
		kv("probe_surface", validation.VObj(
			kv("rows", validation.VInt(2)),
			kv("dispositioned", validation.VInt(0)),
			kv("open", validation.VInt(2)),
			kv("stale", validation.VBool(false)),
			kv("open_rows", validation.VArr(rowEmitted, rowWorked)))),
		kv("divergence", validation.VObj(
			kv("closed", validation.VBool(false)),
			kv("missing", validation.VArr(validation.VObj(
				kv("subject", validation.VStr("L-01 surface")),
				kv("what", validation.VStr(
					"no rows emitted for the liveness axis"))))),
			kv("lenses", validation.VArr(validation.VObj(
				kv("id", validation.VStr("L-04")),
				kv("status", validation.VStr("open")),
				kv("probe", validation.VNull())))))),
		kv("attention", validation.VObj(
			kv("ranked", validation.VArr(queueLead, invariantLead)),
			kv("invariants", validation.VObj(
				kv("items", validation.VArr(invariantDebt)))))),
		kv("economics", validation.VObj(
			kv("budget", validation.VObj(
				kv("spent_usd", validation.VFloat(120.5)),
				kv("max_total_cost_usd", validation.VFloat(100)))))),
		kv("findings", validation.VObj(
			kv("materializable_chains", validation.VArr(materializable)),
			kv("memory_recall_pending", validation.VArr(
				validation.VStr("F-000000000001"))),
			kv("structurally_unreachable", validation.VArr(stuck)),
			kv("gate_deficits", validation.VArr(deficit)))),
		kv("independent_verification_queue", validation.VArr(
			validation.VObj(
				kv("finding_id", validation.VStr("F-000000000001")),
				kv("evidence_level", validation.VStr("E4")),
				kv("effective_floor", validation.VStr("E6")),
				kv("mandatory", validation.VBool(true))))),
		kv("bounty", validation.VObj(
			kv("evaluated", validation.VArr(readyF, eligibleF)))),
		kv("pending_memory", validation.VArr(memoryRow)),
		kv("terminals", validation.VArr(terminal)))
}

// lawCheck fails on any law violation; it returns nothing so callers can
// assert block presence separately.
func lawCheck(t *testing.T, where string, actions []string) {
	t.Helper()
	if len(actions) == 0 {
		t.Fatalf("%s: no next actions", where)
	}
	for _, a := range actions {
		if !strings.HasPrefix(a, "webv2 ") {
			t.Errorf("%s: next action %q is not a command-first `webv2 …` "+
				"line", where, a)
		}
		if strings.ContainsAny(a, "()") {
			t.Errorf("%s: next action %q carries a parenthesis — the law "+
				"bans it everywhere in the line, comment included", where, a)
		}
	}
}

// TestNextActionsMintIsCommandFirst is the I-2 remedy witness: every
// briefing.go mint, not just the orchestrator catalog, obeys the law.
func TestNextActionsMintIsCommandFirst(t *testing.T) {
	actions, err := NextActions(lawBrief(), nil)
	if err != nil {
		t.Fatal(err)
	}
	lawCheck(t, "open-campaign blocks", actions)
	joined := strings.Join(actions, "\n")
	for _, marker := range []string{
		"work probe row ", "emit probe row ", "divergence gate open",
		// attention blocks mint the ledger's own command field, bare
		"webv2 answered " + t35ProbeCID + " Q-002 answered",
		"webv2 invariant-verify " + t35ProbeCID + " INV-008",
		"webv2 invariant-verify " + t35ProbeCID + " INV-009",
		"FIX INTEGRITY FIRST", "cost ceiling exceeded", "materialize chain",
		"independently verify", "memory recall pending", "structurally stuck",
		"submission ready", "finish ", "advance ", "human decision on",
		"terminal state reachable",
	} {
		if !strings.Contains(joined, marker) {
			t.Errorf("law brief lost the %q line — the block went silent: %v",
				marker, actions)
		}
	}
}

// TestClosedPassMintIsCommandFirst covers the closed-pass branch: a real
// completed campaign, hand-briefed, must mint command-first lines too.
func TestClosedPassMintIsCommandFirst(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Law Program", state.InitOpts{
		CampaignID: t35ProbeCID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete("alice", "pass closed: report generated"); err != nil {
		t.Fatal(err)
	}
	brief := validation.VObj(
		kv("campaign", validation.VObj(
			kv("closed", validation.VBool(true)),
			kv("campaign_id", validation.VStr(t35ProbeCID)))),
		kv("integrity", validation.VObj(
			kv("ok", validation.VBool(false)),
			kv("problems", validation.VArr(
				validation.VStr("state hash mismatch for campaigns/x"))))))
	actions, err := NextActions(brief, c)
	if err != nil {
		t.Fatal(err)
	}
	lawCheck(t, "closed pass", actions)
}
