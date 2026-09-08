package cli

// cmd_gate_checklist_test.go: the CLI half of tests/test_gate_checklist.py —
// `gate <campaign> FINDING` prints every LIVE clause with its verdict, the
// fix line follows the failing clause, the delta comes from the refused
// transition's own `finding.gate_attempt` event, and clauses that share a
// check id are qualified by their subject.
//
// Where the Python test drives `webv2 move` (deferred-P1: the transition
// command is not ported yet) the refusal is driven at the state level through
// findings.Transition — the exact code path the command calls.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

const cliCeiling = "capacity basis: the sink is an address[255] test " +
	"constant — no live liquidity bounds it"

// cliAttempt refuses a real CONFIRMED transition (POSSIBLE is the legal
// source status for CONFIRMED), recording the gate_attempt event.
func cliAttempt(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	if _, err := findings.Transition(c, fid, "POSSIBLE",
		"advance to the confirmation rung", "operator", "", false); err != nil {
		t.Fatalf("move POSSIBLE: %v", err)
	}
	_, err := findings.Transition(c, fid, "CONFIRMED", "gate attempt",
		"operator", "", false)
	if err == nil {
		t.Fatal("CONFIRMED must be refused")
	}
	if !strings.Contains(err.Error(), "CONFIRMED gate failed") {
		t.Fatalf("refusal = %q", err.Error())
	}
}

// cliPassingLogicError is _passing_logic_error: a finding that satisfies
// every CONFIRMED clause.
func cliPassingLogicError(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	f := t15Finding(t, c, "a logic flow hypothesis", "logic-error")
	fid := objStr(f, "finding_id")
	rec := t15ExecRecordFor(t, c, "EXEC-0000000001", fid)
	item := validation.VObj(
		kvT("evidence_id", validation.VStr("EV-1")),
		kvT("level", validation.VStr("E4")),
		kvT("type", validation.VStr("foundry-test")),
		kvT("description", validation.VStr("PoC passes")),
		kvT("sandbox_profile", objAt(rec, "profile")),
		kvT("artifact_id", objAt(rec, "exec_id")),
	)
	if _, err := findings.AddEvidence(c, fid, item); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDictCLI(objAt(vf, "verification"))
	ver = setObjFieldCLI(ver, "reproduction", validation.VObj(
		kvT("tier_reached", validation.VStr("T2")),
		kvT("status", validation.VStr("reproduced")),
		kvT("attempts", validation.VArr())))
	vf = setObjFieldCLI(vf, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"mechanism sound"); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kvT("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
			kvT("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	out, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// cliAlmostPassing is the delta fixture: everything but the critic verdict.
func cliAlmostPassing(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	f := t15Finding(t, c, "a logic flow hypothesis", "logic-error")
	fid := objStr(f, "finding_id")
	rec := t15ExecRecordFor(t, c, "EXEC-0000000001", fid)
	item := validation.VObj(
		kvT("evidence_id", validation.VStr("EV-1")),
		kvT("level", validation.VStr("E4")),
		kvT("type", validation.VStr("foundry-test")),
		kvT("description", validation.VStr("PoC passes")),
		kvT("sandbox_profile", objAt(rec, "profile")),
		kvT("artifact_id", objAt(rec, "exec_id")),
	)
	if _, err := findings.AddEvidence(c, fid, item); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDictCLI(objAt(vf, "verification"))
	ver = setObjFieldCLI(ver, "reproduction", validation.VObj(
		kvT("tier_reached", validation.VStr("T2")),
		kvT("status", validation.VStr("reproduced")),
		kvT("attempts", validation.VArr())))
	vf = setObjFieldCLI(vf, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kvT("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
			kvT("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	out, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// countClauseMarks counts the "✓ " marks the checklist printed.
func countClauseMarks(out string) int {
	return strings.Count(out, "✓ ")
}

// Port of test_checklist_prints_every_clause_with_verdict.
func TestChecklistPrintsEveryClauseWithVerdict(t *testing.T) {
	c, root := t15Campaign(t, "checklist")
	f := t15Finding(t, c, "an inflation hypothesis",
		"first-depositor-inflation")
	fid := objStr(f, "finding_id")
	clauses, err := findings.ConfirmationGateClauses(c, f)
	if err != nil {
		t.Fatal(err)
	}
	failing := 0
	for _, cl := range clauses {
		if !cl.OK {
			failing++
		}
	}
	if failing == 0 {
		t.Fatal("fixture must fail at least one clause")
	}
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q\n%s", code, errS, out)
	}
	for _, cl := range clauses {
		mark := "✓"
		if !cl.OK {
			mark = "✗"
		}
		if !strings.Contains(out, "  "+mark+" "+cl.CheckID) {
			t.Fatalf("clause %q missing from:\n%s", cl.ID(), out)
		}
	}
	if want := fmt.Sprintf("%d of %d check(s) failing", failing,
		len(clauses)); !strings.Contains(out, want) {
		t.Fatalf("output missing %q:\n%s", want, out)
	}
	if !strings.Contains(out, "fix:") {
		t.Fatalf("failures must carry their fix line:\n%s", out)
	}
	for _, cl := range clauses {
		if cl.OK && strings.Contains(out, "  ✗ "+cl.CheckID) {
			t.Fatalf("satisfied clause %q printed a failure line", cl.ID())
		}
	}
}

// Port of test_checklist_fix_line_follows_the_failing_clause.
func TestChecklistFixLineFollowsTheFailingClause(t *testing.T) {
	c, root := t15Campaign(t, "fixlines")
	f := t15Finding(t, c, "an inflation hypothesis",
		"first-depositor-inflation")
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID,
		objStr(f, "finding_id"))
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	lines := strings.Split(out, "\n")
	idx := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "  ✗ critic-verdict") {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("no critic-verdict failure line:\n%s", out)
	}
	if idx+1 >= len(lines) || !strings.HasPrefix(lines[idx+1],
		"    fix: webv2 verdict") {
		t.Fatalf("next line after the failure = %q", lines[idx+1])
	}
}

// Port of test_all_pass_still_exits_zero.
func TestAllPassStillExitsZero(t *testing.T) {
	c, root := t15Campaign(t, "allpass")
	t15GlobalRow(t, "MEM-global01", "logic-error")
	f := cliPassingLogicError(t, c)
	fid := objStr(f, "finding_id")
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	if !strings.Contains(out, "all checks pass") {
		t.Fatalf("output %q", out)
	}
	if strings.Contains(out, "✗") {
		t.Fatalf("all-pass output carries a failure:\n%s", out)
	}
	clauses, err := findings.ConfirmationGateClauses(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if got := countClauseMarks(out); got != len(clauses) {
		t.Fatalf("✓ marks = %d, clauses = %d", got, len(clauses))
	}
}

// Port of test_delta_none_recorded_without_an_attempt.
func TestDeltaNoneRecordedWithoutAnAttempt(t *testing.T) {
	c, root := t15Campaign(t, "delta-none")
	f := t15Finding(t, c, "an inflation hypothesis",
		"first-depositor-inflation")
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID,
		objStr(f, "finding_id"))
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	if !strings.Contains(out, "since last attempt: (none recorded)") {
		t.Fatalf("output %q", out)
	}
}

// Port of test_delta_reports_fixed_and_newly_failing.
func TestDeltaReportsFixedAndNewlyFailing(t *testing.T) {
	c, root := t15Campaign(t, "delta")
	t15GlobalRow(t, "MEM-global01", "logic-error")
	f := cliAlmostPassing(t, c)
	fid := objStr(f, "finding_id")
	// only the critic verdict is open -> the refusal records exactly that id
	cliAttempt(t, c, fid)
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	attempts := []validation.Value{}
	for _, e := range events {
		if objStr(e, "type") == "finding.gate_attempt" {
			attempts = append(attempts, e)
		}
	}
	if len(attempts) != 1 {
		t.Fatalf("gate_attempt events = %d, want 1", len(attempts))
	}
	data := asDictCLI(objAt(attempts[0], "data"))
	if objStr(data, "finding") != fid ||
		validation.CanonCompact(objAt(data, "check_ids")) != `["critic-verdict"]` {
		t.Fatalf("recorded attempt data = %s", validation.CanonCompact(data))
	}
	// no change yet -> an honest no-change line
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	if !strings.Contains(out, "since last attempt: no change (critic-verdict)") {
		t.Fatalf("output %q", out)
	}
	// fix critic-verdict; break the evidence floor -> one ✓ and one ✗
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"mechanism sound"); err != nil {
		t.Fatal(err)
	}
	loaded, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	loaded = setObjFieldCLI(loaded, "evidence", validation.VArr())
	if err := findings.SaveFinding(c, &loaded); err != nil {
		t.Fatal(err)
	}
	code, out, errS = run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	if !strings.Contains(out, "since last attempt: critic-verdict ✓") ||
		!strings.Contains(out, "since last attempt: evidence-floor ✗") {
		t.Fatalf("delta lines missing:\n%s", out)
	}
}

// Port of test_delta_lines_are_deterministic_for_multiple_ids.
func TestDeltaLinesAreDeterministicForMultipleIDs(t *testing.T) {
	clauses := []findings.Clause{
		{CheckID: "a", OK: true},
		{CheckID: "b", OK: false, Message: "m"},
		{CheckID: "c", OK: true},
	}
	got := gateDeltaLines(clauses, []string{"a", "c"})
	want := []string{"since last attempt: a ✓", "since last attempt: b ✗",
		"since last attempt: c ✓"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("delta = %v, want %v", got, want)
	}
	// a clause that no longer EXISTS in the live set was fixed too
	got = gateDeltaLines(clauses, []string{"b", "gone"})
	if len(got) != 1 || got[0] != "since last attempt: gone ✓" {
		t.Fatalf("gone delta = %v", got)
	}
	// unchanged failures list in gate order, not set order
	got = gateDeltaLines(clauses, []string{"b"})
	if len(got) != 1 || got[0] != "since last attempt: no change (b)" {
		t.Fatalf("no-change delta = %v", got)
	}
	// an empty record is NOT "all clauses pass": a refused transition always
	// records at least one id, so an empty one is an unreadable attempt
	for _, prev := range [][]string{{}, nil} {
		if prev == nil {
			continue
		}
		got = gateDeltaLines(clauses, prev)
		if len(got) != 1 || got[0] != "since last attempt: (attempt unreadable)" {
			t.Fatalf("empty prev delta = %v", got)
		}
	}
	got = gateDeltaLines([]findings.Clause{}, []string{})
	if len(got) != 1 || got[0] != "since last attempt: (attempt unreadable)" {
		t.Fatalf("empty clauses delta = %v", got)
	}
}

// Port of test_delta_uses_the_latest_recorded_attempt.
func TestDeltaUsesTheLatestRecordedAttempt(t *testing.T) {
	c, root := t15Campaign(t, "latest")
	f := t15Finding(t, c, "an inflation hypothesis",
		"first-depositor-inflation")
	fid := objStr(f, "finding_id")
	clauses, err := findings.ConfirmationGateClauses(c, f)
	if err != nil {
		t.Fatal(err)
	}
	live := findings.FailingCheckIDs(clauses)
	if len(live) == 0 {
		t.Fatal("fixture must fail at least one clause")
	}
	logAttempt := func(ids []string) {
		items := make([]validation.Value, 0, len(ids))
		for _, id := range ids {
			items = append(items, validation.VStr(id))
		}
		data := validation.VObj(
			kvT("finding", validation.VStr(fid)),
			kvT("check_ids", validation.VArr(items...)))
		if _, err := c.Log("finding.gate_attempt", &fid, &data); err != nil {
			t.Fatal(err)
		}
	}
	logAttempt([]string{"critic-verdict"})
	logAttempt(live)
	prev, err := lastGateAttempt(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(prev, ",") != strings.Join(live, ",") {
		t.Fatalf("last attempt = %v, want %v", prev, live)
	}
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	delta := []string{}
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "since last attempt") {
			delta = append(delta, ln)
		}
	}
	want := "since last attempt: no change (" + strings.Join(live, ", ") + ")"
	if len(delta) != 1 || delta[0] != want {
		t.Fatalf("delta = %v, want [%q]", delta, want)
	}
}

// Port of test_gate_delta_lines_tolerate_unhashable_recorded_ids.
func TestGateDeltaLinesTolerateUnhashableRecordedIDs(t *testing.T) {
	c, _ := t15Campaign(t, "unhashable")
	f := t15Finding(t, c, "an inflation hypothesis",
		"first-depositor-inflation")
	fid := objStr(f, "finding_id")
	// a recorded member that is not a string is unreadable, not a clause
	data := validation.VObj(
		kvT("finding", validation.VStr(fid)),
		kvT("check_ids", validation.VArr(validation.VArr(
			validation.VStr("a")), validation.VObj(
			kvT("k", validation.VInt(1))))))
	if _, err := c.Log("finding.gate_attempt", &fid, &data); err != nil {
		t.Fatal(err)
	}
	prev, err := lastGateAttempt(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev) != 0 {
		t.Fatalf("non-string members must be dropped, got %v", prev)
	}
	clauses := []findings.Clause{{CheckID: "b", OK: false, Message: "m"}}
	got := gateDeltaLines(clauses, prev)
	if len(got) != 1 || got[0] != "since last attempt: (attempt unreadable)" {
		t.Fatalf("delta = %v", got)
	}
	// a mixed record keeps its string member and drops the rest
	data = setObjFieldCLI(data, "check_ids", validation.VArr(
		validation.VStr("b"), validation.VArr(validation.VStr("a"))))
	if _, err := c.Log("finding.gate_attempt", &fid, &data); err != nil {
		t.Fatal(err)
	}
	prev, err = lastGateAttempt(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev) != 1 || prev[0] != "b" {
		t.Fatalf("mixed record = %v, want [b]", prev)
	}
	got = gateDeltaLines(clauses, prev)
	if len(got) != 1 || got[0] != "since last attempt: no change (b)" {
		t.Fatalf("delta with a string member = %v", got)
	}
}

// Port of test_unreadable_check_ids_are_reported_not_crashed (the four
// parametrized shapes).
func TestUnreadableCheckIDsAreReportedNotCrashed(t *testing.T) {
	cases := []struct {
		name string
		ids  validation.Value
		set  bool
	}{
		{"unhashable", validation.VArr(validation.VArr(validation.VStr("a")),
			validation.VObj(kvT("k", validation.VInt(1)))), true},
		{"not-a-list", validation.VStr("critic-verdict"), true},
		{"empty", validation.VArr(), true},
		{"missing", validation.VNull(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, root := t15Campaign(t, "unreadable")
			f := t15Finding(t, c, "an inflation hypothesis",
				"first-depositor-inflation")
			fid := objStr(f, "finding_id")
			data := validation.VObj(kvT("finding", validation.VStr(fid)))
			if tc.set {
				data.O = append(data.O, kvT("check_ids", tc.ids))
			}
			if _, err := c.Log("finding.gate_attempt", &fid, &data); err != nil {
				t.Fatal(err)
			}
			code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
			if code != 1 {
				t.Fatalf("exit %d, want 1: %q", code, errS)
			}
			if !strings.Contains(out,
				"since last attempt: (attempt unreadable)") {
				t.Fatalf("output %q", out)
			}
			if strings.Contains(out, "no change (all clauses pass)") {
				t.Fatalf("unreadable attempt must not read as all-pass:\n%s", out)
			}
		})
	}
}

// Port of test_dry_run_writes_nothing.
func TestDryRunWritesNothing(t *testing.T) {
	c, root := t15Campaign(t, "readonly")
	f := t15Finding(t, c, "an inflation hypothesis",
		"first-depositor-inflation")
	fid := objStr(f, "finding_id")
	cliAttempt(t, c, fid)
	beforeEvents, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	path := findings.FindingPath(c, fid)
	beforeBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		code, _, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
		if code != 1 {
			t.Fatalf("exit %d, want 1: %q", code, errS)
		}
	}
	afterEvents, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(afterEvents) != len(beforeEvents) {
		t.Fatalf("events = %d, want %d", len(afterEvents), len(beforeEvents))
	}
	afterBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterBytes) != string(beforeBytes) {
		t.Fatal("dry run rewrote the finding")
	}
}

// Port of test_gate_attempt_event_only_on_refusal.
func TestGateAttemptEventOnlyOnRefusal(t *testing.T) {
	c, _ := t15Campaign(t, "refusal")
	t15GlobalRow(t, "MEM-global01", "logic-error")
	f := cliPassingLogicError(t, c)
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "advance",
		"operator", "", false); err != nil {
		t.Fatalf("move POSSIBLE: %v", err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if objStr(e, "type") == "finding.gate_attempt" {
			t.Fatalf("legal transition logged a gate_attempt: %s",
				validation.CanonCompact(e))
		}
	}
}

// cliInvariantFinding is _invariant_finding: several cited invariants, each
// producing its own invariant-unverified clause.
func cliInvariantFinding(t *testing.T, c *state.Campaign,
	ids []string) validation.Value {
	t.Helper()
	invItems := make([]validation.Value, 0, len(ids))
	secItems := make([]validation.Value, 0, len(ids))
	for _, id := range ids {
		stmt := id + ": the fee accumulator cannot be set backwards"
		invItems = append(invItems, validation.VObj(
			kvT("id", validation.VStr(id)),
			kvT("statement", validation.VStr(stmt)),
			kvT("severity_if_broken", validation.VStr("high"))))
		secItems = append(secItems, validation.VObj(
			kvT("id", validation.VStr(id)),
			kvT("statement", validation.VStr(stmt))))
	}
	if _, err := invariants.SeedFromModel(c, validation.VObj(
		kvT("invariants", validation.VArr(invItems...)))); err != nil {
		t.Fatal(err)
	}
	f := t15Finding(t, c, "an invariant hypothesis", "logic-error")
	f = setObjFieldCLI(f, "security_invariants", validation.VArr(secItems...))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	out, err := findings.LoadFinding(c, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// cliVerifyInvariant is _verify: move one invariant to CHECKED_AGAINST_CODE
// via a registered artifact.
func cliVerifyInvariant(t *testing.T, c *state.Campaign, invID, name string) {
	t.Helper()
	p := filepath.Join(c.ArtifactsDir, name)
	if err := os.WriteFile(p, []byte(invID+
		" checked against src/V.sol#L40\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterArtifact("other", p, "", nil); err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	artID := ""
	for _, a := range objAt(st, "artifacts").A {
		if strings.HasSuffix(objStr(a, "path"), name) {
			artID = objStr(a, "artifact_id")
		}
	}
	if artID == "" {
		t.Fatalf("artifact %q not registered", name)
	}
	if _, err := invariants.VerifyInvariantStatement(c, invID,
		artID); err != nil {
		t.Fatal(err)
	}
}

// Port of test_invariant_clauses_are_qualified_by_their_id.
func TestInvariantClausesAreQualifiedByTheirID(t *testing.T) {
	c, root := t15Campaign(t, "inv-qual")
	f := cliInvariantFinding(t, c, []string{"INV-1", "INV-2"})
	fid := objStr(f, "finding_id")
	cliVerifyInvariant(t, c, "INV-1", "inv1-check.md")
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q\n%s", code, errS, out)
	}
	if !strings.Contains(out, "  ✓ invariant-unverified[INV-1]") {
		t.Fatalf("INV-1 line missing:\n%s", out)
	}
	if !strings.Contains(out, "  ✗ invariant-unverified[INV-2]:") {
		t.Fatalf("INV-2 line missing:\n%s", out)
	}
	// the refusal records the qualified ids, so the delta can match them
	clauses, err := findings.ConfirmationGateClauses(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStrCLI(findings.FailingCheckIDs(clauses),
		"invariant-unverified[INV-2]") {
		t.Fatal("failing ids must be subject-qualified")
	}
}

// Port of test_invariant_delta_distinguishes_fixed_from_broken.
func TestInvariantDeltaDistinguishesFixedFromBroken(t *testing.T) {
	c, root := t15Campaign(t, "inv-delta")
	f := cliInvariantFinding(t, c, []string{"INV-1", "INV-2"})
	fid := objStr(f, "finding_id")
	data := validation.VObj(
		kvT("finding", validation.VStr(fid)),
		kvT("check_ids", validation.VArr(
			validation.VStr("invariant-unverified[INV-1]"))))
	if _, err := c.Log("finding.gate_attempt", &fid, &data); err != nil {
		t.Fatal(err)
	}
	cliVerifyInvariant(t, c, "INV-1", "inv1-check.md")
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q\n%s", code, errS, out)
	}
	if !strings.Contains(out, "since last attempt: invariant-unverified[INV-1] ✓") {
		t.Fatalf("fixed INV-1 not reported:\n%s", out)
	}
	if !strings.Contains(out, "since last attempt: invariant-unverified[INV-2] ✗") {
		t.Fatalf("broken INV-2 not reported:\n%s", out)
	}
	if strings.Contains(out, "no change") {
		t.Fatalf("must not read as no change:\n%s", out)
	}
}

// Port of test_named_decision_line_needs_an_economic_clause (CLI half).
func TestNamedDecisionLineNeedsAnEconomicClause(t *testing.T) {
	c, root := t15Campaign(t, "noneconomic")
	f := t15Finding(t, c, "a logic flow hypothesis", "logic-error")
	fid := objStr(f, "finding_id")
	f = setObjFieldCLI(f, "economic_impact", validation.VObj(
		kvT("priceable", validation.VBool(false)),
		kvT("ceiling", validation.VStr(cliCeiling))))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	loaded, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if findings.UnpriceableDecision(loaded) == nil {
		t.Fatal("fixture must record an unpriceable decision")
	}
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	if strings.Contains(out, "NAMED DECISION") ||
		strings.Contains(out, "UNPRICEABLE") {
		t.Fatalf("a non-economic class must not print the line:\n%s", out)
	}
}

// Port of test_named_decision_line_prints_for_economic_class. The Python test
// drives `webv2 impact --unpriceable`; that command is unported (P3), so the
// decision is recorded through the same state function it calls.
func TestNamedDecisionLinePrintsForEconomicClass(t *testing.T) {
	c, root := t15Campaign(t, "economic")
	f := cliGateReadyEconomic(t, c)
	fid := objStr(f, "finding_id")
	if _, err := risk.RecordUnpriceable(c, fid, cliCeiling,
		"the sink is a test fixture, so any USD figure would be invented "+
			"precision, not a measurement", "operator"); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	if !strings.Contains(out, "NAMED DECISION") {
		t.Fatalf("NAMED DECISION line missing:\n%s", out)
	}
	if !strings.Contains(out, "UNPRICEABLE (ceiling: "+cliCeiling+")") {
		t.Fatalf("ceiling line missing:\n%s", out)
	}
}

// cliGateReadyEconomic is the CLI twin of the library fixture: an
// economic-class finding whose only open clause is the E7 quantification.
func cliGateReadyEconomic(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	t15GlobalRow(t, "MEM-shared01", "oracle-manipulation")
	payload := validation.VObj(
		kvT("title", validation.VStr("an oracle hypothesis")),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr("oracle-manipulation")),
			kvT("description", validation.VStr("the oracle is manipulable")),
		)),
		kvT("affected", validation.VArr(validation.VObj(
			kvT("path", validation.VStr("src/V.sol")),
			kvT("function", validation.VStr("f")),
		))),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("arbitrary EOA")),
			kvT("capabilities", validation.VArr()),
		)),
	)
	f, err := findings.IngestHypothesis(c, payload, "economic", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	rec := t15ExecRecordFor(t, c, "EXEC-0000000001", fid)
	for i, pair := range [][2]string{{"E4", "foundry-test"},
		{"E5", "fork-test"}} {
		item := validation.VObj(
			kvT("evidence_id", validation.VStr(fmt.Sprintf("EV-u%d", i))),
			kvT("level", validation.VStr(pair[0])),
			kvT("type", validation.VStr(pair[1])),
			kvT("description", validation.VStr("gate fixture")),
			kvT("sandbox_profile", objAt(rec, "profile")),
			kvT("artifact_id", objAt(rec, "exec_id")),
		)
		if _, err := findings.AddEvidence(c, fid, item); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"mechanism sound"); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kvT("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kvT("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	loaded, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDictCLI(objAt(loaded, "verification"))
	ver = setObjFieldCLI(ver, "reproduction", validation.VObj(
		kvT("tier_reached", validation.VStr("T3")),
		kvT("status", validation.VStr("reproduced")),
		kvT("attempts", validation.VArr())))
	loaded = setObjFieldCLI(loaded, "verification", ver)
	if err := findings.SaveFinding(c, &loaded); err != nil {
		t.Fatal(err)
	}
	out, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
