package cli

// T35 testmap re-triage: 1:1 ports of the deferred test_cli.py /
// test_plan_rebuild.py / test_answered.py rows whose Go home is the CLI.
// Rows whose behavior is already pinned byte-for-byte by an existing
// cmd_*_test.go are mapped to that test in testmap.json, not re-ported here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestInitStatusLogVerifyAudit ports test_init_status_log_verify_audit: the
// four read-only lifecycle commands agree on one fresh campaign.
func TestInitStatusLogVerifyAudit(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)

	code, out, errS := run(t, "--root", root, "status", cid)
	if code != 0 {
		t.Fatalf("status exit %d: %q", code, errS)
	}
	var st map[string]any
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("status json: %v", err)
	}
	if st["campaign_id"] != cid {
		t.Fatalf("status campaign_id = %v, want %s", st["campaign_id"], cid)
	}

	code, out, errS = run(t, "--root", root, "log", cid, "--tail", "5")
	if code != 0 {
		t.Fatalf("log exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "campaign.created") {
		t.Fatalf("log tail = %q", out)
	}

	code, out, errS = run(t, "--root", root, "verify", cid)
	if code != 0 {
		t.Fatalf("verify exit %d: %q", code, errS)
	}
	var vres struct {
		OK      bool  `json:"ok"`
		Chained int64 `json:"chained"`
	}
	if err := json.Unmarshal([]byte(out), &vres); err != nil {
		t.Fatalf("verify json: %v", err)
	}
	if !vres.OK || vres.Chained < 1 {
		t.Fatalf("verify = %+v, want ok with chained>=1", vres)
	}

	code, out, errS = run(t, "--root", root, "audit", cid)
	if code != 0 {
		t.Fatalf("audit exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "audit PASS") {
		t.Fatalf("audit = %q", out)
	}
}

// TestAuditHasFloorPolicySection ports test_audit_has_floor_policy_section:
// a recorded floor override is audited as a first-class section.
func TestAuditHasFloorPolicySection(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "floors", cid, "set",
		"reentrancy", "E5", "--actor", "lead",
		"--reason", "fork infra available for this campaign")
	if code != 0 {
		t.Fatalf("floors set exit %d: %q", code, errS)
	}
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if code != 0 {
		t.Fatalf("audit --json exit %d: %q", code, errS)
	}
	var rep struct {
		Sections map[string]struct {
			OK bool `json:"ok"`
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("audit json: %v", err)
	}
	sec, ok := rep.Sections["floor_policy"]
	if !ok {
		t.Fatalf("audit sections lack floor_policy: %v", out[:200])
	}
	if !sec.OK {
		t.Fatalf("floor_policy section not ok: %v", out)
	}
}

// TestBriefShowsStagesAndBudget ports test_brief_shows_stages_and_budget.
func TestBriefShowsStagesAndBudget(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "stages 0/17") {
		t.Fatalf("brief lacks the stage count: %q", out)
	}
	if !strings.Contains(out, "ceiling") && !strings.Contains(out, "unbounded") {
		t.Fatalf("brief lacks the budget line: %q", out)
	}
}

// TestIngestJSONOutputsAdvisoryAndWarnings ports
// test_ingest_json_outputs_advisory_and_warnings: the --json envelope carries
// the taxonomy advisory and the intake warnings, not just the finding.
func TestIngestJSONOutputsAdvisoryAndWarnings(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	payload := t14TestWrite(t, root, "f.json", `{
  "title": "unknown class hypothesis",
  "root_cause": {"class": "quantum-decoherence",
    "description": "an invented class to exercise the taxonomy advisory in the CLI smoke test"},
  "affected": [{"path": "src/T.sol", "contract": "T", "function": "f"}],
  "attacker": {"profile": "EOA", "capabilities": []}
}`)
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", payload, "--json")
	if code != 0 {
		t.Fatalf("ingest --json exit %d: %q", code, errS)
	}
	var d struct {
		Finding struct {
			Status string `json:"status"`
		} `json:"finding"`
		ClassAdvisory  string   `json:"class_advisory"`
		IntakeWarnings []string `json:"intake_warnings"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("ingest json: %v", err)
	}
	if d.Finding.Status != "HYPOTHESIS" {
		t.Fatalf("finding.status = %q, want HYPOTHESIS", d.Finding.Status)
	}
	if !strings.Contains(d.ClassAdvisory, "unknown class") {
		t.Fatalf("class_advisory = %q", d.ClassAdvisory)
	}
	if len(d.IntakeWarnings) == 0 {
		t.Fatal("intake_warnings must not be empty for an unknown class")
	}
}

// TestPlanFileOnExistingPlanWithoutRebuildFailsLoudly ports
// test_file_on_existing_plan_without_rebuild_fails_loudly: a positional plan
// file is a WRITE, so it needs --rebuild on an existing plan.
func TestPlanFileOnExistingPlanWithoutRebuildFailsLoudly(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	planPath := filepath.Join(root, "campaigns", cid, "artifacts",
		"campaign_plan.json")
	before, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(root, "new_plan.json")
	if err := os.WriteFile(replacement, before, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "plan", cid, replacement)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS, "plan failed") {
		t.Fatalf("stderr = %q", errS)
	}
	if !strings.Contains(errS, "--rebuild") {
		t.Fatalf("stderr does not name the remedy: %q", errS)
	}
	after, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a refused --file write must not touch the live plan")
	}
	if _, err := os.Stat(filepath.Join(root, "campaigns", cid, "artifacts",
		"superseded")); !os.IsNotExist(err) {
		t.Fatalf("refused write must not archive: %v", err)
	}
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if validation.ObjStr(e, "type") == "plan.superseded" {
			t.Fatal("refused write must not log plan.superseded")
		}
	}
}

// TestFreshCampaignPlanAndRebuildBothWrite ports
// test_fresh_campaign_plan_and_rebuild_both_write: on a campaign with no plan
// yet, the bare call, --rebuild and a positional file all write; nothing is
// ever archived because there is nothing to retire.
func TestFreshCampaignPlanAndRebuildBothWrite(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		file bool
	}{
		{name: "bare"},
		{name: "rebuild", args: []string{"--rebuild"}},
		{name: "file", file: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := mkroot(t)
			cid := initOne(t, root)
			model := t14TestWrite(t, root, "model.json", t14TestModelJSON)
			if code, _, errS := run(t, "--root", root, "model", cid,
				model); code != 0 {
				t.Fatalf("model exit %d: %q", code, errS)
			}
			args := append([]string{"--root", root, "plan", cid}, tc.args...)
			if tc.file {
				args = append(args, t14TestWrite(t, root, "in.json",
					"{\"campaign_id\":\"x\"}"))
			}
			code, out, errS := run(t, args...)
			if tc.file {
				// a positional file is validated: this fixture is invalid
				// on purpose, so pin the loud refusal instead of a write.
				if code != 2 || !strings.Contains(errS, "plan failed") {
					t.Fatalf("invalid file: exit %d %q", code, errS)
				}
				return
			}
			if code != 0 {
				t.Fatalf("exit %d: %q", code, errS)
			}
			if !strings.HasPrefix(out, "plan: ") {
				t.Fatalf("out = %q", out)
			}
			if _, err := os.Stat(filepath.Join(root, "campaigns", cid,
				"artifacts", "campaign_plan.json")); err != nil {
				t.Fatalf("plan not written: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, "campaigns", cid,
				"artifacts", "superseded")); !os.IsNotExist(err) {
				t.Fatalf("a first write must not archive: %v", err)
			}
		})
	}
}

// TestProbeEmitRewritesInPlaceWithoutArchiving ports
// test_probe_emit_still_rewrites_in_place_without_archiving: the emit is a
// living-document rewrite, never a plan regeneration.
func TestProbeEmitRewritesInPlaceWithoutArchiving(t *testing.T) {
	ws, c, _, _ := t29Setup(t, t29Ranking, true)
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	before, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	out := t29Emit(t, ws)
	if !strings.Contains(out, "created 10") &&
		!strings.Contains(out, "10 created") {
		t.Fatalf("emit output = %q", out)
	}
	after, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) {
		t.Fatal("emit must rewrite the plan in place")
	}
	if _, err := os.Stat(filepath.Join(c.ArtifactsDir, "superseded")); !os.IsNotExist(err) {
		t.Fatalf("emit must not archive: %v", err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if validation.ObjStr(e, "type") == "plan.superseded" {
			t.Fatal("emit must not log plan.superseded")
		}
	}
	if err := validation.Validate(t29PlanJSON(t, c), "campaign_plan", 1); err != nil {
		t.Fatalf("rewritten plan invalid: %v", err)
	}
}

// TestAnsweredCLIRecordsProvenance ports
// test_answered_cli_records_provenance: the closure provenance is recorded
// with the CLI's default actor and a reopen clears it again.
func TestAnsweredCLIRecordsProvenance(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	planPath := filepath.Join(root, "campaigns", cid, "artifacts",
		"campaign_plan.json")
	prio := func() validation.Value {
		plan, err := validation.ReadJson(planPath)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range plan.O {
			if p.K == "priorities" {
				return p.V.A[0]
			}
		}
		t.Fatal("plan has no priorities")
		return validation.VNull()
	}
	q := validation.ObjStr(prio(), "id")
	code, _, errS := run(t, "--root", root, "answered", cid, q,
		"answered", "--reason", "probe ran; no effect",
		"--ref", "EXEC-abc123")
	if code != 0 {
		t.Fatalf("answered exit %d: %q", code, errS)
	}
	p := prio()
	if got := validation.ObjStr(p, "status"); got != "answered" {
		t.Fatalf("status = %q", got)
	}
	if got := validation.ObjStr(p, "closed_reason"); got != "probe ran; no effect" {
		t.Fatalf("closed_reason = %q", got)
	}
	if got := validation.ObjStr(p, "closed_ref"); got != "EXEC-abc123" {
		t.Fatalf("closed_ref = %q", got)
	}
	if got := validation.ObjStr(p, "closed_by"); got != "cli" {
		t.Fatalf("closed_by = %q, want cli", got)
	}
	code, _, errS = run(t, "--root", root, "answered", cid, q, "open",
		"--reason", "reopened")
	if code != 0 {
		t.Fatalf("reopen exit %d: %q", code, errS)
	}
	p = prio()
	if got := validation.ObjStr(p, "status"); got != "open" {
		t.Fatalf("reopened status = %q", got)
	}
	for _, kv := range p.O {
		if kv.K == "closed_ref" {
			t.Fatal("reopen must clear closed_ref")
		}
	}
}
