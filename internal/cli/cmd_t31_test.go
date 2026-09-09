package cli

// cmd_t31_test: the T31 view-family CLI contract. Ports the CLI halves of
// tests/test_briefing_memory.py, tests/test_noop_reporting.py,
// tests/test_attention_ledger.py and tests/test_campaign_complete.py.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/briefing"
	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/planner"
	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// t31OneGateFromConfirmed is test_briefing_memory.one_gate_from_confirmed.
func t31OneGateFromConfirmed(t *testing.T, c *state.Campaign) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("vault drain via unguarded sweep")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr("mechanism described in detail here")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("contract", validation.VStr("Vault")),
			kv("function", validation.VStr("sweep"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.VArr()),
			kv("required", validation.VArr()))),
	), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatal(err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "pytest-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatal(err)
	}
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-1")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("repro under sandbox")),
		kv("sandbox_profile", objAt(rec, "profile")),
		kv("artifact_id", objAt(rec, "exec_id")))
	if _, err := findings.AddEvidence(c, fid, item); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed", "ok"); err != nil {
		t.Fatal(err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := objAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = setOrAppendKV(ver.O, "reproduction", validation.VObj(
		kv("status", validation.VStr("reproduced")),
		kv("tier_reached", validation.VStr("T3")),
		kv("attempts", validation.VArr())))
	vf.O = setOrAppendKV(vf.O, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	return fid
}

func TestCLIBriefRendersMemoryRecall(t *testing.T) {
	root, cid, c := noopCamp(t)
	fid := t31OneGateFromConfirmed(t, c)
	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errS)
	}
	want := "webv2 recall " + cid + " --finding " + fid
	if !strings.Contains(out, want) {
		t.Errorf("stdout lacks %q:\n%s", want, out)
	}
	if !strings.Contains(out, "memory recall pending") {
		t.Errorf("stdout lacks the recall wording")
	}
	if strings.Contains(out, "negative-mode RAG") {
		t.Errorf("stdout still mentions the retired RAG check")
	}
}

var recallRe = regexp.MustCompile("`(webv2 recall [^`]*)`")

func TestEveryPrintedRecallRemedyIsExecutable(t *testing.T) {
	root, cid, c := noopCamp(t)
	fid := t31OneGateFromConfirmed(t, c)
	gateMsg, err := findings.MemoryCheckFails(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if gateMsg == nil {
		t.Fatalf("the gate must fail without a recorded memory check")
	}
	brief, err := briefing.BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	action := ""
	for _, a := range objAt(brief, "next_actions").A {
		if a.Kind == validation.Str && strings.Contains(a.S, fid) &&
			strings.Contains(a.S, "memory recall pending") {
			action = a.S
		}
	}
	if action == "" {
		t.Fatalf("no recall next-action for %s", fid)
	}
	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit %d: %s", code, errS)
	}
	printed := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "memory recall pending") {
			printed = line
		}
	}
	if printed == "" {
		t.Fatalf("brief printed no recall line")
	}
	for _, text := range []string{*gateMsg, action, printed} {
		m := recallRe.FindStringSubmatch(text)
		if m == nil {
			t.Fatalf("no `webv2 recall ...` remedy in %q", text)
		}
		argv := strings.Fields(m[1])
		if len(argv) < 2 || argv[0] != "webv2" {
			t.Fatalf("remedy is not a webv2 invocation: %q", m[1])
		}
		argv = argv[1:]
		if len(argv) < 2 || argv[1] != cid {
			t.Fatalf("remedy lacks the campaign positional: %q", m[1])
		}
		if !strings.Contains(m[1], fid) {
			t.Fatalf("remedy lacks the finding id: %q", m[1])
		}
		code, out, errS := run(t, append([]string{"--root", root}, argv...)...)
		if code != 0 {
			t.Errorf("printed remedy %q exited %d: %s", m[1], code, errS)
		}
		_ = out
	}
}

func TestCLIBriefPrintsTheProblemLine(t *testing.T) {
	root, cid, c := noopCamp(t)
	noopHypo(t, c, "unwritten graph finding", "")
	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errS)
	}
	if !strings.Contains(out, "graph was never written") {
		t.Errorf("stdout lacks the problem line:\n%s", out)
	}
	if !strings.Contains(out, "webv2 relations "+cid+" --rebuild") {
		t.Errorf("stdout lacks the rebuild remedy:\n%s", out)
	}
}

func TestCLIBriefOnEmptyCampaignExitsZeroAndPrintsNoDebtLine(t *testing.T) {
	root, cid, _ := noopCamp(t)
	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errS)
	}
	if strings.Contains(out, "untouched") {
		t.Errorf("empty campaign printed a debt line:\n%s", out)
	}
	if strings.Contains(out, "UNVERIFIED (liveness/critical") {
		t.Errorf("empty campaign printed an invariant debt line:\n%s", out)
	}
}

// t31PlanPrio is tests/test_attention_ledger._prio (the fields the debt
// block needs).
func t31PlanPrio(i int, status string, invariantIDs []string) validation.Value {
	kvs := []validation.KV{
		kv("id", validation.VStr(pyQID(i))),
		kv("question", validation.VStr("Does invariant "+itoaCLI(i)+
			" hold under the vault's conditions?")),
		kv("risk", validation.VFloat(0.5)),
		kv("components", validation.VArr(validation.VStr("Vault"))),
		kv("trajectories", validation.VArr(validation.VStr("code"))),
		kv("status", validation.VStr(status)),
	}
	if len(invariantIDs) > 0 {
		kvs = append(kvs, kv("invariant_ids", strArrCLI(invariantIDs)))
	}
	return validation.VObj(kvs...)
}

func pyQID(i int) string {
	s := itoaCLI(i)
	for len(s) < 3 {
		s = "0" + s
	}
	return "Q-" + s
}

func itoaCLI(i int) string {
	if i == 0 {
		return "0"
	}
	out := ""
	for i > 0 {
		out = string(rune('0'+i%10)) + out
		i /= 10
	}
	return out
}

func TestCLIBriefPrintsTheDebtBlock(t *testing.T) {
	root, cid, c := noopCamp(t)
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(cid)),
		kv("created_at", validation.VStr("2026-09-08T08:48:00+00:00")),
		kv("strategy_note", validation.VStr("attention-ledger fixture")),
		kv("priorities", validation.VArr(t31PlanPrio(1, "open",
			[]string{"INV-008"}))),
		kv("lenses", validation.VArr()),
		kv("trajectory_matrix", validation.VObj()),
		kv("coverage_targets", validation.VObj()))
	if _, err := planner.ValidatePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"), plan, ""); err != nil {
		t.Fatal(err)
	}
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	reg.O = setOrAppendKV(reg.O, "INV-008", validation.VObj(
		kv("statement", validation.VStr("INV-008 statement")),
		kv("kind", validation.VStr("liveness")),
		kv("severity_if_broken", validation.VStr("critical")),
		kv("applies_to", validation.VArr(validation.VStr("Vault"))),
		kv("test_status", validation.VStr("untested")),
		kv("status", validation.VStr("UNVERIFIED")),
		kv("source", validation.VStr("model")),
		kv("model_belief", validation.VNull()),
		kv("depends_on", validation.VArr()),
		kv("modified_by", validation.VNull()),
		kv("findings", validation.VArr()),
		kv("tests", validation.VArr()),
		kv("detectors", validation.VArr()),
		kv("updated_at", validation.VStr("2026-09-08T08:48:00+00:00"))))
	links.O = setOrAppendKV(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	// pin the cockpit's clock (the repo's golden-suite hook)
	t.Setenv("WEBV2_NOW", "2026-09-08T12:00:00+00:00")
	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errS)
	}
	if !strings.Contains(out, "attention:") {
		t.Errorf("stdout lacks the attention block:\n%s", out)
	}
	want := "questions worked 0/1 — oldest untouched: Q-001 " +
		"(3h12m, INV-008 critical)"
	if !strings.Contains(out, want) {
		t.Errorf("stdout lacks %q:\n%s", want, out)
	}
	wantInv := "verify INV-008 (unverified 3h12m): webv2 invariant-verify " +
		cid + " INV-008 --exec EXEC-*"
	if !strings.Contains(out, wantInv) {
		t.Errorf("stdout lacks %q:\n%s", wantInv, out)
	}
}

func TestCLIComplete(t *testing.T) {
	root, cid, c := noopCamp(t)
	code, out, errS := run(t, "--root", root, "complete", cid,
		"--actor", "alice", "--reason", "pass closed: report generated")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errS)
	}
	if !strings.Contains(out, "COMPLETE") {
		t.Errorf("stdout lacks COMPLETE:\n%s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("stdout lacks the actor:\n%s", out)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(st, "phase"); got != "COMPLETE" {
		t.Errorf("phase = %q, want COMPLETE", got)
	}
}

func TestCLICompleteRejectsThinReason(t *testing.T) {
	root, cid, _ := noopCamp(t)
	code, out, errS := run(t, "--root", root, "complete", cid,
		"--actor", "alice", "--reason", "done")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (out=%q err=%q)", code, out, errS)
	}
	if !strings.Contains(errS, "reason") {
		t.Errorf("stderr = %q, want it to mention the reason", errS)
	}
}

func TestNextRespectsClosure(t *testing.T) {
	root, cid, c := noopCamp(t)
	if _, err := c.Complete("alice", "pass closed: report generated"); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errS)
	}
	if !strings.Contains(out, "COMPLETE") || !strings.Contains(out, "alice") {
		t.Errorf("stdout lacks the closure statement:\n%s", out)
	}
	if strings.Contains(out, "orchestrator.") {
		t.Errorf("closed campaign still suggests stages:\n%s", out)
	}
}

func TestStatusShowsCompletePhase(t *testing.T) {
	root, cid, c := noopCamp(t)
	if _, err := c.Complete("alice", "pass closed: report generated"); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "status", cid)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errS)
	}
	doc, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("status is not JSON: %v", err)
	}
	if got := objStr(doc, "phase"); got != "COMPLETE" {
		t.Errorf("phase = %q, want COMPLETE", got)
	}
}

// t31CampWithSnapshot is test_campaign_complete.camp: a campaign with a
// pinned source snapshot (the `run` stage path needs a target).
func t31CampWithSnapshot(t *testing.T) (string, string, *state.Campaign) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	ensureSeams()
	code, out, errS := run(t, "--root", root, "init", "--program",
		"Closure Program")
	if code != 0 {
		t.Fatalf("init exit %d: %q", code, errS)
	}
	cid := initIDRe.FindStringSubmatch(out)[1]
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return root, cid, c
}

func TestReopeningByRunningAStageMovesThePhase(t *testing.T) {
	root, cid, c := t31CampWithSnapshot(t)
	if _, err := c.Complete("alice", "pass closed: report generated"); err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(st, "phase"); got != "COMPLETE" {
		t.Fatalf("phase = %q, want COMPLETE", got)
	}
	code, out, errS := run(t, "--root", root, "run", cid)
	// run halts at the first model stage (exit 3) — that is not an error,
	// and the phase must no longer be COMPLETE
	if code != 0 && code != 3 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	st, err = c.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(st, "phase"); got == "COMPLETE" {
		t.Errorf("phase is still COMPLETE after a stage run")
	}
}

// ---- help blocks (byte-exact against the pinned argparse output) ----------

func TestT31HelpBlocks(t *testing.T) {
	cases := []struct{ name, want string }{
		{"brief", `usage: webv2 brief [-h] [--json] [--deep] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
  --json
  --deep      fold in the full integrity audit
`},
		{"report", `usage: webv2 report [-h] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
`},
		{"complete", `usage: webv2 complete [-h] [--actor ACTOR] [--reason REASON] campaign

positional arguments:
  campaign

options:
  -h, --help       show this help message and exit
  --actor ACTOR    who is closing the pass (required)
  --reason REASON  written reason: what was closed, why the pass is done (>=
                   10 chars)
`},
		{"shield", `usage: webv2 shield [-h] [--extraction] --reason REASON [--actor ACTOR]
                    campaign finding

positional arguments:
  campaign
  finding

options:
  -h, --help       show this help message and exit
  --extraction     the effect IS extraction despite being intended
  --reason REASON
  --actor ACTOR
`},
		{"precondition", `usage: webv2 precondition [-h] (--enforced | --not-enforced)
                          campaign finding description

positional arguments:
  campaign
  finding
  description

options:
  -h, --help      show this help message and exit
  --enforced
  --not-enforced
`},
	}
	for _, tc := range cases {
		code, out, errS := run(t, tc.name, "--help")
		if code != 0 {
			t.Fatalf("%s --help exit = %d (err=%q)", tc.name, code, errS)
		}
		if out != tc.want {
			t.Fatalf("%s help mismatch:\n--- got ---\n%s--- want ---\n%s",
				tc.name, out, tc.want)
		}
		if errS != "" {
			t.Fatalf("%s stderr = %q", tc.name, errS)
		}
	}
}

func TestT31ArgErrors(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantSub string
	}{
		{"complete", []string{"complete"}, "required: campaign"},
		{"shield", []string{"shield", "c", "f"}, "required: --reason"},
		{"precondition-exclusive",
			[]string{"precondition", "--enforced", "--not-enforced", "c", "f", "d"},
			"not allowed with argument"},
		{"brief", []string{"brief"}, "required: campaign"},
		{"report", []string{"report"}, "required: campaign"},
		{"shield-extra",
			[]string{"shield", "c", "f", "--reason", "r", "--extraction",
				"--actor", "a", "extra"},
			"unrecognized arguments: extra"},
	}
	for _, tc := range cases {
		code, _, errS := run(t, tc.args...)
		if code != 2 {
			t.Fatalf("%s exit = %d, want 2 (err=%q)", tc.name, code, errS)
		}
		if !strings.Contains(errS, tc.wantSub) {
			t.Fatalf("%s stderr = %q, want %q", tc.name, errS, tc.wantSub)
		}
	}
}
