package cli

// cmd_assume tests — R3-4 (Morph r3 defect 4): the library already moves
// assumption status honestly (store-proven refs only); the OPERATOR had no
// verb, so a refuted blocking assumption could only be narrated. This is the
// thin CLI over findings.AssumptionTransition — every refusal comes from the
// library, and the CLI class prints it.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// assumeFixture ingests a finding carrying three assumptions and gives it
// one manual evidence item the moves can cite.
func assumeFixture(t *testing.T, root, cid string) string {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(
			"Withdraw path bypassed under rounding")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr(
				"mechanism described in detail here")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("contract", validation.VStr("Vault")),
			kv("function", validation.VStr("withdraw"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("assumptions", validation.VArr(
			validation.VObj(
				kv("id", validation.VStr("A1")),
				kv("type", validation.VStr("reachability")),
				kv("claim", validation.VStr(
					"the withdraw path is reachable by an arbitrary EOA")),
				kv("status", validation.VStr("UNKNOWN")),
				kv("model_belief", validation.VFloat(0.7)),
				kv("blocking", validation.VBool(true))),
			validation.VObj(
				kv("id", validation.VStr("A2")),
				kv("type", validation.VStr("authority")),
				kv("claim", validation.VStr(
					"the owner key has not rotated since the deploy")),
				kv("status", validation.VStr("UNKNOWN")),
				kv("model_belief", validation.VFloat(0.5)),
				kv("blocking", validation.VBool(false))),
			validation.VObj(
				kv("id", validation.VStr("A3")),
				kv("type", validation.VStr("invariant")),
				kv("claim", validation.VStr(
					"totalAssets never exceeds the recorded deposits")),
				kv("status", validation.VStr("UNKNOWN")),
				kv("model_belief", validation.VFloat(0.9)),
				kv("blocking", validation.VBool(true))))),
	), "code", "test", "")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	fid := validation.ObjStr(f, "finding_id")
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-a1")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("traced the call path")),
	)); err != nil {
		t.Fatal(err)
	}
	return fid
}

func assumeFindingRow(t *testing.T, root, cid, fid string) validation.Value {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func assumeRow(t *testing.T, f validation.Value, aid string) validation.Value {
	t.Helper()
	for _, a := range validation.ObjAt(f, "assumptions").A {
		if validation.ObjStr(a, "id") == aid {
			return a
		}
	}
	t.Fatalf("assumption %s gone from the finding", aid)
	return validation.VNull()
}

func TestAssumeHappyPath(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := assumeFixture(t, root, cid)
	code, out, errS := run(t, "--root", root, "assume", cid, fid, "A1",
		"--status", "REFUTED", "--ref", "EV-a1", "--actor", "op")
	if code != 0 {
		t.Fatalf("exit %d: stdout %q stderr %q", code, out, errS)
	}
	if out != "assumption A1: UNKNOWN -> REFUTED (evidence: EV-a1)\n" {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	row := assumeRow(t, assumeFindingRow(t, root, cid, fid), "A1")
	if validation.ObjStr(row, "status") != "REFUTED" {
		t.Fatalf("stored status = %q", validation.ObjStr(row, "status"))
	}
	if !strings.Contains(validation.DumpIndented(row), "EV-a1") {
		t.Fatal("the cited ref was not recorded on the assumption")
	}
	// The ledger carries the actor.
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if validation.ObjStr(last, "type") != "finding.assumption_transition" {
		t.Fatalf("last event = %q", validation.ObjStr(last, "type"))
	}
	data := validation.ObjAt(last, "data")
	if validation.ObjStr(data, "actor") != "op" ||
		validation.ObjStr(data, "to") != "REFUTED" {
		t.Fatalf("event data = %s", validation.DumpIndented(data))
	}
}

func TestAssumeNoRefsOffUnknown(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := assumeFixture(t, root, cid)
	code, out, errS := run(t, "--root", root, "assume", cid, fid, "A1",
		"--status", "SUPPORTED")
	if code != 2 {
		t.Fatalf("exit %d (stderr %q)", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "assume failed: assumption A1: UNKNOWN -> SUPPORTED with no " +
		"evidence ids — status can only move on store-proven evidence, " +
		"never on model_belief alone\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestAssumeIllegalEdge(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := assumeFixture(t, root, cid)
	code, _, errS := run(t, "--root", root, "assume", cid, fid, "A1",
		"--status", "UNKNOWN", "--ref", "EV-a1")
	if code != 2 {
		t.Fatalf("exit %d (stderr %q)", code, errS)
	}
	want := "assume failed: assumption A1: UNKNOWN -> UNKNOWN is not a " +
		"legal move (legal: ['REFUTED', 'SUPPORTED'])\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestAssumeGhostRef(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := assumeFixture(t, root, cid)
	code, _, errS := run(t, "--root", root, "assume", cid, fid, "A1",
		"--status", "SUPPORTED", "--ref", "ART-DEADBEEF")
	if code != 2 {
		t.Fatalf("exit %d (stderr %q)", code, errS)
	}
	want := "assume failed: evidence reference 'ART-DEADBEEF' does not " +
		"exist in the campaign evidence store (no evidence item, " +
		"registered artifact, or EXEC record) — an assumption status can " +
		"never move on model_belief or a bare claim\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestAssumeGhostAssumption(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := assumeFixture(t, root, cid)
	code, _, errS := run(t, "--root", root, "assume", cid, fid, "A9",
		"--status", "SUPPORTED", "--ref", "EV-a1")
	// Same class as a ghost finding on `move`: a plain error at exit 1,
	// not a handler refusal.
	if code != 1 {
		t.Fatalf("exit %d (stderr %q)", code, errS)
	}
	want := "error: A9 is not an assumption of this finding " +
		"(ids: ['A1', 'A2', 'A3'])\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestAssumeGhostFinding(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "assume", cid, "F-deadbeef",
		"A1", "--status", "SUPPORTED", "--ref", "EV-a1")
	if code != 1 || !strings.HasPrefix(errS, "error: ") {
		t.Fatalf("exit %d stderr %q, want error: at 1", code, errS)
	}
}

func TestAssumeLowercaseAndDefaultActor(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := assumeFixture(t, root, cid)
	code, out, errS := run(t, "--root", root, "assume", cid, fid, "A2",
		"--status", "supported", "--ref", "EV-a1")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "assumption A2: UNKNOWN -> SUPPORTED (evidence: EV-a1)\n" {
		t.Fatalf("stdout = %q", out)
	}
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	data := validation.ObjAt(events[len(events)-1], "data")
	if validation.ObjStr(data, "actor") != "cli" {
		t.Fatalf("actor = %q, want the cli default",
			validation.ObjStr(data, "actor"))
	}
}

func TestAssumeMultipleRefs(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := assumeFixture(t, root, cid)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-a2")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("second read")),
	)); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "assume", cid, fid, "A1",
		"--status", "REFUTED", "--ref", "EV-a1", "--ref", "EV-a2")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "assumption A1: UNKNOWN -> REFUTED (evidence: EV-a1, EV-a2)\n" {
		t.Fatalf("stdout = %q", out)
	}
}

func TestAssumeArgparse(t *testing.T) {
	t23WantArgparse(t, []string{"assume"}, assumeUsage,
		"webv2 assume: error: the following arguments are required: "+
			"campaign, finding, assumption_id, --status\n")
	t23WantArgparse(t, []string{"assume", "C", "F", "A1"}, assumeUsage,
		"webv2 assume: error: the following arguments are required: "+
			"--status\n")
	t23WantArgparse(t, []string{"assume", "C", "F", "A1", "--status"},
		assumeUsage,
		"webv2 assume: error: argument --status: expected one argument\n")
	t23WantArgparse(t, []string{"assume", "C", "F", "A1", "--status",
		"maybe"}, assumeUsage,
		"webv2 assume: error: argument --status: invalid choice: 'maybe' "+
			"(choose from 'UNKNOWN', 'SUPPORTED', 'REFUTED')\n")
	// Unknown tokens are refused by the ROOT parser's shape (the house
	// rule, cmd_scope.go's t14Unrecognized): top usage, `webv2:` prefix.
	t23WantArgparse(t, []string{"assume", "C", "F", "A1", "--status",
		"REFUTED", "--bogus"}, t14TopUsage,
		"webv2: error: unrecognized arguments: --bogus\n")
	t23WantArgparse(t, []string{"assume", "C", "F", "A1", "extra",
		"--status", "REFUTED"}, t14TopUsage,
		"webv2: error: unrecognized arguments: extra\n")
	t23WantHelp(t, []string{"assume", "--help"}, assumeUsage)
}

// argparse order (cmd_move's law): the subparser's required arguments are
// refused BEFORE the root's unrecognized-arguments — `assume --bogus`
// names what is missing, not what is extra.
func TestAssumeMissingArgsBeatUnknownFlag(t *testing.T) {
	root := mkroot(t)
	code, _, errS := run(t, "--root", root, "assume", "--bogus")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := assumeUsage + "webv2 assume: error: the following arguments " +
		"are required: campaign, finding, assumption_id, --status\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}
