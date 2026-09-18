package cli

// Wave N, T2 — `ingest` evidence items may cite an existing EXEC
// (exec_ref) end to end, through the real verb.
//
// What these tests pin:
//
//   - PARITY: the same content + the same exec lands the SAME evidence item
//     via `mint` and via `ingest ... exec_ref` (the fields the mint gate and
//     the evidence floor read: level, type, artifact_id, description, command,
//     sandbox_profile, snapshot_id);
//   - ORDER: a payload with a schema error AND an E4 claim (with or without
//     exec_ref) reports the SCHEMA error — the ledger check never masks it;
//   - REFUSAL: an exec_ref the ledger does not hold is refused by name, exit 2,
//     with no finding written.
//
// No child tool is executed: the exec ledger record is registered through
// sandbox.RegisterExec (externally-reported), exactly like the t20 fixture.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// t2ExecRefPayloadJSON is the hypothesis payload both legs share. With ref
// set it carries ONE evidence item citing that exec; without it, the plain
// hypothesis payload (the mint leg ingests first, then mints onto it).
func t2ExecRefPayloadJSON(ref string) string {
	base := `{"title":"Unguarded rescue moves protocol-held tokens",` +
		`"root_cause":{"class":"access-control","description":` +
		`"rescue has no role check at all"},"affected":[{"path":"V.sol"}],` +
		`"attacker":{"profile":"arbitrary EOA","capabilities":[]}`
	if ref == "" {
		return base + "}"
	}
	return base + `,"evidence":[{"evidence_id":"EV-ref1","level":"E4",` +
		`"type":"foundry-test","description":"the sandboxed PoC drained it",` +
		`"exec_ref":"` + ref + `"}]}`
}

// t2RegisterExec registers a successful container exec in the ledger and
// returns its id. binding "" registers a generic (unbound) exec.
func t2RegisterExec(t *testing.T, c *state.Campaign, binding string) string {
	t.Helper()
	var fid *string
	if binding != "" {
		fid = &binding
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test poc",
		ReportedBy: "operator", ExitStatus: 0, StdoutText: "PASS: poc\n",
		FindingID: fid})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	return t2Str(rec, "exec_id")
}

// t2Campaign initialises a campaign and opens it for direct ledger reads.
func t2Campaign(t *testing.T) (*state.Campaign, string, string) {
	t.Helper()
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return c, root, cid
}

func t2Write(t *testing.T, root, name, body string) string {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func t2Str(v validation.Value, key string) string {
	x := validation.ObjAt(v, key)
	if x.Kind == validation.Str {
		return x.S
	}
	return ""
}

// t2IngestedID is the `ingested <fid> [STATUS] (class ...)` line's finding id.
func t2IngestedID(t *testing.T, out string) string {
	t.Helper()
	fields := strings.Fields(out)
	if len(fields) < 2 || fields[0] != "ingested" {
		t.Fatalf("ingest output = %q", out)
	}
	return fields[1]
}

// t2ItemFor is the finding's evidence item citing execID.
func t2ItemFor(t *testing.T, c *state.Campaign, fid, execID string) validation.Value {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("load %s: %v", fid, err)
	}
	ev := validation.ObjAt(f, "evidence")
	for _, item := range ev.A {
		if t2Str(item, "artifact_id") == execID {
			return item
		}
	}
	t.Fatalf("%s has no evidence item citing %s: %v", fid, execID,
		validation.PyRepr(ev))
	return validation.VNull()
}

// TestIngestExecRefParityWithMint: one campaign, one generic exec, the same
// payload content — `mint` and `ingest --json-file` with exec_ref must land
// equivalent evidence items.
func TestIngestExecRefParityWithMint(t *testing.T) {
	c, root, cid := t2Campaign(t)
	execID := t2RegisterExec(t, c, "")

	// leg A — mint.
	plain := t2Write(t, root, "plain.json", t2ExecRefPayloadJSON(""))
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", plain)
	if code != 0 {
		t.Fatalf("ingest exit %d: %q", code, errS)
	}
	fidA := t2IngestedID(t, out)
	desc := "the sandboxed PoC drained it"
	code, out, errS = run(t, "--root", root, "mint", cid, fidA,
		"--exec", execID, "--description", desc)
	if code != 0 {
		t.Fatalf("mint exit %d: %q", code, errS)
	}
	want := fidA + ": minted default evidence from " + execID +
		" — level E4\n"
	if out != want {
		t.Fatalf("mint out\n%q\nwant\n%q", out, want)
	}

	// leg B — ingest with exec_ref (the same content, one-shot).
	withRef := t2Write(t, root, "withref.json", t2ExecRefPayloadJSON(execID))
	code, out, errS = run(t, "--root", root, "ingest", cid,
		"--json-file", withRef)
	if code != 0 {
		t.Fatalf("ingest exec_ref exit %d: %q", code, errS)
	}
	fidB := t2IngestedID(t, out)

	minted := t2ItemFor(t, c, fidA, execID)
	landed := t2ItemFor(t, c, fidB, execID)
	for _, key := range []string{"level", "type", "artifact_id",
		"description", "command", "sandbox_profile", "snapshot_id"} {
		if a, b := t2Str(minted, key), t2Str(landed, key); a != b {
			t.Errorf("parity: mint %s = %q, ingest exec_ref %s = %q",
				key, a, key, b)
		}
	}
	// the landed item is the MINTED shape: exec_ref never lands.
	for _, k := range landed.O {
		if k.K == "exec_ref" {
			t.Fatalf("exec_ref landed on the finding: %v",
				validation.PyRepr(landed))
		}
	}
}

// TestIngestSchemaErrorBeatsExecRefLedger: the ordering law through the real
// verb — a payload that carries BOTH a schema error and an E4 claim must name
// the schema error, never the E4 gate and never the exec_ref ledger refusal.
func TestIngestSchemaErrorBeatsExecRefLedger(t *testing.T) {
	_, root, cid := t2Campaign(t)
	cases := []struct {
		name  string
		item  string
		notIn string
	}{
		{"E4 claim without exec", `{"evidence_id":"EV-x","level":"E4",` +
			`"type":"foundry-test","description":"smuggled",` +
			`"sandbox_profile":"docker-networkless"}`, "EXECUTION evidence"},
		{"exec_ref the ledger does not hold", `{"evidence_id":"EV-x",` +
			`"level":"E4","type":"foundry-test","description":"smuggled",` +
			`"exec_ref":"EXEC-deadbeef01"}`, "ingest refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := t2Write(t, root, "bad.json", `{"title":"short",`+
				`"root_cause":{"class":"access-control","description":`+
				`"rescue has no role check at all"},`+
				`"affected":[{"path":"V.sol"}],`+
				`"attacker":{"profile":"arbitrary EOA","capabilities":[]},`+
				`"evidence":[`+tc.item+`]}`)
			code, out, errS := run(t, "--root", root, "ingest", cid,
				"--json-file", p)
			if code != 2 || out != "" {
				t.Fatalf("exit %d out %q err %q", code, out, errS)
			}
			if !strings.HasPrefix(errS, "ingest failed: finding validation "+
				"failed at title: 'short' is too short") {
				t.Fatalf("stderr = %q", errS)
			}
			if strings.Contains(errS, tc.notIn) {
				t.Fatalf("the schema error was masked by %q: %q",
					tc.notIn, errS)
			}
		})
	}
}

// TestIngestExecRefRefusalsAtCLI: unknown ref and a non-SUCCEEDED ref are
// refused with the reason named, exit 2, and nothing is written.
func TestIngestExecRefRefusalsAtCLI(t *testing.T) {
	c, root, cid := t2Campaign(t)
	before := t2FindingFiles(t, c)

	unknown := t2Write(t, root, "unknown.json",
		t2ExecRefPayloadJSON("EXEC-deadbeef01"))
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", unknown)
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	if !strings.HasPrefix(errS, "ingest failed: ingest refused: evidence "+
		"EV-ref1 cites exec_ref 'EXEC-deadbeef01', which this campaign's "+
		"ledger does not hold") {
		t.Fatalf("unknown-ref stderr = %q", errS)
	}

	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test poc",
		ReportedBy: "operator", ExitStatus: 1, StdoutText: "FAIL: poc\n"})
	if err != nil {
		t.Fatal(err)
	}
	failed := t2Str(rec, "exec_id")
	notOk := t2Write(t, root, "notok.json", t2ExecRefPayloadJSON(failed))
	code, _, errS = run(t, "--root", root, "ingest", cid,
		"--json-file", notOk)
	if code != 2 {
		t.Fatalf("not-succeeded exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "ingest refused: evidence EV-ref1 exec_ref "+
		failed+": exec "+failed+" exited with status 1; a run that did not "+
		"succeed is not a reproduction") {
		t.Fatalf("not-succeeded stderr = %q", errS)
	}

	if after := t2FindingFiles(t, c); after != before {
		t.Fatalf("a refused payload wrote findings: %q -> %q", before, after)
	}
}

// t2FindingFiles is a cheap "nothing was written" witness: the sorted listing
// of the campaign's finding files.
func t2FindingFiles(t *testing.T, c *state.Campaign) string {
	t.Helper()
	entries, err := os.ReadDir(c.FindingsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return strings.Join(names, ",")
}
