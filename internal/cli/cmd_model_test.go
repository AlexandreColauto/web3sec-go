package cli

// T14 cmd_model tests: load/validate, the no-file summary, and the --json
// view. Vectors captured from the live Python CLI (.scratch/t14/py3.json).

import (
	"strings"
	"testing"
)

func TestModelNotLoaded(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "model", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "no protocol model loaded yet (webv2 model " + cid + " " +
		"model.json)\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestModelLoadAndSummary(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	model := t14TestWrite(t, root, "model.json", t14TestModelJSON)
	code, out, errS := run(t, "--root", root, "model", cid, model)
	if code != 0 {
		t.Fatalf("load exit %d: %q", code, errS)
	}
	want := "model loaded: 1 actors, 2 assets, 1 invariants\n" +
		"  invariant registry: 1 invariant(s) (1 from this load)\n" +
		"  reconciliation: model covers every documented invariant id\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	// the no-file form now prints the summary line instead of "not loaded"
	code, out, _ = run(t, "--root", root, "model", cid)
	if code != 0 {
		t.Fatalf("summary exit %d", code)
	}
	if out != "model: 1 actors, 2 assets, 1 invariants, 0 relations\n" {
		t.Fatalf("summary = %q", out)
	}
}

func TestModelJSONView(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	model := t14TestWrite(t, root, "model.json", t14TestModelJSON)
	if code, _, errS := run(t, "--root", root, "model", cid, model); code != 0 {
		t.Fatalf("load exit %d: %q", code, errS)
	}
	code, out, errS := run(t, "--root", root, "model", cid, "--json")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "\"protocol_id\": \"sharevault\"") {
		t.Fatalf("json missing protocol_id: %q", out[:120])
	}
	if !strings.Contains(out, "\"id\": \"INV-5\"") {
		t.Fatalf("json missing the seeded invariant: %q", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestModelMissingFile(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	missing := root + "/nope.json"
	code, out, errS := run(t, "--root", root, "model", cid, missing)
	if code != 1 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errS,
		"error: [Errno 2] No such file or directory: '"+missing+"'") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestModelInvalidSchema(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	bad := t14TestWrite(t, root, "nomodel.json", `{"protocol_id":"x"}`)
	code, out, errS := run(t, "--root", root, "model", cid, bad)
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "model load failed: protocol_model validation failed at <root>: " +
		"'name' is a required property (+4 more errors)\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestModelHelp(t *testing.T) {
	code, out, errS := run(t, "model", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != t14ModelHelp {
		t.Fatalf("help = %q, want %q", out, t14ModelHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}
