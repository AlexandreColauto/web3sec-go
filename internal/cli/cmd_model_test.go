package cli

// T14 cmd_model tests: load/validate, the no-file summary, and the --json
// view. Vectors captured from the live Python CLI (py3.json [untracked]).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// t8FactsModelJSON is the I4 join fixture: a schema-valid model whose
// components carry the two identity fields the facts join reads.
const t8FactsModelJSON = `{"protocol_id":"factsdemo","name":"Facts Demo",` +
	`"components":[` +
	`{"kind":"frontend","url":"https://app.example","trust":"semi-trusted",` +
	`"in_scope":true,"paid_for":true},` +
	`{"kind":"offchain-service","path":"@openzeppelin/contracts",` +
	`"trust":"trusted","in_scope":true,"paid_for":false}],` +
	`"contracts":[{"name":"Vault","path":"src/Vault.sol"}],` +
	`"actors":[{"id":"user","kind":"EOA"}],` +
	`"assets":[{"id":"share","kind":"share"}],"relations":[]}`

// t8FactsDocJSON is the operator document matching t8FactsModelJSON.
const t8FactsDocJSON = `{"schema_version":"1","facts":[` +
	`{"target":{"kind":"frontend","url":"https://app.example"},` +
	`"dns":{"observed_at":"2026-01-02","source":"operator ticket OPS-77",` +
	`"records":{"a":["203.0.113.7"]}}},` +
	`{"target":{"kind":"offchain-service","path":"@openzeppelin/contracts"},` +
	`"dependency":{"observed_at":"2026-01-02",` +
	`"source":"operator-supplied manifest","package":"@openzeppelin/contracts",` +
	`"version":"v4.9.3"}}]}`

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
	// Task 7: the model-load cap moved 1 -> 25, so the whole ("also at")
	// path list is reported instead of the "(+4 more errors)" truncation.
	want := "model load failed: protocol_model validation failed at <root>: " +
		"'name' is a required property\n" +
		"  also at <root>: 'contracts' is a required property\n" +
		"  also at <root>: 'actors' is a required property\n" +
		"  also at <root>: 'assets' is a required property\n" +
		"  also at <root>: 'relations' is a required property\n"
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

// ---- I4: operator-supplied facts (Wave I Task 8) --------------------------

// TestModelWithoutFactsMovesNoBytes: --facts is presence-gated — the same
// invocation without it prints exactly the pre-change output, and WITH it
// prints that output plus one summary line.
func TestModelWithoutFactsMovesNoBytes(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	model := t14TestWrite(t, root, "model.json", t8FactsModelJSON)
	code, plain, errS := run(t, "--root", root, "model", cid, model)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	facts := t14TestWrite(t, root, "facts.json", t8FactsDocJSON)
	code, merged, errS := run(t, "--root", root, "model", cid, model,
		"--facts", facts)
	if code != 0 {
		t.Fatalf("facts exit %d: %q", code, errS)
	}
	want := "facts: 2 applied (1 dns, 1 dependency) onto 2 components\n"
	if merged != plain+want {
		t.Fatalf("merged stdout = %q, want %q (plain + summary)",
			merged, plain+want)
	}
	// the stored model is the MERGED one (the merge precedes the store)
	stored, err := os.ReadFile(filepath.Join(root, "campaigns", cid,
		"artifacts", "protocol_model.json"))
	if err != nil {
		t.Fatalf("read stored model: %v", err)
	}
	if !strings.Contains(string(stored), `"dns"`) ||
		!strings.Contains(string(stored), `"dependency"`) {
		t.Fatalf("stored model is not the merged one: %s", stored)
	}
}

// TestModelFactsJSONAcceptsDateFlag: --facts-observed-at is IGNORED (but
// accepted) for a JSON document, where every fact carries its own date.
func TestModelFactsJSONAcceptsDateFlag(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	model := t14TestWrite(t, root, "model.json", t8FactsModelJSON)
	facts := t14TestWrite(t, root, "facts.json", t8FactsDocJSON)
	code, out, errS := run(t, "--root", root, "model", cid, model,
		"--facts", facts, "--facts-observed-at", "1999-12-31")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasSuffix(out, "facts: 2 applied (1 dns, 1 dependency) "+
		"onto 2 components\n") {
		t.Fatalf("stdout = %q", out)
	}
}

// TestModelFactsDirectoryRequiresDate: a directory extraction has no date in
// it, so the companion flag is a usage error when missing (exit 2).
func TestModelFactsDirectoryRequiresDate(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	model := t14TestWrite(t, root, "model.json", t8FactsModelJSON)
	dir := filepath.Join(root, "manifests")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t14TestWrite(t, dir, "remappings.txt",
		"@openzeppelin/contracts/=lib/openzeppelin-contracts@v4.9.3/\n")
	code, out, errS := run(t, "--root", root, "model", cid, model,
		"--facts", dir)
	if code != 2 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "argument --facts-observed-at") {
		t.Fatalf("stderr = %q", errS)
	}
	// an invalid date is refused the same way
	code, _, errS = run(t, "--root", root, "model", cid, model,
		"--facts", dir, "--facts-observed-at", "02.01.2026")
	if code != 2 || !strings.Contains(errS, "argument --facts-observed-at") {
		t.Fatalf("bad date: exit %d err=%q", code, errS)
	}
}

// TestModelFactsDirectoryMerge: the directory mode extracts the offline
// manifests and merges them before the store.
func TestModelFactsDirectoryMerge(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	model := t14TestWrite(t, root, "model.json", t8FactsModelJSON)
	dir := filepath.Join(root, "manifests")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t14TestWrite(t, dir, "remappings.txt",
		"# comment\n@openzeppelin/contracts/=lib/openzeppelin-contracts@v4.9.3/\n")
	code, out, errS := run(t, "--root", root, "model", cid, model,
		"--facts", dir, "--facts-observed-at", "2026-01-02")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasSuffix(out, "facts: 1 applied (0 dns, 1 dependency) "+
		"onto 1 components\n") {
		t.Fatalf("stdout = %q", out)
	}
	stored, err := os.ReadFile(filepath.Join(root, "campaigns", cid,
		"artifacts", "protocol_model.json"))
	if err != nil {
		t.Fatalf("read stored model: %v", err)
	}
	if !strings.Contains(string(stored), `"v4.9.3"`) ||
		!strings.Contains(string(stored), `"2026-01-02"`) {
		t.Fatalf("stored model is not the merged one: %s", stored)
	}
}

// TestModelFactsNoMatchIsAnError: a typo'd target fails the whole load.
func TestModelFactsNoMatchIsAnError(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	model := t14TestWrite(t, root, "model.json", t8FactsModelJSON)
	facts := t14TestWrite(t, root, "facts.json",
		`{"schema_version":"1","facts":[{"target":{"kind":"frontend",`+
			`"url":"https://typo.example"},"dns":{"observed_at":"2026-01-02",`+
			`"source":"registrar export"}}]}`)
	code, out, errS := run(t, "--root", root, "model", cid, model,
		"--facts", facts)
	if code != 2 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS,
		"operator facts: no component matches kind=frontend url=https://typo.example") {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestModelFactsRequiresAModelFile: --facts merges into a loaded model, so
// the no-file form refuses it instead of silently ignoring the flag.
func TestModelFactsRequiresAModelFile(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	facts := t14TestWrite(t, root, "facts.json", t8FactsDocJSON)
	code, _, errS := run(t, "--root", root, "model", cid, "--facts", facts)
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "argument --facts") {
		t.Fatalf("stderr = %q", errS)
	}
}
