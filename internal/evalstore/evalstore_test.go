package evalstore

// Port of tests/test_eval_store.py: the eval store is repo-level and
// tamper-evident. These tests pin the contract: validate-then-write, unique
// ids, framework-owned stamping, working filters, and a verifier that catches
// an edited case, a hand edit to the file, a missing sidecar, and
// hand-created duplicate ids.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/validation"
)

func store(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "eval")
	SetEvalDir(d)
	t.Cleanup(ResetEvalDir)
	return d
}

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

// caseVal is the Python `_case` fixture (overrides replace whole keys).
func caseVal(caseID string, over ...validation.KV) validation.Value {
	base := []validation.KV{
		kv("case_id", validation.VStr(caseID)),
		kv("source", validation.VObj(
			kv("dataset", validation.VStr("scabench")),
			kv("record_id", validation.VStr("REC-1")),
			kv("url", validation.VStr("https://example.com/rec-1")))),
		kv("partition", validation.VStr("dev")),
		kv("program", validation.VObj(
			kv("program", validation.VStr("Acme Protocol")),
			kv("platform", validation.VStr("immunefi")),
			kv("chains", validation.VArr(validation.VStr("ethereum"))))),
		kv("gold", validation.VObj(
			kv("outcome", validation.VStr("confirmed-exploitable")),
			kv("bug_class", validation.VStr("reentrancy")),
			kv("severity", validation.VStr("high")),
			kv("root_cause", validation.VStr(
				"external call fires before the state update")),
			kv("locations", validation.VArr(validation.VObj(
				kv("file", validation.VStr("src/Vault.sol")),
				kv("line", validation.VInt(42))))))),
		kv("code", validation.VObj(
			kv("repo", validation.VStr("acme/vault")),
			kv("commit", validation.VStr(strings.Repeat("a", 40))),
			kv("files", validation.VArr(validation.VStr("src/Vault.sol"))))),
		kv("created_at", validation.VStr("2026-09-04T12:00:00+00:00")),
		kv("schema_version", validation.VInt(2)),
	}
	return validation.VObj(mergeKVs(base, over)...)
}

// mergeKVs is dict.update: replace an existing key in place, append a new one.
func mergeKVs(base []validation.KV, over []validation.KV) []validation.KV {
	out := append([]validation.KV(nil), base...)
	for _, o := range over {
		replaced := false
		for i := range out {
			if out[i].K == o.K {
				out[i].V = o.V
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, o)
		}
	}
	return out
}

// rehash recomputes the sidecar over the current cases.json bytes (simulating
// an editor that keeps the sidecar in sync — corruption must still be caught
// by re-validation, not only by the hash).
func rehash(t *testing.T, dir string) {
	t.Helper()
	digest, err := validation.Sha256File(filepath.Join(dir, CasesName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, SidecarName),
		[]byte(digest+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEvalStoreAddThenLoadRoundtrip(t *testing.T) {
	store(t)
	stored, err := AddCase(caseVal("CASE-" + strings.Repeat("a", 12)))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCase(stored.O[0].V.S)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonCompact(loaded) != validation.CanonCompact(stored) {
		t.Fatalf("load_case mismatch:\n%s\n%s",
			validation.CanonCompact(loaded), validation.CanonCompact(stored))
	}
	cases, err := ListCases(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || validation.CanonCompact(cases[0]) !=
		validation.CanonCompact(stored) {
		t.Fatalf("list_cases = %v", cases)
	}
	if got := VerifyEvalStore(); !got.OK || got.Count != 1 {
		t.Fatalf("verify = %+v", got)
	}
}

func TestEvalStoreAddStampsFrameworkOwnedFields(t *testing.T) {
	store(t)
	stored, err := AddCase(validation.VObj(
		kv("source", validation.VObj(
			kv("dataset", validation.VStr("manual")),
			kv("record_id", validation.VStr("x")))),
		kv("program", validation.VObj(
			kv("program", validation.VStr("Acme")))),
		kv("gold", validation.VObj(
			kv("outcome", validation.VStr("disproved")),
			kv("bug_class", validation.VStr("unmapped")),
			kv("root_cause", validation.VStr(
				"the suspected bug is intended behavior")))),
		kv("code", validation.VObj(kv("repo", validation.VStr("acme/vault"))))))
	if err != nil {
		t.Fatal(err)
	}
	cid := objStr(stored, "case_id")
	if !regexp.MustCompile(`^CASE-[a-f0-9]{12}$`).MatchString(cid) {
		t.Fatalf("case_id = %q", cid)
	}
	if got := objStr(stored, "partition"); got != "dev" {
		t.Fatalf("partition = %q", got)
	}
	if got := objAt(stored, "schema_version"); got.Kind != validation.Int || got.I != 2 {
		t.Fatalf("schema_version = %v", got)
	}
	if objAt(stored, "created_at").Kind != validation.Str ||
		objStr(stored, "created_at") == "" {
		t.Fatal("created_at not stamped")
	}
}

func TestEvalStoreDuplicateCaseIDRejected(t *testing.T) {
	store(t)
	if _, err := AddCase(caseVal("CASE-" + strings.Repeat("a", 12))); err != nil {
		t.Fatal(err)
	}
	_, err := AddCase(caseVal("CASE-" + strings.Repeat("a", 12)))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v", err)
	}
}

func TestEvalStoreInvalidCaseRejectedAndNothingWritten(t *testing.T) {
	dir := store(t)
	_, err := AddCase(caseVal("CASE-"+strings.Repeat("a", 12), kv("gold",
		validation.VObj(
			kv("outcome", validation.VStr("not-a-real-outcome")),
			kv("bug_class", validation.VStr("reentrancy")),
			kv("root_cause", validation.VStr(
				"external call before update"))))))
	if err == nil {
		t.Fatal("expected a schema error")
	}
	if _, ok := err.(*validation.SchemaError); !ok {
		t.Fatalf("err type %T: %v", err, err)
	}
	cases, err := ListCases(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 0 {
		t.Fatalf("cases = %v", cases)
	}
	if _, statErr := os.Stat(filepath.Join(dir, CasesName)); statErr == nil {
		t.Fatal("cases.json was written")
	}
}

func TestEvalStoreNoncanonicalBugClassRejected(t *testing.T) {
	store(t)
	_, err := AddCase(caseVal("CASE-"+strings.Repeat("a", 12), kv("gold",
		validation.VObj(
			kv("outcome", validation.VStr("disproved")),
			kv("bug_class", validation.VStr("Access Control")),
			kv("root_cause", validation.VStr(
				"external call before update"))))))
	if err == nil || !strings.Contains(err.Error(), "normalize_class") {
		t.Fatalf("err = %v", err)
	}
}

func TestEvalStoreLoadCaseMissingRaises(t *testing.T) {
	store(t)
	_, err := LoadCase("CASE-" + strings.Repeat("0", 12))
	if err == nil || !strings.Contains(err.Error(), "no eval case") {
		t.Fatalf("err = %v", err)
	}
}

func TestEvalStoreListFiltersPartitionDatasetProgram(t *testing.T) {
	store(t)
	mustAdd(t, caseVal("CASE-"+strings.Repeat("a", 12)))
	mustAdd(t, caseVal("CASE-"+strings.Repeat("b", 12),
		kv("partition", validation.VStr("held-out"))))
	mustAdd(t, caseVal("CASE-"+strings.Repeat("c", 12),
		kv("partition", validation.VStr("training")),
		kv("source", validation.VObj(
			kv("dataset", validation.VStr("forge")),
			kv("record_id", validation.VStr("F-1")))),
		kv("program", validation.VObj(
			kv("program", validation.VStr("Beta Protocol"))))))

	all, err := ListCases(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("len = %d", len(all))
	}
	check := func(partition, dataset, program *string, want ...string) {
		t.Helper()
		got, err := ListCases(partition, dataset, program)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(got))
		for _, c := range got {
			ids = append(ids, objStr(c, "case_id"))
		}
		if strings.Join(ids, ",") != strings.Join(want, ",") {
			t.Fatalf("filter(%v,%v,%v) = %v want %v",
				ptr(partition), ptr(dataset), ptr(program), ids, want)
		}
	}
	dev := "dev"
	check(&dev, nil, nil, "CASE-"+strings.Repeat("a", 12))
	held := "held-out"
	check(&held, nil, nil, "CASE-"+strings.Repeat("b", 12))
	train := "training"
	check(&train, nil, nil, "CASE-"+strings.Repeat("c", 12))
	forge := "forge"
	check(nil, &forge, nil, "CASE-"+strings.Repeat("c", 12))
	acme := "acme PROTOCOL"
	check(nil, nil, &acme, "CASE-"+strings.Repeat("a", 12),
		"CASE-"+strings.Repeat("b", 12))
	gamma := "Gamma"
	check(nil, nil, &gamma)
}

func TestEvalStoreVerifyOnFreshStore(t *testing.T) {
	store(t)
	got := VerifyEvalStore()
	if !got.OK || got.Count != 0 || len(got.Problems) != 0 {
		t.Fatalf("verify = %+v", got)
	}
	if v := got.Value(); validation.CanonCompact(v) !=
		`{"count":0,"ok":true,"problems":[]}` {
		t.Fatalf("value = %s", validation.CanonCompact(v))
	}
}

func TestEvalStoreVerifyDetectsCorruptedCase(t *testing.T) {
	dir := store(t)
	mustAdd(t, caseVal("CASE-"+strings.Repeat("a", 12)))
	p := filepath.Join(dir, CasesName)
	cases := readCases(t, p)
	cases[0].O[4].V.O[0].V = validation.VStr("not-a-real-outcome") // gold.outcome
	writeCasesRaw(t, p, cases)
	rehash(t, dir) // sidecar in sync: only re-validation can catch this
	got := VerifyEvalStore()
	if got.OK {
		t.Fatal("ok = true")
	}
	if got.Count != 1 {
		t.Fatalf("count = %d", got.Count)
	}
	if !anyContains(got.Problems, "validation failed") {
		t.Fatalf("problems = %v", got.Problems)
	}
}

func TestEvalStoreVerifyDetectsSidecarMismatch(t *testing.T) {
	dir := store(t)
	mustAdd(t, caseVal("CASE-"+strings.Repeat("a", 12)))
	p := filepath.Join(dir, CasesName)
	cases := readCases(t, p)
	// same content, different bytes: valid JSON, broken sidecar
	body, err := json.Marshal(toPlain(cases))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	got := VerifyEvalStore()
	if got.OK {
		t.Fatal("ok = true")
	}
	if !anyContains(got.Problems, "modified outside add_case") {
		t.Fatalf("problems = %v", got.Problems)
	}
}

func TestEvalStoreVerifyDetectsMissingSidecar(t *testing.T) {
	dir := store(t)
	mustAdd(t, caseVal("CASE-"+strings.Repeat("a", 12)))
	if err := os.Remove(filepath.Join(dir, SidecarName)); err != nil {
		t.Fatal(err)
	}
	got := VerifyEvalStore()
	if got.OK {
		t.Fatal("ok = true")
	}
	if !anyContains(got.Problems, "missing") {
		t.Fatalf("problems = %v", got.Problems)
	}
}

func TestEvalStoreVerifyDetectsHandMadeDuplicateIDs(t *testing.T) {
	dir := store(t)
	mustAdd(t, caseVal("CASE-"+strings.Repeat("a", 12)))
	p := filepath.Join(dir, CasesName)
	cases := readCases(t, p)
	cases = append(cases, cases[0])
	writeCasesRaw(t, p, cases)
	rehash(t, dir)
	got := VerifyEvalStore()
	if got.OK {
		t.Fatal("ok = true")
	}
	if !anyContains(got.Problems, "duplicate case_id") {
		t.Fatalf("problems = %v", got.Problems)
	}
}

// ---- helpers -------------------------------------------------------------

func mustAdd(t *testing.T, c validation.Value) validation.Value {
	t.Helper()
	out, err := AddCase(c)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func ptr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func anyContains(problems []string, want string) bool {
	for _, p := range problems {
		if strings.Contains(p, want) {
			return true
		}
	}
	return false
}

func readCases(t *testing.T, p string) []validation.Value {
	t.Helper()
	data, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	return data.A
}

func writeCasesRaw(t *testing.T, p string, cases []validation.Value) {
	t.Helper()
	if err := os.WriteFile(p, []byte(validation.DumpIndented(
		validation.VArr(cases...))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// toPlain converts to the encoding/json tree (json.dumps parity for the
// sidecar-mismatch leg).
func toPlain(cases []validation.Value) []any {
	raw := validation.DumpsOrdered(validation.VArr(cases...), false)
	var out []any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		panic(err)
	}
	return out
}
