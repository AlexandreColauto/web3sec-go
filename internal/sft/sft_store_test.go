package sft

// Port of tests/test_sft_store.py (Task A): the store core — id assignment,
// copy semantics, schema + lint gates, the status-transition path, list
// filters, the loud corrupt-store failure, JSONL export, and the committed
// seeds (real repo file) linting clean.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestSFTMissingStoreIsEmpty(t *testing.T) {
	useStore(t)
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(store, "version").I; got != 1 {
		t.Fatalf("version = %d", got)
	}
	if got := objAt(store, "examples"); got.Kind != validation.Arr || len(got.A) != 0 {
		t.Fatalf("examples = %v", got)
	}
}

func TestSFTAddAssignsIDAndPersists(t *testing.T) {
	useStore(t)
	caller := baseExample(t)
	ex, err := AddExample(caller, "draft")
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(ex, "id"); got != "SFT-0001" {
		t.Fatalf("id = %q", got)
	}
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	rows := objAt(store, "examples").A
	if len(rows) != 1 || objStr(rows[0], "id") != "SFT-0001" {
		t.Fatalf("store = %v", rows)
	}
	// caller's dict untouched (copy semantics)
	if hasKey(caller, "id") {
		t.Fatal("caller's dict was mutated")
	}
}

func TestSFTAddSecondGetsNextID(t *testing.T) {
	useStore(t)
	if _, err := AddExample(baseExample(t), "draft"); err != nil {
		t.Fatal(err)
	}
	ex2, err := AddExample(baseExample(t), "draft")
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(ex2, "id"); got != "SFT-0002" {
		t.Fatalf("id = %q", got)
	}
}

func TestSFTAddRejectsBadSchema(t *testing.T) {
	useStore(t)
	ex := baseExample(t)
	assumptions := objAt(atPath(ex, "structured"), "assumptions").A
	assumptions[0] = setKey(assumptions[0], "id", validation.VStr("B1"))
	ex = setAt(ex, validation.VArr(assumptions...), "structured", "assumptions")
	_, err := AddExample(ex, "draft")
	if err == nil || !strings.Contains(err.Error(), "schema violation") {
		t.Fatalf("err = %v", err)
	}
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(store, "examples"); len(got.A) != 0 {
		t.Fatalf("partial write: %v", got)
	}
}

func TestSFTAddRejectsDuplicateID(t *testing.T) {
	useStore(t)
	if _, err := AddExample(baseExample(t), "draft"); err != nil {
		t.Fatal(err)
	}
	dup := baseExample(t, kv("id", validation.VStr("SFT-0001")))
	_, err := AddExample(dup, "draft")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v", err)
	}
}

func TestSFTUpdateTransitionsAndVersionBump(t *testing.T) {
	useStore(t)
	ex, err := AddExample(baseExample(t), "draft")
	if err != nil {
		t.Fatal(err)
	}
	id, curated := objStr(ex, "id"), "x"
	cur, err := UpdateExample(id, strPtr("curated"), &curated, nil)
	if err != nil {
		t.Fatal(err)
	}
	if objStr(cur, "status") != "curated" || objAt(cur, "version").I != 2 {
		t.Fatalf("curated = %v", cur)
	}
	_, err = UpdateExample(id, strPtr("draft"), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "illegal transition") {
		t.Fatalf("err = %v", err)
	}
}

func TestSFTRejectedRequiresReasons(t *testing.T) {
	useStore(t)
	ex, err := AddExample(baseExample(t), "draft")
	if err != nil {
		t.Fatal(err)
	}
	id := objStr(ex, "id")
	_, err = UpdateExample(id, strPtr("rejected"), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "rejection_reasons") {
		t.Fatalf("err = %v", err)
	}
	rej, err := UpdateExample(id, strPtr("rejected"), nil,
		[]string{"vague impact"})
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(rej, "status"); got != "rejected" {
		t.Fatalf("status = %q", got)
	}
}

func TestSFTListFilters(t *testing.T) {
	useStore(t)
	a, err := AddExample(baseExample(t), "draft")
	if err != nil {
		t.Fatal(err)
	}
	// `b` must be lint-valid for its own taxonomy (the Task B gate lints
	// every add): an invalid-hypothesis needs a REFUTED trace assumption
	// naming the misreading and no VIOLATED invariant.
	b, err := AddExample(invalidExample(t), "draft")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateExample(objStr(a, "id"), strPtr("curated"), nil, nil); err != nil {
		t.Fatal(err)
	}
	curated, err := ListExamples(strPtr("curated"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(curated) != 1 || objStr(curated[0], "id") != objStr(a, "id") {
		t.Fatalf("curated = %v", curated)
	}
	byTax, err := ListExamples(nil, nil, strPtr("invalid-hypothesis"))
	if err != nil {
		t.Fatal(err)
	}
	if len(byTax) != 1 || objStr(byTax[0], "id") != objStr(b, "id") {
		t.Fatalf("by taxonomy = %v", byTax)
	}
}

func TestSFTGetMissingRaises(t *testing.T) {
	useStore(t)
	if _, err := GetExample("SFT-9999"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSFTCorruptStoreFailsLoud(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(root, "sft"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "sft", ExamplesName)
	if err := os.WriteFile(p, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	SetStorePath(p)
	t.Cleanup(func() { SetStorePath("") })
	_, err := LoadStore()
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("err = %v", err)
	}
}

func TestSFTStorePathEnvOverride(t *testing.T) {
	root := t.TempDir()
	env := filepath.Join(root, "elsewhere", "store.json")
	t.Setenv("WEBV2_SFT_STORE", env)
	if got := StorePath(); got != env {
		t.Fatalf("StorePath() = %q, want %q", got, env)
	}
	SetStorePath(filepath.Join(root, "explicit.json"))
	defer SetStorePath("")
	if got := StorePath(); got != filepath.Join(root, "explicit.json") {
		t.Fatalf("explicit seam lost to env: %q", got)
	}
}

func TestSFTExportJSONLOnlyCurated(t *testing.T) {
	useStore(t)
	a, err := AddExample(baseExample(t), "draft")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddExample(baseExample(t), "draft"); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateExample(objStr(a, "id"), strPtr("curated"), nil, nil); err != nil {
		t.Fatal(err)
	}
	text, err := ExportJSONL(nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{}
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("lines = %v", lines)
	}
	row, err := validation.ParseOrdered([]byte(lines[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(row.O) != 1 || row.O[0].K != "messages" {
		t.Fatalf("keys = %v", row)
	}
}

func TestSFTSeedStoreLintsCleanAndShape(t *testing.T) {
	repoStore(t)
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	rows := objAt(store, "examples").A
	ids := []string{}
	for _, e := range rows {
		ids = append(ids, objStr(e, "id"))
	}
	if strings.Join(ids, ",") != "SFT-0001,SFT-0002" {
		t.Fatalf("ids = %v", ids)
	}
	prompt := promptText(t)
	for _, e := range rows {
		if objStr(e, "status") != "curated" {
			t.Fatalf("status = %q", objStr(e, "status"))
		}
		if got := objStr(arrAt(objAt(e, "messages"), 0), "content"); got != prompt {
			t.Fatalf("system prompt drift on %s", objStr(e, "id"))
		}
		if err := validation.Validate(e, "sft_example", 1); err != nil {
			t.Fatal(err)
		}
	}
	byID := map[string]validation.Value{}
	for _, e := range rows {
		byID[objStr(e, "id")] = e
	}
	if got := objStr(byID["SFT-0001"], "taxonomy"); got != "confirmed-critical" {
		t.Fatalf("SFT-0001 taxonomy = %q", got)
	}
	if got := intOf(atPath(byID["SFT-0001"], "structured", "pivot_count")); got != 1 {
		t.Fatalf("SFT-0001 pivot_count = %d", got)
	}
	if got := objStr(byID["SFT-0002"], "taxonomy"); got !=
		"real-weakness-non-exploitable" {
		t.Fatalf("SFT-0002 taxonomy = %q", got)
	}
}

func TestSFTSeedExamplesPassFullLint(t *testing.T) {
	repoStore(t)
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	curated := []validation.Value{}
	for _, e := range objAt(store, "examples").A {
		if objStr(e, "status") == "curated" {
			curated = append(curated, e)
		}
	}
	if len(curated) != 2 {
		t.Fatalf("curated = %d", len(curated))
	}
	for _, e := range curated {
		others := []validation.Value{}
		for _, x := range curated {
			if objStr(x, "id") != objStr(e, "id") {
				others = append(others, x)
			}
		}
		hard := hardReasons(LintExample(e, others, "curated"))
		if len(hard) != 0 {
			t.Fatalf("%s: %v", objStr(e, "id"), hard)
		}
	}
}

func strPtr(s string) *string { return &s }

// arrAt is Python's xs[i] for a JSON array.
func arrAt(v validation.Value, i int) validation.Value {
	if v.Kind == validation.Arr && i >= 0 && i < len(v.A) {
		return v.A[i]
	}
	return validation.VNull()
}

func intPtr(n int) *int { return &n }
