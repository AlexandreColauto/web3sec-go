package datasets

// Port of tests/test_datasets.py's three registry tests. Python asserts
// `REG.<name> is <module>` (the guarded __init__ import resolved) and that the
// adapter's load_records/ingest are callable; Go's static registry instead
// proves the stronger contract: each entry carries its subpackage's DATASET
// name and its LoadRecords delegates to the subpackage loader byte-for-byte on
// a tiny fixture.

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"websec/internal/datasets/defihacklabs"
	"websec/internal/datasets/forge"
	"websec/internal/datasets/scabench"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func writeJSON(t *testing.T, path string, v validation.Value) {
	t.Helper()
	if err := validation.WriteJson(path, v, ""); err != nil {
		t.Fatal(err)
	}
}

func TestDatasetsRegistryGuardedImportDefihacklabs(t *testing.T) {
	if DefiHackLabs.Name != defihacklabs.Dataset {
		t.Fatalf("registry name = %q want %q", DefiHackLabs.Name, defihacklabs.Dataset)
	}
	if DefiHackLabs.LoadRecords == nil || DefiHackLabs.Ingest == nil {
		t.Fatal("registry entry must carry load_records and ingest")
	}
	// Direct assignment: the registry entry IS the subpackage loader.
	if reflect.ValueOf(DefiHackLabs.LoadRecords).Pointer() !=
		reflect.ValueOf(defihacklabs.LoadRecords).Pointer() {
		t.Fatal("registry loader is not defihacklabs.LoadRecords")
	}
	base := t.TempDir()
	explorer := filepath.Join(base, "explorer")
	if err := os.MkdirAll(explorer, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(explorer, "incidents.json"), validation.VArr(
		validation.VObj(
			kv("date", validation.VStr("20240101")),
			kv("name", validation.VStr("Acme")),
			kv("type", validation.VStr("Reentrancy")),
			kv("Contract", validation.VStr("")),
			kv("chain", validation.VStr("Ethereum")))))
	writeJSON(t, filepath.Join(explorer, "rootcause_data.json"),
		validation.VObj())
	poc := filepath.Join(base, "poc")
	if err := os.MkdirAll(poc, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := DefiHackLabs.LoadRecords(&explorer, &poc)
	if err != nil {
		t.Fatalf("registry load: %v", err)
	}
	want, err := defihacklabs.LoadRecords(&explorer, &poc)
	if err != nil {
		t.Fatalf("subpackage load: %v", err)
	}
	if len(got) != 1 || len(want) != 1 {
		t.Fatalf("record counts = %d/%d want 1/1", len(got), len(want))
	}
	if validation.CanonCompact(validation.VArr(got...)) !=
		validation.CanonCompact(validation.VArr(want...)) {
		t.Fatal("registry loader diverged from the subpackage loader")
	}
}

func TestDatasetsRegistryGuardedImportForge(t *testing.T) {
	if Forge.Name != forge.Dataset {
		t.Fatalf("registry name = %q want %q", Forge.Name, forge.Dataset)
	}
	if Forge.LoadRecords == nil || Forge.Ingest == nil {
		t.Fatal("registry entry must carry load_records and ingest")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "findings")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(dir, "acme.json"), validation.VObj(
		kv("project_info", validation.VObj(
			kv("url", validation.VArr(
				validation.VStr("https://github.com/demo/acme"))))),
		kv("findings", validation.VArr(validation.VObj(
			kv("id", validation.VInt(0)),
			kv("category", validation.VObj(
				kv("1", validation.VArr(validation.VStr("CWE-284"))))),
			kv("title", validation.VStr("Missing access control on withdraw")),
			kv("description", validation.VStr(
				"The withdraw function is public and never checks the caller, "+
					"so anyone can drain the pool.")),
			kv("severity", validation.VStr("High")),
			kv("location", validation.VArr()),
			kv("files", validation.VArr()))))))
	got, err := Forge.LoadRecords(nil, &base)
	if err != nil {
		t.Fatalf("registry load: %v", err)
	}
	want, err := forge.LoadRecords(&base)
	if err != nil {
		t.Fatalf("subpackage load: %v", err)
	}
	if len(got) != 1 || len(want) != 1 {
		t.Fatalf("record counts = %d/%d want 1/1", len(got), len(want))
	}
	if validation.CanonCompact(validation.VArr(got...)) !=
		validation.CanonCompact(validation.VArr(want...)) {
		t.Fatal("registry loader diverged from the subpackage loader")
	}
}

func TestDatasetsRegistryGuardedImportsScabench(t *testing.T) {
	if Scabench.Name != scabench.Dataset {
		t.Fatalf("registry name = %q want %q", Scabench.Name, scabench.Dataset)
	}
	if Scabench.LoadRecords == nil || Scabench.Ingest == nil {
		t.Fatal("registry entry must carry load_records and ingest")
	}
	if len(All) != 3 {
		t.Fatalf("registry size = %d want 3", len(All))
	}
	src := filepath.Join(t.TempDir(), "curated.json")
	writeJSON(t, src, validation.VArr(validation.VObj(
		kv("project_id", validation.VStr("demo_2025")),
		kv("name", validation.VStr("Demo")),
		kv("platform", validation.VStr("code4rena")),
		kv("codebases", validation.VArr(validation.VObj(
			kv("repo_url", validation.VStr("https://github.com/demo/demo")),
			kv("commit", validation.VStr("main"))))),
		kv("vulnerabilities", validation.VArr(validation.VObj(
			kv("finding_id", validation.VStr("H-01")),
			kv("severity", validation.VStr("high")),
			kv("title", validation.VStr("Vault allows reentrant withdraw")),
			kv("description", validation.VStr(
				"The withdraw function makes an external call before "+
					"updating balances, allowing reentry."))))))))
	got, err := Scabench.LoadRecords(nil, &src)
	if err != nil {
		t.Fatalf("registry load: %v", err)
	}
	want, err := scabench.LoadRecords(&src)
	if err != nil {
		t.Fatalf("subpackage load: %v", err)
	}
	if len(got) != 1 || len(want) != 1 {
		t.Fatalf("record counts = %d/%d want 1/1", len(got), len(want))
	}
	if validation.CanonCompact(validation.VArr(got...)) !=
		validation.CanonCompact(validation.VArr(want...)) {
		t.Fatal("registry loader diverged from the subpackage loader")
	}
}
