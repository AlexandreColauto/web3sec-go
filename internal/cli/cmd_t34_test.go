package cli

// T34 wiring test: the dataset-record seam. The ported adapter is only useful
// once corpus.SetLoadPocRecords points at it (D26: attribution was
// absent-by-default before), and the golden harness's WEBV2_POC_ROOT patch has
// to reach the Go twins' package roots the same way sitecustomize reaches the
// reference's module constants.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"websec/internal/corpus"
	"websec/internal/datasets/defihacklabs"
	"websec/internal/validation"
)

func TestWireT34SeamsInstallsDatasetLoader(t *testing.T) {
	savedExplorer, savedPoc := defihacklabs.ExplorerDir, defihacklabs.PocRoot
	savedIncidents, savedRootcause := defihacklabs.IncidentsFile,
		defihacklabs.RootCauseFile
	savedCorpusPoc := corpus.PocRoot
	t.Cleanup(func() {
		defihacklabs.ExplorerDir = savedExplorer
		defihacklabs.PocRoot = savedPoc
		defihacklabs.IncidentsFile = savedIncidents
		defihacklabs.RootCauseFile = savedRootcause
		corpus.PocRoot = savedCorpusPoc
		corpus.SetLoadPocRecords(nil)
	})
	base := t.TempDir()
	explorer := filepath.Join(base, "explorer")
	poc := filepath.Join(base, "DeFiHackLabs")
	for _, dir := range []string{explorer, filepath.Join(poc, "src", "test", "2024-01")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFixtureJSON(t, filepath.Join(explorer, "incidents.json"), validation.VArr(
		validation.VObj(
			kvT("date", validation.VStr("20240101")),
			kvT("name", validation.VStr("Acme")),
			kvT("type", validation.VStr("Reentrancy")),
			kvT("Contract", validation.VStr("src/test/2024-01/Acme_exp.sol")),
			kvT("chain", validation.VStr("Ethereum")))))
	writeFixtureJSON(t, filepath.Join(explorer, "rootcause_data.json"),
		validation.VObj())
	if err := os.WriteFile(filepath.Join(poc, "src", "test", "2024-01",
		"Acme_exp.sol"), []byte("contract Acme_exp {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WEBV2_POC_ROOT", base)
	wireT34Seams()
	if got := corpus.PocRoot; got != filepath.Join(base, "DeFiHackLabs") {
		t.Fatalf("corpus.PocRoot = %q", got)
	}
	if got := defihacklabs.ExplorerDir; got != explorer {
		t.Fatalf("defihacklabs.ExplorerDir = %q want %q", got, explorer)
	}
	records, err := corpus.LoadPocRecords(nil, nil)
	if err != nil {
		t.Fatalf("LoadPocRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d want 1", len(records))
	}
	if got := objText(records[0], "id"); got != "defihacklabs-20240101-acme" {
		t.Fatalf("record id = %q", got)
	}
	// An absent clone still reports the corpus seam's absent-data sentinel.
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := corpus.LoadPocRecords(&missing, &missing); !errors.Is(err,
		corpus.ErrDatasetAbsent) {
		t.Fatalf("absent clone err = %v want ErrDatasetAbsent", err)
	}
}

func writeFixtureJSON(t *testing.T, path string, v validation.Value) {
	t.Helper()
	if err := validation.WriteJson(path, v, ""); err != nil {
		t.Fatal(err)
	}
}

func objText(v validation.Value, key string) string {
	for _, p := range v.O {
		if p.K == key && p.V.Kind == validation.Str {
			return p.V.S
		}
	}
	return ""
}
