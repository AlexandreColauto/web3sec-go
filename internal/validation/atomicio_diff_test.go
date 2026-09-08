package validation

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDumpIndentedMatchesCPython: the golden files in testdata were
// produced by CPython 3.14 json.dumps(indent=2, ensure_ascii=False) +
// "\n" (insertion order as written). Go must re-dump them byte-for-byte.
func TestDumpIndentedMatchesCPython(t *testing.T) {
	for _, name := range []string{"nested", "empty", "empties", "arr"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join("testdata", name+".in.json")
			want, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			v, err := ReadJson(p)
			if err != nil {
				t.Fatal(err)
			}
			got := []byte(DumpIndented(v) + "\n")
			if string(got) != string(want) {
				t.Errorf("byte mismatch:\n got %q\nwant %q", got, want)
			}
		})
	}
}
