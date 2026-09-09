package cli

// cmd_t34_wire: the dataset-record seam (Python's import-time connection for
// webv2.datasets.defihacklabs, in one place).
//
// D26: corpus_surface._poc_attribution reads
// datasets.defihacklabs.load_records and attaches record_id / memory_ids /
// bug_class to every shape match. The Go seam (corpus.SetLoadPocRecords)
// defaulted to the absent-clone signal, so attribution was always empty even
// when the real clones were on disk. wireT34Seams installs the ported loader.
//
// The WEBV2_POC_ROOT patch the golden harness applies to the Python twin's
// module constants (sitecustomize.py: EXPLORER_DIR/INCIDENTS_FILE/
// ROOTCAUSE_FILE = <base>/explorer*, POC_ROOT = <base>/DeFiHackLabs) is
// applied here to the Go twins' package variables, so both sides resolve the
// same roots from the same one variable.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/corpus"
	"websec/internal/datasets/defihacklabs"
	"websec/internal/validation"
)

// loadPocRecords adapts the ported adapter to the corpus seam, translating the
// adapter's FileNotFoundError twin into corpus.ErrDatasetAbsent so
// BuildReport's documented absent-clone degradation still fires.
func loadPocRecords(explorerDir, pocRoot *string) ([]validation.Value, error) {
	records, err := defihacklabs.LoadRecords(explorerDir, pocRoot)
	if err != nil {
		var absent *defihacklabs.CloneAbsentError
		if errors.As(err, &absent) {
			return nil, fmt.Errorf("%w: %s", corpus.ErrDatasetAbsent, absent.Path)
		}
		return nil, err
	}
	return records, nil
}

// wireT34Seams installs the T34 seam targets. Idempotent.
func wireT34Seams() {
	if base := os.Getenv("WEBV2_POC_ROOT"); base != "" {
		defihacklabs.SetRoots(base)
		corpus.SetPocRoot(filepath.Join(base, "DeFiHackLabs"))
	}
	corpus.SetLoadPocRecords(loadPocRecords)
}

// WireT34Seams is wireT34Seams for cmd/webv2's init (Python's import-time
// connections are wired in both the CLI dispatch path and the binary's init,
// exactly like the T26/T28/T33 seams).
func WireT34Seams() { wireT34Seams() }
