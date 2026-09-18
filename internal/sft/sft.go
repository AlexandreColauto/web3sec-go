// Package sft ports webv2.sft_dataset: the SFT critical-bug reasoning dataset
// — a committed store, a curation lint, a leakage-safe cluster split, a mix
// report, and trajectory backfill.
//
// WHY: production reasoning is trained on exactly what production sends. The
// store (sft/examples.json) is committed to git — VCS is the integrity layer,
// unlike the machine-generated eval store — and the human curator is the only
// reasoner: this package is pure format/lint/store machinery, with no model
// calls. The lint mechanizes the curation rubric (arc markers, per-taxonomy
// requirements, reason completeness, placeholder markers, pivot accounting,
// impact specificity, name anchoring, dedup) so a draft cannot reach the
// corpus half-formed.
package sft

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"websec/internal/validation"
)

const (
	// StoreVersion is STORE_VERSION.
	StoreVersion = 1
	// SFTDirName is SFT_DIR_NAME.
	SFTDirName = "sft"
	// ExamplesName is EXAMPLES_NAME.
	ExamplesName = "examples.json"
)

// Taxonomies / Partitions / Statuses are the closed vocabularies, in order.
var (
	Taxonomies = []string{"confirmed-critical",
		"real-weakness-non-exploitable", "invalid-hypothesis",
		"exploitable-below-threshold"}
	Partitions = []string{"training", "held-out"}
	Statuses   = []string{"draft", "curated", "rejected"}
)

// RepoRoot is the tree sft/ hangs off. Python resolves it from __file__; the
// Go binary has no repo, so it defaults to the working directory (the harness
// runs from inside the workspace, which is where the store lives).
var RepoRoot = "."

func init() {
	if wd, err := os.Getwd(); err == nil {
		RepoRoot = wd
	}
}

// storePathOverride is the test/CLI seam for store_path (Python monkeypatches
// the module function; the store is repo data, not workspace data).
var storePathOverride func() string

// SetStorePath points the store at an explicit file ("" restores the default).
func SetStorePath(p string) {
	if p == "" {
		storePathOverride = nil
		return
	}
	storePathOverride = func() string { return p }
}

// StorePath is store_path: <repo>/sft/examples.json (or the seam override).
// WEBV2_SFT_STORE points the store at an explicit file (D28: the reference
// resolves it from its source tree; the binary defaults to the cwd — the
// override is how the two twins share one store from any working directory).
func StorePath() string {
	if storePathOverride != nil {
		return storePathOverride()
	}
	if env := os.Getenv("WEBV2_SFT_STORE"); env != "" {
		return env
	}
	return filepath.Join(RepoRoot, SFTDirName, ExamplesName)
}

// LoadStore is _load_store: the store document, or the empty default when the
// file does not exist. A corrupt or oddly-shaped store fails LOUD — a silent
// reset would discard curated data.
func LoadStore() (validation.Value, error) {
	p := StorePath()
	if _, err := os.Stat(p); err != nil {
		return emptyStore(), nil
	}
	data, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull(), fmt.Errorf(
			"sft store corrupt or unreadable at %s: %s", p, err)
	}
	if data.Kind != validation.Obj || validation.ObjAt(data, "examples").Kind != validation.Arr {
		return validation.VNull(), fmt.Errorf(
			"sft store has unexpected shape at %s", p)
	}
	return data, nil
}

func emptyStore() validation.Value {
	return validation.VObj(
		validation.KV{K: "version", V: validation.VInt(StoreVersion)},
		validation.KV{K: "examples", V: validation.VArr()})
}

// SaveStore is _save_store: atomic indent-2 write (never a partial store).
func SaveStore(store validation.Value) error {
	return validation.WriteJson(StorePath(), store, "")
}

// NextExampleID is next_example_id: the max existing SFT-NNNN + 1.
func NextExampleID(store validation.Value) string {
	n := 0
	for _, e := range validation.ObjAt(store, "examples").A {
		m := exampleIDRe.FindStringSubmatch(validation.ObjStr(e, "id"))
		if m == nil {
			continue
		}
		got, err := strconv.Atoi(m[1])
		if err == nil && got > n {
			n = got
		}
	}
	return fmt.Sprintf("SFT-%04d", n+1)
}

var exampleIDRe = regexp.MustCompile(`^SFT-([0-9]+)$`)

// ---- value helpers -------------------------------------------------------

// objStrDefault is `v.get(key) or default` for strings.
func objStrDefault(v validation.Value, key, def string) string {
	if x := validation.ObjAt(v, key); x.Kind == validation.Str && x.S != "" {
		return x.S
	}
	return def
}

// setKey is Python dict assignment: replace in place (position preserved), or
// append when absent.
func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	out := append([]validation.KV(nil), v.O...)
	for i := range out {
		if out[i].K == key {
			out[i].V = val
			v.O = out
			return v
		}
	}
	v.O = append(out, validation.KV{K: key, V: val})
	return v
}

// pyNumText is f"{value}" for an int/float JSON value.
func pyNumText(v validation.Value) string {
	switch v.Kind {
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	}
	return ""
}

// schemaMsg is `getattr(e, "message", None) or str(e)`.
func schemaMsg(err error) string {
	if se, ok := err.(*validation.SchemaError); ok && se.Msg != "" {
		return se.Msg
	}
	return err.Error()
}

// trimSpace is Python str.strip() on a string value ("" for non-strings).
func trimSpace(v validation.Value) string {
	if v.Kind == validation.Str {
		return strings.TrimSpace(v.S)
	}
	return ""
}
