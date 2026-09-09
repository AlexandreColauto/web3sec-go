// Package playbooks ports webv2.playbooks: the framework's PRIOR for one
// canonical bug class.
//
// A playbook names the invariants to extract, the decomposition skeleton the
// proposer instantiates per target, the prioritized hunt order, how attempts
// at this class typically die, and the prior rejections most likely to be
// re-raised. It is context for the proposer — never a verdict, never an
// instruction to the orchestrator (mirrors schema/playbook.schema.json).
// Playbooks are repo-level data, not campaign data: one file per class under
// playbooks/, embedded byte-for-byte from web3sec-final/playbooks/.
package playbooks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"websec/assets"
	"websec/internal/invariants"
	"websec/internal/validation"
)

// embeddedDir is the embed.FS prefix holding the shipped pack.
const embeddedDir = "playbooks"

// classRe is _CLASS_RE: the id shape a playbook file can serve — the
// schema's bug_class pattern. Anything else (including a path-traversal
// attempt) is a normal miss.
var classRe = regexp.MustCompile(`^[a-z0-9-]{3,64}$`)

// PlaybooksDir is PLAYBOOKS_DIR. The empty string means the embedded pack
// (Python resolves REPO_ROOT/playbooks from __file__; a Go binary has no
// source-relative root, so the pack is embedded). Tests and embedders point
// it at their own tree — the twin of a test setting PB.PLAYBOOKS_DIR.
var PlaybooksDir string

// SetPlaybooksDir points the loader at dir; an empty string restores the
// embedded pack.
func SetPlaybooksDir(dir string) { PlaybooksDir = dir }

// listFiles is sorted(PLAYBOOKS_DIR.glob("*.yaml")): the pack's file names,
// without directories.
func listFiles() ([]string, error) {
	if PlaybooksDir == "" {
		entries, err := fs.Glob(assets.PlaybooksFS, embeddedDir+"/*.yaml")
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, filepath.Base(e))
		}
		sort.Strings(out)
		return out, nil
	}
	entries, err := os.ReadDir(PlaybooksDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

// readFile is Path.read_text(encoding="utf-8") for a pack file name.
func readFile(name string) ([]byte, error) {
	if PlaybooksDir == "" {
		return assets.PlaybooksFS.ReadFile(embeddedDir + "/" + name)
	}
	return os.ReadFile(filepath.Join(PlaybooksDir, name))
}

// exists is Path.exists() for a pack file name.
func exists(name string) bool {
	if PlaybooksDir == "" {
		_, err := assets.PlaybooksFS.ReadFile(embeddedDir + "/" + name)
		return err == nil
	}
	_, err := os.Stat(filepath.Join(PlaybooksDir, name))
	return err == nil
}

// PlaybookForClass is playbook_for_class: load and validate
// playbooks/<bugClass>.yaml. found is false on a miss (a class without a
// playbook is normal, not an error); a present-but-invalid playbook is a
// deployment error and returns an error — fail loud, never silently degrade
// the proposer's context.
func PlaybookForClass(bugClass string) (data validation.Value, found bool, err error) {
	if !classRe.MatchString(bugClass) {
		return validation.VNull(), false, nil
	}
	name := bugClass + ".yaml"
	if !exists(name) {
		return validation.VNull(), false, nil
	}
	raw, err := readFile(name)
	if err != nil {
		return validation.VNull(), false, err
	}
	data, err = validation.ParseYaml(raw)
	if err != nil {
		return validation.VNull(), false,
			validation.ParseYamlFileError("playbook "+name, err)
	}
	if err := validation.Validate(data, "playbook", 1); err != nil {
		return validation.VNull(), false, err
	}
	if err := checkSimulationBlock(name, data); err != nil {
		return validation.VNull(), false, err
	}
	return data, true, nil
}

// AvailablePlaybooks is available_playbooks: sorted bug_class values of
// every *.yaml in the pack that loads AND validates. Files that fail to load
// or validate are skipped silently — the listing is what is usable, and a
// broken file surfaces loudly the moment its class is requested. A file that
// loads and validates but declares a bug_class different from its filename
// stem is a deployment error and returns an error: the listing would
// otherwise advertise a class PlaybookForClass can never serve.
func AvailablePlaybooks() ([]string, error) {
	files, err := listFiles()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(files))
	for _, name := range files {
		raw, rerr := readFile(name)
		if rerr != nil {
			continue
		}
		data, yerr := validation.ParseYaml(raw)
		if yerr != nil {
			continue
		}
		if err := validation.Validate(data, "playbook", 1); err != nil {
			continue
		}
		declared := objAt(data, "bug_class")
		stem := strings.TrimSuffix(name, ".yaml")
		if declared.Kind != validation.Str || declared.S != stem {
			return nil, fmt.Errorf(
				"playbook %s declares bug_class %s but its filename stem is "+
					"%s — a playbook must be named for the class it serves; "+
					"rename the file or fix the declaration",
				name, pyRepr(declared), validation.PyReprStr(stem))
		}
		out = append(out, declared.S)
	}
	sort.Strings(out)
	return out, nil
}

// checkSimulationBlock is _check_simulation_block: the loader-side checks
// JSON Schema cannot express (spec 3.2 §4.1). A broken simulation block is a
// deployment error — fail loud, same contract as schema validation.
func checkSimulationBlock(filename string, data validation.Value) error {
	sim := objAt(data, "simulation")
	if sim.Kind != validation.Obj {
		return nil
	}
	var names []string
	var classes []string
	for _, a := range listAt(sim, "actors") {
		if a.Kind != validation.Obj {
			continue
		}
		names = append(names, pyRepr(objAt(a, "name")))
		if c := objAt(a, "behavior_class"); c.Kind == validation.Str {
			classes = append(classes, c.S)
		}
	}
	if dupes := duplicateNames(names); len(dupes) > 0 {
		return fmt.Errorf("playbook %s: duplicate actor name(s) %s in "+
			"simulation block — actor names must be unique",
			filename, pyReprList(dupes))
	}
	if !containsStr(classes, "adversarial") ||
		!containsStr(classes, "benign-rational") {
		return fmt.Errorf("playbook %s: simulation cast needs at least one "+
			"'adversarial' and one 'benign-rational' actor — an all-one-side "+
			"cast is a deployment error (got %s)",
			filename, pyReprList(classes))
	}
	ref := objAt(sim, "expectation_violated")
	invIDs := []string{}
	for _, inv := range listAt(data, "invariants") {
		if inv.Kind != validation.Obj {
			continue
		}
		if id := objAt(inv, "id"); id.Kind == validation.Str {
			invIDs = append(invIDs, id.S)
		}
	}
	if ref.Kind != validation.Str || !containsStr(invIDs, ref.S) {
		return fmt.Errorf("playbook %s: simulation.expectation_violated %s "+
			"must name an invariant id declared in this playbook's "+
			"invariants list (found %s)",
			filename, pyRepr(ref), pyReprList(sortedStrings(invIDs)))
	}
	return nil
}

// CuratedInvariantIDs is curated_invariant_ids: invariant ids declared by
// any loadable playbook — the curated prior set that joins the documented
// set for guardrail source derivation (spec 3.2 §4.7). Sorted for
// determinism; ids are namespaced per class (INV-<PREFIX>-...) so they
// cannot collide with target-doc INV-<n> ids.
func CuratedInvariantIDs() []string {
	seen := map[string]bool{}
	classes, err := AvailablePlaybooks()
	if err != nil {
		return nil
	}
	for _, cls := range classes {
		pb, found, perr := PlaybookForClass(cls)
		if perr != nil || !found {
			continue
		}
		for _, inv := range listAt(pb, "invariants") {
			if inv.Kind != validation.Obj {
				continue
			}
			if id := objAt(inv, "id"); id.Kind == validation.Str && id.S != "" {
				seen[id.S] = true
			}
		}
	}
	return sortedKeys(seen)
}

// init wires the invariants seam: playbooks cannot be imported by invariants
// (that would be a cycle), so the twin of Python's module-level import edge
// happens here.
func init() { invariants.SetCuratedInvariantIDs(CuratedInvariantIDs) }

// ---- helpers -------------------------------------------------------------

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func listAt(v validation.Value, key string) []validation.Value {
	x := objAt(v, key)
	if x.Kind != validation.Arr {
		return nil
	}
	return x.A
}

// duplicateNames is sorted({n for n in names if names.count(n) > 1}).
func duplicateNames(names []string) []string {
	seen := map[string]int{}
	for _, n := range names {
		seen[n]++
	}
	var out []string
	for n, c := range seen {
		if c > 1 {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func sortedStrings(xs []string) []string {
	out := append([]string{}, xs...)
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pyRepr is Python's repr() of a YAML scalar (None for a missing key).
func pyRepr(v validation.Value) string {
	if v.Kind == validation.Null {
		return "None"
	}
	if v.Kind == validation.Str {
		return validation.PyReprStr(v.S)
	}
	return validation.DumpsOrdered(v, false)
}

// pyReprList renders a list the way Python's repr() does (sorted here: every
// caller passes a sorted slice).
func pyReprList(xs []string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		if x == "None" {
			parts[i] = "None"
			continue
		}
		parts[i] = validation.PyReprStr(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
