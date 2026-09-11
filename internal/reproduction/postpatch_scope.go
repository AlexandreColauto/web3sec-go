// postpatch_scope.go: Task 9 (G11 scope) — the changed-surface diff and the
// clean-control plant check. Advisory only: rows ride the Task 8 record's
// `detail` string (newline-joined, capped); the record shape never drifts
// and nothing consumes the output but the operator.
//
// FingerprintTree note (read before extracting, per the brief): the fp Value
// carries NO per-file map. FingerprintTree (internal/forkdiff/forkdiff.go:73)
// emits exactly six aggregate keys — contracts, selectors, state_vars,
// modifiers, delegatecall_functions, inherits — all tree-global sorted lists.
// A file→hash extraction from that shape is genuinely unextractable, so per
// the brief no parallel hasher is invented here (zero hashing anywhere in
// this file). ScopeDiff is pure file-set math instead: relative .sol path
// sets over the two snapshot dirs, modified detected by byte equality.
//
// PlantCheck consumes archetypes.EvaluatePrecondition unchanged
// (single-check, same detail format — the T3 precision contract) through the
// ScopePlantAPI seam. The seam exists because structidx→reproduction is a
// real import edge (structidx/wire.go), so this package cannot import
// structidx or archetypes directly — the same reason reachability.go reads
// through StructuralIndexAPI. internal/archetypes installs the real surface
// (WireScopePlant); the CLI and cmd/webv2 call it beside structidx.Wire().
package reproduction

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// postPatchScopeCap bounds scope output: 50 rows, then one overflow line
// (the bounded-output law — a vendored-deps patch must not flood the record).
const postPatchScopeCap = 50

// scopeExcludedDirs mirrors structidx's excludedDirs (parser.go): the scope
// must cover exactly the surface the index (and PlantCheck) sees.
var scopeExcludedDirs = map[string]bool{".git": true, "node_modules": true,
	"__pycache__": true, "cache": true, "out": true}

// ScopeDiff is the changed-surface diff: relative .sol path sets over the
// old and new snapshot trees. Rows are `~ <path>` modified, `+ <path>`
// added, `- <path>` removed, sorted; capped at postPatchScopeCap rows plus
// one `… and N more` overflow line. A missing/unreadable tree is an error
// (the honest BLOCKED-shaped path — a garbage dir cannot diff).
func ScopeDiff(oldSnapshotDir, newSnapshotDir string) ([]string, error) {
	oldFiles, err := scopeSolFiles(oldSnapshotDir)
	if err != nil {
		return nil, err
	}
	newFiles, err := scopeSolFiles(newSnapshotDir)
	if err != nil {
		return nil, err
	}
	oldSet, newSet := map[string]bool{}, map[string]bool{}
	for _, f := range oldFiles {
		oldSet[f] = true
	}
	for _, f := range newFiles {
		newSet[f] = true
	}
	var rows []string
	for _, f := range newFiles {
		if !oldSet[f] {
			rows = append(rows, "+ "+f)
			continue
		}
		same, err := scopeSameBytes(oldSnapshotDir, newSnapshotDir, f)
		if err != nil {
			return nil, err
		}
		if !same {
			rows = append(rows, "~ "+f)
		}
	}
	for _, f := range oldFiles {
		if !newSet[f] {
			rows = append(rows, "- "+f)
		}
	}
	sort.Strings(rows)
	if len(rows) > postPatchScopeCap {
		rest := len(rows) - postPatchScopeCap
		rows = append(rows[:postPatchScopeCap],
			fmt.Sprintf("… and %d more", rest))
	}
	return rows, nil
}

// scopeSolFiles is the snapshot's .sol surface: relative slash paths,
// sorted, with structidx's excluded dirs skipped (cf. collectFiles).
func scopeSolFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry,
		err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && scopeExcludedDirs[name] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			if scopeExcludedDirs[part] {
				return nil
			}
		}
		if filepath.Ext(path) != ".sol" {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// scopeSameBytes reports whether the two trees hold identical bytes at rel.
func scopeSameBytes(oldDir, newDir, rel string) (bool, error) {
	oldRaw, err := os.ReadFile(filepath.Join(oldDir,
		filepath.FromSlash(rel)))
	if err != nil {
		return false, err
	}
	newRaw, err := os.ReadFile(filepath.Join(newDir,
		filepath.FromSlash(rel)))
	if err != nil {
		return false, err
	}
	return bytes.Equal(oldRaw, newRaw), nil
}

// AppendScopeDetail rides scope rows on a Task 8 record's detail string:
// the existing detail is an opaque prefix, rows newline-join beneath it.
// Empty rows leave the detail untouched (no schema drift either way).
func AppendScopeDetail(detail string, rows []string) string {
	if len(rows) == 0 {
		return detail
	}
	if detail == "" {
		return strings.Join(rows, "\n")
	}
	return detail + "\n" + strings.Join(rows, "\n")
}

// ScopePlantAPI is the archetype/index surface PlantCheck needs (installed
// by internal/archetypes' WireScopePlant: real structidx indexing, the real
// archetype pack, the real EvaluatePrecondition).
type ScopePlantAPI struct {
	// BuildIndex is structidx.IndexSnapshot over the new tree (pure: no
	// writes, no docker — the regex backend never shells out).
	BuildIndex func(c *state.Campaign, root string) (validation.Value, error)
	// ArchetypeIDs is archetypes.AvailableArchetypes (sorted).
	ArchetypeIDs func() ([]string, error)
	// LoadArchetype is archetypes.LoadArchetypeByName.
	LoadArchetype func(id string) (validation.Value, error)
	// EvalCheck is archetypes.EvaluatePrecondition (single check).
	EvalCheck func(check, index validation.Value) (string, string, error)
}

var scopePlant = ScopePlantAPI{}

// SetScopePlantAPI installs the plant-check surface; the zero value restores
// the unwired state (PlantCheck then errors naming the seam).
func SetScopePlantAPI(api ScopePlantAPI) { scopePlant = api }

// PlantCheck runs every available archetype over the NEW snapshot tree and
// keeps hits whose file is in the changed set (bare relative .sol paths, the
// ScopeDiff form without the `~/+/-` prefixes). Any hit is a detail row
// `patch plants risk: <archetype-id> <path>:<line> (hint-only — triage
// decides)`; zero hits is `patch plants nothing new (N files checked)`.
// Archetype order is AvailableArchetypes order (sorted, re-sorted here for
// determinism) and rows sort before return.
func PlantCheck(c *state.Campaign, newSnapshotDir string,
	changedFiles []string) ([]string, error) {
	if scopePlant.BuildIndex == nil || scopePlant.ArchetypeIDs == nil ||
		scopePlant.LoadArchetype == nil || scopePlant.EvalCheck == nil {
		return nil, fmt.Errorf("plant check not wired: ScopePlantAPI " +
			"has no implementation (call archetypes.WireScopePlant)")
	}
	idx, err := scopePlant.BuildIndex(c, newSnapshotDir)
	if err != nil {
		return nil, err
	}
	changed := map[string]bool{}
	for _, f := range changedFiles {
		changed[f] = true
	}
	ids, err := scopePlant.ArchetypeIDs()
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	byID, byName := scopeNodeMaps(idx)
	edges := scopeArr(objAt(idx, "edges"))
	seen := map[string]bool{}
	var rows []string
	mark := func(s string) {
		if !seen[s] {
			seen[s] = true
			rows = append(rows, s)
		}
	}
	for _, aid := range ids {
		arch, err := scopePlant.LoadArchetype(aid)
		if err != nil {
			return nil, err
		}
		checks := scopeArr(objAt(arch, "checks"))
		matched, locs := true, []validation.Value{}
		for _, check := range checks {
			res, detail, err := scopePlant.EvalCheck(check, idx)
			if err != nil {
				return nil, err
			}
			if res != "present" {
				matched = false
				break
			}
			locs = append(locs,
				scopeHitNodes(check, detail, byID, byName, edges)...)
		}
		if !matched {
			continue
		}
		for _, n := range locs {
			p := objStr(n, "path")
			if p == "" || !changed[p] {
				continue
			}
			mark(fmt.Sprintf("patch plants risk: %s %s:%d "+
				"(hint-only — triage decides)", aid, p, scopeLine(n)))
		}
	}
	sort.Strings(rows)
	if len(rows) == 0 {
		return []string{fmt.Sprintf(
			"patch plants nothing new (%d files checked)",
			len(changedFiles))}, nil
	}
	return rows, nil
}

// scopeHitNodes resolves one present check's detail to index nodes: the hit
// list after the first ": " names functions/state vars (or node ids for
// external_call_pattern's "call sites"). delegatecall_present names nothing
// ("N delegatecall edge(s)"), so its locations come from the delegatecalls
// edges' from-nodes instead.
func scopeHitNodes(check validation.Value, detail string,
	byID map[string]validation.Value, byName map[string][]validation.Value,
	edges []validation.Value) []validation.Value {
	var out []validation.Value
	for _, tok := range scopeDetailToks(detail) {
		if n, ok := byID[tok]; ok {
			out = append(out, n)
			continue
		}
		out = append(out, byName[tok]...)
	}
	if len(out) == 0 && objStr(check, "type") == "delegatecall_present" {
		for _, e := range edges {
			if objStr(e, "rel") != "delegatecalls" {
				continue
			}
			if n, ok := byID[objStr(e, "from")]; ok {
				out = append(out, n)
			}
		}
	}
	return out
}

// scopeDetailToks splits a present detail ("prefix: a, b") into hit tokens.
func scopeDetailToks(detail string) []string {
	i := strings.Index(detail, ": ")
	if i < 0 {
		return nil
	}
	var out []string
	for _, tok := range strings.Split(detail[i+2:], ", ") {
		if tok = strings.TrimSpace(tok); tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// scopeNodeMaps indexes function + state-variable nodes by id and by name.
func scopeNodeMaps(idx validation.Value) (map[string]validation.Value,
	map[string][]validation.Value) {
	byID := map[string]validation.Value{}
	byName := map[string][]validation.Value{}
	for _, n := range scopeArr(objAt(idx, "nodes")) {
		if k := objStr(n, "kind"); k != "function" && k != "state-variable" {
			continue
		}
		if id := objStr(n, "id"); id != "" {
			byID[id] = n
		}
		if name := objStr(n, "name"); name != "" {
			byName[name] = append(byName[name], n)
		}
	}
	return byID, byName
}

// scopeArr reads an array Value (null-safe: a missing key is no nodes).
func scopeArr(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

// scopeLine reads a node's line (missing/null reads as 0 — same Int shape
// PostPatchVerdict's execExit trusts: Kind Int with empty Big).
func scopeLine(n validation.Value) int {
	if v := objAt(n, "line"); v.Kind == validation.Int && v.Big == "" {
		return int(v.I)
	}
	return 0
}
