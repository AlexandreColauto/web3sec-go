// Package anchorlink is the read-side code-anchor join across a campaign's
// three stores: probe-surface rows, plan priorities, and findings.
//
// CANONICAL KEY (docs/feedback-triage-morph-r2.md §B7): the snapshot-relative
// model path from protocol_model.contracts[].path — e.g.
// "l1/rollup/Rollup.sol" — optionally qualified by a function,
// "l1/rollup/Rollup.sol#commitBatch". The three stores spell the same code
// lead differently: a surface row carries a contract NAME plus
// consumer/asserter names and lines, a plan priority carries components[]
// that are either contract NAMES or lifecycle ids ("rollup/BatchLifecycle"),
// and a finding carries affected[] file paths with line ranges. This package
// resolves all three onto that one key so the stores can be compared.
//
// NO-WRITE-JOIN DECISION (§B7, the §5 replay): the name→path join needs only
// artifacts a campaign already holds, so legacy campaigns are joined at read
// time and NOTHING is migrated. The mint-time `anchors` stamps B7 adds later
// are a pre-materialization of this join for ranking speed, not a
// precondition for correctness. This package never writes a campaign: every
// input is a decoded artifact value and every output is a plain string,
// leaving the caller free to render it (stdout bytes elsewhere in this CLI
// are golden-pinned, so B7 renders additive --json/stderr surfaces only).
//
// COLLISION RULE (§B7/F5): matching is by full model path, never by basename.
// A contract NAME that the model maps to more than one path is a BASENAME
// citation: it resolves to every candidate path (so a query about a basename
// still reaches the row that cites it), but it CONVERGES nothing by itself —
// a candidate path counts a basename citation only once some store cites that
// path BY FULL PATH. The full path is what resolves the collision, so two
// stores that both cite a basename never manufacture an anchor on both
// copies, while a surface row naming the ambiguous L1ERC20Gateway does join
// the finding that cites contracts/l1/gateways/L1ERC20Gateway.sol. The morph
// model really carries four ambiguous names (Tree, Verify, GatewayBase,
// OwnableBase — each defined under two paths), so this rule is live, not
// theoretical. An
// unknown name resolves to nothing rather than to a fuzzy match.
//
// The store is built from the model once and then asked about rows,
// priorities and findings:
//
//	s, err := anchorlink.Open(model)
//	if err != nil { ... }
//	s.Index(surfaceRows, planPriorities, findings)
//	paths, funcs := s.RowTargets(row)
//	m := s.Query("l1/rollup/Rollup.sol#commitBatch:204")
//	anchors := s.Convergences(surfaceRows, planPriorities, findings)
package anchorlink

import (
	"errors"
	"sort"
	"strings"

	"websec/internal/validation"
)

// Store resolves campaign stores onto canonical model paths. Build it with
// Open, wire the three stores with Index, then query.
type Store struct {
	// namePaths maps a model contract name to the snapshot-relative paths
	// that carry it. len(paths) > 1 marks a basename citation: it resolves to
	// every candidate path but converges none of them (see the collision rule
	// above).
	namePaths map[string][]string
	// paths is every model path, sorted, so suffix matching is deterministic.
	paths []string
	// pathSet is the exact-path membership test.
	pathSet map[string]bool
	// lifecycle is the set of model state_machines[].name values: the only
	// strings a priority component may use as a "<dir>/<MachineName>"
	// lifecycle id. A component that is not one of these is unknown and
	// resolves to nothing — the machine name is never ignored.
	lifecycle map[string]bool

	// The three stores Index wired in; Query reads them.
	rows       []validation.Value
	priorities []validation.Value
	findings   []validation.Value
}

// Open builds the model index: contract name -> path(s), plus the state
// machine names that make a priority component a lifecycle id. It reads only
// protocol_model.contracts[] and protocol_model.state_machines[]; a contract
// entry missing its name or path is skipped (it cannot be anchored).
func Open(model validation.Value) (*Store, error) {
	if model.Kind != validation.Obj {
		return nil, errors.New("anchorlink: model must be a JSON object")
	}
	s := &Store{
		namePaths: map[string][]string{},
		pathSet:   map[string]bool{},
		lifecycle: map[string]bool{},
	}
	contracts := validation.ObjAt(model, "contracts")
	if contracts.Kind != validation.Null && contracts.Kind != validation.Arr {
		return nil, errors.New("anchorlink: model.contracts must be an array")
	}
	for _, c := range contracts.A {
		name := validation.ObjStr(c, "name")
		path := normalizePath(validation.ObjStr(c, "path"))
		if name == "" || path == "" {
			continue
		}
		if !s.pathSet[path] {
			s.pathSet[path] = true
			s.paths = append(s.paths, path)
		}
		if !contains(s.namePaths[name], path) {
			s.namePaths[name] = append(s.namePaths[name], path)
		}
	}
	sort.Strings(s.paths)
	machines := validation.ObjAt(model, "state_machines")
	if machines.Kind != validation.Null && machines.Kind != validation.Arr {
		return nil, errors.New("anchorlink: model.state_machines must be an array")
	}
	for _, m := range machines.A {
		if name := validation.ObjStr(m, "name"); name != "" {
			s.lifecycle[name] = true
		}
	}
	return s, nil
}

// Index wires the campaign's three stores into the join Query reads. Rows,
// priorities and findings are the decoded probe_surface.rows[],
// campaign_plan.priorities[] and findings. It returns the store so a caller
// can chain.
func (s *Store) Index(rows, priorities, findings []validation.Value) *Store {
	s.rows, s.priorities, s.findings = rows, priorities, findings
	return s
}

// RowTargets resolves a probe-surface row onto canonical paths and functions:
// the row's contract plus its siblings[] contracts give the paths (a row
// names its own contract; a sibling names the site the row compares it to),
// and the row's consumer/asserter names ride along as the functions the row
// anchors. A contract name the model carries on more than one path yields
// every candidate path (a basename citation — Convergences is where the full
// path resolves it); an unknown name contributes no path.
func (s *Store) RowTargets(row validation.Value) (paths []string, funcs []string) {
	paths, funcs = []string{}, []string{}
	for _, name := range rowContractNames(row) {
		for _, c := range s.nameCitations(name) {
			paths = appendUnique(paths, c.path)
		}
	}
	for _, f := range []string{validation.ObjStr(row, "consumer"),
		validation.ObjStr(row, "asserter")} {
		if f != "" {
			funcs = appendUnique(funcs, f)
		}
	}
	return paths, funcs
}

// PriorityTargets resolves a plan priority's components[] onto canonical
// paths. A component is either a model contract NAME (resolved through the
// model; a name carried by several paths yields them all, as a basename
// citation) or a model state-machine id of the form "<dir>/<MachineName>" (a
// lifecycle id): the lifecycle id is matched against the model's
// state_machines[].name set first — so the machine name is never ignored and
// an invented id resolves to nothing — and then reaches every model path
// whose directory ends with <dir> at a segment boundary. Thus
// "rollup/BatchLifecycle" reaches l1/rollup/Rollup.sol, while the plan's
// "l2gw/..." ids (no such model directory) resolve to nothing. Never fuzzy.
func (s *Store) PriorityTargets(prio validation.Value) []string {
	out := []string{}
	for _, c := range stringList(prio, "components") {
		for _, cite := range s.componentCitations(c) {
			out = appendUnique(out, cite.path)
		}
	}
	sort.Strings(out)
	return out
}

// FindingTargets resolves a finding's affected[] entries onto canonical
// paths. The affected file is normalized (the schema field is `path`; `file`
// is accepted as the brief's alias, and "./" and "\" are stripped) and
// accepted in two forms: the exact snapshot-relative model path, or any path
// ENDING WITH a model contract's path at a segment boundary — the morph
// findings carry repo-prefixed forms like
// "contracts/l1/rollup/Rollup.sol" while the model path is
// "l1/rollup/Rollup.sol". This is ONE directional suffix rule, and when a
// normalized file matches more than one model path (one model path being a
// suffix of another) the LONGEST model path wins.
func (s *Store) FindingTargets(finding validation.Value) []string {
	out := []string{}
	for _, a := range valueList(finding, "affected") {
		raw := validation.ObjStr(a, "path")
		if raw == "" {
			raw = validation.ObjStr(a, "file")
		}
		if p := s.resolveFilePath(raw); p != "" {
			out = appendUnique(out, p)
		}
	}
	return out
}

// citation is one resolved coordinate plus how it was reached: ambiguous
// marks a path reached through a contract NAME the model carries on more than
// one path (a basename citation). Convergences withholds those until a store
// pins the path by full path; the query and target APIs return them as-is.
type citation struct {
	path      string
	ambiguous bool
}

// nameCitations is the collision rule: every path carrying the name, each
// flagged ambiguous when the name is not unique. An unknown name yields none.
func (s *Store) nameCitations(name string) []citation {
	paths := s.namePaths[name]
	out := make([]citation, 0, len(paths))
	for _, p := range paths {
		out = append(out, citation{path: p, ambiguous: len(paths) > 1})
	}
	return out
}

// componentCitations is the priority-component rule (see PriorityTargets).
func (s *Store) componentCitations(component string) []citation {
	if component == "" {
		return nil
	}
	if _, known := s.namePaths[component]; known {
		return s.nameCitations(component)
	}
	if !s.lifecycle[component] {
		return nil // unknown name or invented lifecycle id: nothing, never fuzzy
	}
	i := strings.LastIndex(component, "/")
	if i <= 0 {
		return nil
	}
	// A lifecycle id is a DIRECTORY citation, not a basename one: the rule is
	// the documented "<dir>/<MachineName> -> every path under */<dir>", so it
	// needs no full-path pin to converge.
	out := []citation{}
	for _, p := range s.pathsUnderDir(component[:i]) {
		out = append(out, citation{path: p})
	}
	return out
}

// pathUnderDir reports whether path's directory equals dir or ends with it at
// a segment boundary ("l1/rollup" ends with "rollup"; "l2/gateways" does not
// end with "l2gw").
func pathUnderDir(path, dir string) bool {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return false
	}
	parent := path[:i]
	return parent == dir || strings.HasSuffix(parent, "/"+dir)
}

// pathsUnderDir returns every model path under dir (sorted, since s.paths is).
func (s *Store) pathsUnderDir(dir string) []string {
	out := []string{}
	for _, p := range s.paths {
		if pathUnderDir(p, dir) {
			out = append(out, p)
		}
	}
	return out
}

// resolveFilePath is the finding suffix rule, longest model path wins.
func (s *Store) resolveFilePath(raw string) string {
	norm := normalizePath(raw)
	if norm == "" {
		return ""
	}
	if s.pathSet[norm] {
		return norm
	}
	best := ""
	for _, p := range s.paths {
		if strings.HasSuffix(norm, "/"+p) && len(p) > len(best) {
			best = p
		}
	}
	return best
}

// rowContractNames is the row's contract plus every sibling's contract, in
// row order.
func rowContractNames(row validation.Value) []string {
	out := []string{}
	if name := validation.ObjStr(row, "contract"); name != "" {
		out = appendUnique(out, name)
	}
	for _, sib := range valueList(row, "siblings") {
		if name := validation.ObjStr(sib, "contract"); name != "" {
			out = appendUnique(out, name)
		}
	}
	return out
}

// normalizePath is the ONE path normalizer: backslashes to slashes, a leading
// "./" and any leading "/" dropped, trailing spaces trimmed.
func normalizePath(raw string) string {
	p := strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return strings.TrimPrefix(p, "/")
}

// valueList is obj[key] as a list (empty when absent or not an array).
func valueList(obj validation.Value, key string) []validation.Value {
	v := validation.ObjAt(obj, key)
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

// stringList is obj[key] filtered to its string elements.
func stringList(obj validation.Value, key string) []string {
	out := []string{}
	for _, v := range valueList(obj, key) {
		if v.Kind == validation.Str && v.S != "" {
			out = append(out, v.S)
		}
	}
	return out
}

// intList is obj[key] filtered to its integer elements, in order.
func intList(obj validation.Value, key string) []int {
	out := []int{}
	for _, v := range valueList(obj, key) {
		switch v.Kind {
		case validation.Int:
			out = append(out, int(v.I))
		case validation.Flt:
			out = append(out, int(v.F))
		}
	}
	return out
}

// appendUnique appends the values not already present, preserving order.
func appendUnique(dst []string, vals ...string) []string {
	for _, v := range vals {
		if v == "" || contains(dst, v) {
			continue
		}
		dst = append(dst, v)
	}
	return dst
}

// contains is slices.Contains without the import at every call site.
func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
