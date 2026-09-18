package anchorlink

import (
	"strconv"
	"strings"

	"websec/internal/validation"
)

// dispositionedStatuses is planner.ProbeRowDispositioned: the plan statuses
// that mean a probe row has been discharged. It is copied rather than
// imported so this read-side join stays a leaf package; a test pins the copy
// against the planner's list, so drift fails the build instead of silently
// re-labelling every row as open.
var dispositionedStatuses = []string{"answered", "not-applicable", "deprioritized"}

// Matches is what a Query pattern reached, grouped by store: the surface rows
// it intersects (with the row's tier and disposition status), the OPEN plan
// priority ids, and the finding ids.
type Matches struct {
	Rows       []RowMatch
	Priorities []string
	Findings   []string
}

// RowMatch is one surface row a pattern reaches. Disposition is the status of
// the plan priority that claims the row through probe.row_id (the same
// provenance probe rows are dispositioned by); "undispositioned" means no
// priority claims it, and Dispositioned reports whether that status is one of
// the planner's terminal dispositions.
type RowMatch struct {
	RowID         string
	Tier          int
	Disposition   string
	Dispositioned bool
}

// Query intersects one pattern with the three stores Index wired in.
//
// Pattern grammar: a path part, an optional "#Function", and an optional
// ":line" — "Rollup.sol", "l1/rollup/Rollup.sol", "Rollup.sol#commitBatch",
// "Rollup.sol#commitBatch:204", "l1/rollup/Rollup.sol:204". The path part
// matches a canonical path by SEGMENT-BOUNDARY SUFFIX IN EITHER DIRECTION: an
// operator may type the basename ("Rollup.sol"), a directory tail
// ("rollup/Rollup.sol") or the full model path, and a repo-prefixed spelling
// matches too. This is deliberately looser than the finding resolution rule
// (FindingTargets is directional and longest-wins) because a query is a
// search, not a convergence claim: ambiguity here widens the answer instead
// of inventing an anchor.
//
// A row matches through its resolved anchor sites (contract+consumer,
// contract+asserter, siblings): the path part must match the site's path, and
// the function/line qualifiers must match that site's function/line. A
// priority matches through PriorityTargets on the pattern's PATH part only
// (priorities carry no line-level coordinates; a fn-qualified query still
// lists them as path-level members), and only while it is OPEN. A finding matches through affected[]: the path part
// may match the raw affected file or its resolved model path, and a line
// matches when it falls inside the entry's lines range.
//
// An empty pattern, or one with neither a path nor a function, matches
// nothing.
func (s *Store) Query(pattern string) Matches {
	out := Matches{Rows: []RowMatch{}, Priorities: []string{}, Findings: []string{}}
	q, ok := parsePattern(pattern)
	if !ok {
		return out
	}
	for _, row := range s.rows {
		rowID := validation.ObjStr(row, "row_id")
		if rowID == "" || !s.rowMatches(row, q) {
			continue
		}
		status := s.rowDisposition(rowID)
		out.Rows = append(out.Rows, RowMatch{
			RowID:         rowID,
			Tier:          objInt(row, "tier"),
			Disposition:   status,
			Dispositioned: contains(dispositionedStatuses, status),
		})
	}
	for _, p := range s.priorities {
		// Priorities carry no function/line coordinates, so a fn-qualified
		// query still returns the OPEN priorities that match its PATH part:
		// a question about Rollup is a question about commitBatch on Rollup
		// (B8 acceptance; round-2 review finding 1).
		if !priorityOpen(p) || q.path == "" {
			continue
		}
		for _, target := range s.PriorityTargets(p) {
			if pathMatches(q.path, target) {
				out.Priorities = append(out.Priorities, validation.ObjStr(p, "id"))
				break
			}
		}
	}
	for _, f := range s.findings {
		if id := validation.ObjStr(f, "finding_id"); id != "" && s.findingMatches(f, q) {
			out.Findings = append(out.Findings, id)
		}
	}
	return out
}

// rowMatches applies the pattern to the row's resolved anchor sites.
func (s *Store) rowMatches(row validation.Value, q pattern) bool {
	for _, st := range s.rowSites(row) {
		if !pathMatches(q.path, st.path) {
			continue
		}
		if q.fn != "" && st.fn != q.fn {
			continue
		}
		if q.line != 0 && st.line != q.line {
			continue
		}
		return true
	}
	return false
}

// findingMatches applies the pattern to the finding's affected[] entries.
func (s *Store) findingMatches(finding validation.Value, q pattern) bool {
	for _, a := range valueList(finding, "affected") {
		raw := validation.ObjStr(a, "path")
		if raw == "" {
			raw = validation.ObjStr(a, "file")
		}
		if raw == "" {
			continue
		}
		if q.fn != "" && validation.ObjStr(a, "function") != q.fn {
			continue
		}
		if q.line != 0 && !lineInRange(intList(a, "lines"), q.line) {
			continue
		}
		if pathMatches(q.path, normalizePath(raw)) {
			return true
		}
		if p := s.resolveFilePath(raw); p != "" && pathMatches(q.path, p) {
			return true
		}
	}
	return false
}

// rowDisposition is the row's disposition status: the status of the FIRST
// plan priority that claims the row through probe.row_id — the provenance
// probe rows are dispositioned by (probes.RowDispositions reads the same
// field). A row no priority claims is "undispositioned"; the morph handoff
// campaign was 40 rows / 0 dispositioned, so that is the common answer, not
// an error. Staleness (shape_sha drift) is not judged here: this is a
// read-side join and it re-derives no row shape.
func (s *Store) rowDisposition(rowID string) string {
	for _, p := range s.priorities {
		prov := validation.ObjAt(p, "probe")
		if prov.Kind != validation.Obj || validation.ObjStr(prov, "row_id") != rowID {
			continue
		}
		if status := validation.ObjStr(p, "status"); status != "" {
			return status
		}
		return "undispositioned"
	}
	return "undispositioned"
}

// site is one resolved code coordinate: a canonical path, the function
// anchored there ("" when the site names only a line), and the line (0 when
// the site names no line).
type site struct {
	path string
	fn   string
	line int
}

// rowCite is one resolved row coordinate with its citation provenance.
type rowCite struct {
	citation
	fn   string
	line int
}

// rowCitations resolves the row's anchor coordinates. A contract name the
// model carries on several paths yields a coordinate on each of them: the row
// really does cite that name, so a query about any of those files must reach
// it. It is Convergences — not Query — that requires a full-path pin before a
// basename citation may count toward an anchor.
func (s *Store) rowCitations(row validation.Value) []rowCite {
	out := []rowCite{}
	contract := validation.ObjStr(row, "contract")
	add := func(name, fn string, line int) {
		if name == "" || (fn == "" && line == 0) {
			return
		}
		for _, c := range s.nameCitations(name) {
			out = append(out, rowCite{citation: c, fn: fn, line: line})
		}
	}
	add(contract, validation.ObjStr(row, "consumer"), objInt(row, "consumer_line"))
	add(contract, validation.ObjStr(row, "asserter"), objInt(row, "asserter_line"))
	for _, sib := range valueList(row, "siblings") {
		add(validation.ObjStr(sib, "contract"), "", objInt(sib, "line"))
	}
	return out
}

// rowSites is rowCitations without the provenance flag, for pattern matching.
func (s *Store) rowSites(row validation.Value) []site {
	out := []site{}
	for _, c := range s.rowCitations(row) {
		out = append(out, site{path: c.path, fn: c.fn, line: c.line})
	}
	return out
}

// pattern is a parsed Query pattern. path == "" means "any path"; fn == ""
// means "any function"; line == 0 means "any line".
type pattern struct {
	path string
	fn   string
	line int
}

// parsePattern splits "<path>[#<function>][:<line>]"; the line may trail
// either part ("Rollup.sol:204", "Rollup.sol#commitBatch:204"). A pattern with
// neither a path nor a function is not a query.
func parsePattern(raw string) (pattern, bool) {
	p := pattern{path: strings.TrimSpace(raw)}
	if p.path == "" {
		return p, false
	}
	if i := strings.Index(p.path, "#"); i >= 0 {
		p.fn, p.path = p.path[i+1:], p.path[:i]
	}
	if p.fn != "" {
		if i := strings.LastIndex(p.fn, ":"); i >= 0 && isDigits(p.fn[i+1:]) {
			p.line = atoi(p.fn[i+1:])
			p.fn = p.fn[:i]
		}
	}
	if p.line == 0 {
		if i := strings.LastIndex(p.path, ":"); i >= 0 && isDigits(p.path[i+1:]) {
			p.line = atoi(p.path[i+1:])
			p.path = p.path[:i]
		}
	}
	p.path = normalizePath(p.path)
	if p.path == "" && p.fn == "" {
		return p, false
	}
	return p, true
}

// pathMatches is the query's path rule: equality, or a segment-boundary
// suffix in either direction. It never matches a bare basename inside a
// longer name ("Rollup.sol" does not match "NotRollup.sol").
func pathMatches(patternPath, target string) bool {
	if patternPath == "" {
		return true
	}
	if patternPath == target {
		return true
	}
	return strings.HasSuffix(patternPath, "/"+target) ||
		strings.HasSuffix(target, "/"+patternPath)
}

// priorityOpen reports whether a plan priority is still open. The planner
// always writes `status`; a missing one reads as open (a priority with no
// status has not been closed).
func priorityOpen(prio validation.Value) bool {
	switch validation.ObjStr(prio, "status") {
	case "", "open":
		return true
	}
	return false
}

// lineInRange reports whether line falls inside an affected entry's lines
// range (the schema writes [first,last]; a one-element list is an equality).
func lineInRange(lines []int, line int) bool {
	if len(lines) == 0 {
		return false
	}
	if len(lines) == 1 {
		return lines[0] == line
	}
	lo, hi := lines[0], lines[0]
	for _, l := range lines[1:] {
		if l < lo {
			lo = l
		}
		if l > hi {
			hi = l
		}
	}
	return line >= lo && line <= hi
}

// objInt reads an integer field (0 when absent; a float truncates, mirroring
// the planner's rowInt).
func objInt(obj validation.Value, key string) int {
	v := validation.ObjAt(obj, key)
	switch v.Kind {
	case validation.Int:
		return int(v.I)
	case validation.Flt:
		return int(v.F)
	}
	return 0
}

// isDigits reports whether s is a non-empty run of ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// atoi parses digits already validated by isDigits.
func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
