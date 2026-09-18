package anchorlink

import (
	"sort"
	"strings"

	"websec/internal/validation"
)

// The three store names an Anchor reports. They are the package's stable
// vocabulary: "surface" is probe_surface.rows[], "plan" is
// campaign_plan.priorities[], "findings" is findings/*.json.
const (
	StoreSurface  = "surface"
	StorePlan     = "plan"
	StoreFindings = "findings"
)

// Anchor is one canonical-key convergence: a model path (optionally qualified
// by a function, Key == "path#Function") that at least TWO of the three stores
// independently name, together with the members that named it.
//
// A bare path is a member of every store that names it at all; a function key
// is additionally reported for the stores that carry function-level
// coordinates (surface rows through consumer/asserter, findings through
// affected[].function). Priorities have no function coordinates, so they only
// ever name the bare path — which is exactly why a path-level anchor is the
// robust convergence signal and the function-level one is the lead.
type Anchor struct {
	// Key is Path, or Path#Function.
	Key string
	// Path is the snapshot-relative model path — the canonical key.
	Path string
	// Function is the function the key qualifies, "" for a path-level anchor.
	Function string
	// Stores is the sorted subset of {StoreSurface, StorePlan, StoreFindings}
	// that named this anchor (len >= 2).
	Stores []string
	// Members, sorted: the row_ids, priority ids and finding_ids that named
	// it. A store with no member id to cite does not contribute.
	Rows       []string
	Priorities []string
	Findings   []string
}

// Convergences is the §5 replay's join: every canonical key named by at least
// two of the three stores, with its members. Rows contribute their resolved
// anchor sites, priorities their components[] targets, findings their
// affected[] targets. Priority status does not filter here — a closed
// priority still cited the code, and Query is the open-only view — but a
// store that cannot name an id (no row_id/priority id/finding_id) contributes
// nothing, because an uncitable member is not a lead.
//
// The COLLISION RULE bites here (and only here): a contract name the model
// carries on several paths is a basename citation, so it counts toward a
// candidate path only when some store PINS that path by full path — i.e. a
// finding whose affected file resolves to it. A lifecycle id's directory
// match is not a basename citation and needs no pin. This is what keeps two
// stores that both cite "L1ERC20Gateway" from manufacturing an anchor on both
// gateway copies, while still letting the row that cites the ambiguous name
// join the finding that cites contracts/l1/gateways/L1ERC20Gateway.sol.
//
// The result is sorted by Path then Function, and every member list is
// sorted, so the same artifacts always produce the same anchors.
func (s *Store) Convergences(rows, priorities, findings []validation.Value) []Anchor {
	pinned := map[string]bool{}
	for _, finding := range findings {
		for _, a := range valueList(finding, "affected") {
			raw := validation.ObjStr(a, "path")
			if raw == "" {
				raw = validation.ObjStr(a, "file")
			}
			if p := s.resolveFilePath(raw); p != "" {
				pinned[p] = true
			}
		}
	}
	accs := map[string]*anchorAcc{}
	add := func(c citation, fn, store, member string) {
		if c.path == "" || member == "" || (c.ambiguous && !pinned[c.path]) {
			return
		}
		key := c.path
		if fn != "" {
			key = c.path + "#" + fn
		}
		a, ok := accs[key]
		if !ok {
			a = &anchorAcc{stores: map[string]bool{}}
			accs[key] = a
		}
		a.stores[store] = true
		switch store {
		case StoreSurface:
			a.rows = appendUnique(a.rows, member)
		case StorePlan:
			a.priorities = appendUnique(a.priorities, member)
		case StoreFindings:
			a.findings = appendUnique(a.findings, member)
		}
	}
	for _, row := range rows {
		rowID := validation.ObjStr(row, "row_id")
		for _, c := range s.rowCitations(row) {
			add(c.citation, "", StoreSurface, rowID)
			add(c.citation, c.fn, StoreSurface, rowID)
		}
	}
	for _, prio := range priorities {
		prioID := validation.ObjStr(prio, "id")
		for _, component := range stringList(prio, "components") {
			for _, c := range s.componentCitations(component) {
				add(c, "", StorePlan, prioID)
			}
		}
	}
	for _, finding := range findings {
		findingID := validation.ObjStr(finding, "finding_id")
		for _, a := range valueList(finding, "affected") {
			raw := validation.ObjStr(a, "path")
			if raw == "" {
				raw = validation.ObjStr(a, "file")
			}
			path := s.resolveFilePath(raw)
			if path == "" {
				continue
			}
			c := citation{path: path}
			add(c, "", StoreFindings, findingID)
			add(c, validation.ObjStr(a, "function"), StoreFindings, findingID)
		}
	}
	out := []Anchor{}
	for key, a := range accs {
		if len(a.stores) < 2 {
			continue
		}
		path, fn := key, ""
		if i := strings.Index(key, "#"); i >= 0 {
			path, fn = key[:i], key[i+1:]
		}
		out = append(out, Anchor{
			Key:        key,
			Path:       path,
			Function:   fn,
			Stores:     sortedKeys(a.stores),
			Rows:       sortedCopy(a.rows),
			Priorities: sortedCopy(a.priorities),
			Findings:   sortedCopy(a.findings),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Function < out[j].Function
	})
	return out
}

// Convergences is the package-level form of (*Store).Convergences, for callers
// that hold the store and the three artifact slices side by side.
func Convergences(s *Store, rows, priorities, findings []validation.Value) []Anchor {
	if s == nil {
		return []Anchor{}
	}
	return s.Convergences(rows, priorities, findings)
}

// anchorAcc accumulates the members and stores that named one canonical key.
type anchorAcc struct {
	stores     map[string]bool
	rows       []string
	priorities []string
	findings   []string
}

// sortedKeys is the sorted store list of an accumulator.
func sortedKeys(stores map[string]bool) []string {
	out := make([]string, 0, len(stores))
	for k := range stores {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedCopy returns a sorted copy (nil-safe: always a non-nil slice).
func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}
