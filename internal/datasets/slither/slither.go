// Package slither is the Wave G G1 adapter: Slither JSON output becomes
// campaign hypothesis payloads that ride the existing ingest path — same
// dedup fingerprints, same gates, and an honest provenance tag. A tool flag
// is a HYPOTHESIS, never evidence: impact/confidence from Slither are
// rendered into the description, never into severity.
//
// Contract mirrors internal/datasets/defihacklabs: unmapped labels fall to
// the default class, ordering is explicit (no map iteration in output), and
// Informational/Low-signal checks are dropped because the framework's budget
// law says every finding costs reviewer time.
package slither

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"websec/internal/validation"
)

// Dataset names the adapter for messages.
const Dataset = "slither"

// minImpact admits Medium/High/Critical findings only.
var admittedImpacts = map[string]bool{"High": true, "Critical": true, "Medium": true}

// checkClasses maps Slither check ids to canonical taxonomy classes. It
// lists ONLY non-default mappings: anything absent maps to logic-error
// (the taxonomy advisory on ingest is then the honest signal, not a silent
// invention).
var checkClasses = map[string]string{
	"reentrancy-eth":           "reentrancy",
	"reentrancy-no-eth":        "reentrancy",
	"reentrancy-unlimited-gas": "reentrancy",
	"unchecked-transfer":       "unchecked-external-call",
	"unchecked-lowlevel":       "unchecked-external-call",
	"calls-loop":               "dos-griefing",
	"locked-ether":             "dos-griefing",
	"arbitrary-send-eth":       "access-control",
	"suicidal":                 "access-control",
	"tx-origin":                "access-control",
	"weak-prng":                "signature-replay",
	"uninitialized-state":      "upgrade-initializer",
	"uninitialized-public":     "upgrade-initializer",
}

const defaultClass = "logic-error"

// ToPayloads renders every admitted Slither result as a hypothesis payload,
// in deterministic (path, line, check) order.
//
// The document shape is the REAL one (slither 0.11.6, captured 2026-09-11):
// `results` is an OBJECT whose `detectors` array holds the findings, and a
// location is NOT a `vertex` — it is an element's `source_mapping`:
//
//	{success, error, results:{detectors:[{check, impact, confidence,
//	   description, elements:[{type, name, source_mapping:{
//	     filename_relative, filename_short, filename_absolute,
//	     is_dependency, lines[]}}]}]}}
//
// An earlier revision of this adapter read `results` as an array and locations
// from `vertices[].filename/line_no`; nothing in a real Slither document
// matches that shape, so it silently produced ZERO payloads on every real run.
// Note there is no `impact` band below Informational to fall back on and no
// vertex kind to filter: every element is a location, and only elements that
// (a) are not dependencies and (b) carry at least one line can be anchored. A
// location we cannot anchor is noise, so the element is dropped rather than
// guessed at.
func ToPayloads(doc validation.Value) ([]validation.Value, error) {
	type row struct {
		path  string
		line  int64
		check string
		out   validation.Value
	}
	var rows []row
	detectors := valsOf(validation.ObjAt(validation.ObjAt(doc, "results"), "detectors"))
	for _, r := range detectors {
		check := validation.ObjStr(r, "check")
		if check == "" {
			return nil, fmt.Errorf("slither: result without 'check' id")
		}
		if !admittedImpacts[validation.ObjStr(r, "impact")] {
			continue
		}
		desc := strings.TrimSpace(validation.ObjStr(r, "description"))
		if desc == "" {
			continue
		}
		type site struct {
			path string
			line int64
		}
		var sites []site
		for _, el := range valsOf(validation.ObjAt(r, "elements")) {
			sm := validation.ObjAt(el, "source_mapping")
			if sm.Kind != validation.Obj {
				continue
			}
			if validation.ObjAt(sm, "is_dependency").B {
				continue // a dependency's location is not this repo's code
			}
			// The filename fallback chain: relative -> short -> absolute.
			fn := validation.ObjStr(sm, "filename_relative")
			if fn == "" {
				fn = validation.ObjStr(sm, "filename_short")
			}
			if fn == "" {
				fn = validation.ObjStr(sm, "filename_absolute")
			}
			// lines[0] anchors the element; an element without lines (or
			// with an empty `lines` array) has no line we can render.
			lines := valsOf(validation.ObjAt(sm, "lines"))
			if fn == "" || len(lines) == 0 || lines[0].Kind != validation.Int {
				continue
			}
			sites = append(sites, site{fn, lines[0].I})
		}
		if len(sites) == 0 {
			continue // a flag with no location cannot anchor; drop it
		}
		sort.Slice(sites, func(i, j int) bool {
			if sites[i].path != sites[j].path {
				return sites[i].path < sites[j].path
			}
			return sites[i].line < sites[j].line
		})
		affected := make([]validation.Value, 0, len(sites))
		for _, s := range sites {
			affected = append(affected, validation.VObj(
				kv("path", validation.VStr(s.path)),
				kv("lines", validation.VArr(
					validation.VInt(s.line), validation.VInt(s.line))),
				kv("entry_point", validation.VBool(false))))
		}
		cls, ok := checkClasses[check]
		if !ok {
			cls = defaultClass
		}
		title := "Slither " + check + ": " + firstLine(desc)
		if utf8.RuneCountInString(title) > 120 {
			title = string([]rune(title)[:117]) + "..."
		}
		out := validation.VObj(
			kv("title", validation.VStr(title)),
			kv("root_cause", validation.VObj(
				kv("class", validation.VStr(cls)),
				kv("description", validation.VStr(clip(desc, 900))),
				kv("mechanism", validation.VStr("static pattern: slither/"+check)))),
			kv("affected", validation.VArr(affected...)),
			kv("attacker", validation.VObj(
				kv("profile", validation.VStr("static analysis (Slither)")),
				kv("capabilities", validation.VArr()))),
			kv("evidence", validation.VArr()),
			kv("provenance", validation.VObj(
				kv("discovered_by", validation.VStr("sast/slither")),
				kv("sast_tools", validation.VArr(
					validation.VStr("slither:"+check))))),
		)
		rows = append(rows, row{sites[0].path, sites[0].line, check, out})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].path != rows[j].path {
			return rows[i].path < rows[j].path
		}
		if rows[i].line != rows[j].line {
			return rows[i].line < rows[j].line
		}
		return rows[i].check < rows[j].check
	})
	out := make([]validation.Value, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.out)
	}
	return out, nil
}

// firstLine is the text up to the first newline, trimmed.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// clip cuts to n RUNES (byte cuts split UTF-8 and Python never did).
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}

// ---- local ordered-object helpers (same pattern as internal/dedup) -------

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func valsOf(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}
