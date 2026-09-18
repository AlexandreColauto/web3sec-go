// Package aderyn is the I2a SAST adapter: Aderyn JSON output becomes campaign
// hypothesis payloads that ride the existing ingest path — same dedup
// fingerprints, same gates, and an honest provenance tag. A tool flag is a
// HYPOTHESIS, never evidence: the detector name and the description are
// rendered into the payload, never into a severity.
//
// The document shape is the REAL one (aderyn 0.6.8, captured 2026-09-11):
//
//	{files_summary, files_details, issue_count:{high,low},
//	 high_issues:{issues:[{title, description, detector_name, instances:[
//	   {contract_path, line_no, src, src_char}]}]},
//	 low_issues:{issues:[...]}, detectors_used:[...]}
//
// Only high_issues.issues[] is ADMITTED. Aderyn has no Medium band: `high` is
// its High/Critical analogue, mirroring the Slither loader's Medium/High/
// Critical admission. Aderyn exits 0 even when it has findings, so the exit
// code is never the signal — the JSON is. `issue_count` and `detectors_used`
// are informational only and are never consumed for admission.
//
// Contract mirrors internal/datasets/slither deliberately (the datasets
// packages duplicate this shape rather than sharing a helper package): unmapped
// detectors fall to the default class, ordering is explicit (no map iteration
// in output), and low-signal rows are dropped because the framework's budget
// law says every finding costs reviewer time.
package aderyn

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"websec/internal/validation"
)

// Dataset names the adapter for messages.
const Dataset = "aderyn"

// checkClasses maps Aderyn detector names to canonical taxonomy classes. It
// lists ONLY non-default mappings: anything absent maps to logic-error (the
// taxonomy advisory on ingest is then the honest signal, not a silent
// invention).
var checkClasses = map[string]string{
	"reentrancy-state-change":         "reentrancy",
	"unchecked-low-level-call":        "unchecked-external-call",
	"unchecked-return":                "unchecked-external-call",
	"unchecked-send":                  "unchecked-external-call",
	"delegate-call-unchecked-address": "unchecked-external-call",
	"arbitrary-transfer-from":         "access-control",
	"tx-origin-used-for-auth":         "access-control",
	"centralization-risk":             "access-control",
	"unprotected-initializer":         "upgrade-initializer",
	"weak-randomness":                 "signature-replay",
	"costly-loop":                     "dos-griefing",
	"contract-locks-ether":            "dos-griefing",
}

const defaultClass = "logic-error"

// toPayloadsRow is one rendered payload plus its sort keys.
type toPayloadsRow struct {
	path  string
	line  int64
	check string
	out   validation.Value
}

// toPayloadsSite is one anchorable instance location.
type toPayloadsSite struct {
	path string
	line int64
}

// toPayloadsState carries the payload rows across the sections of
// ToPayloads.
type toPayloadsState struct {
	rows []toPayloadsRow
}

// ToPayloads renders every admitted Aderyn issue as a hypothesis payload, in
// deterministic (path, line, detector) order. An issue whose every instance is
// unanchorable is dropped, exactly as the Slither adapter drops a flag with no
// location.
func ToPayloads(doc validation.Value) ([]validation.Value, error) {
	issues := valsOf(validation.ObjAt(validation.ObjAt(doc, "high_issues"), "issues"))
	s := &toPayloadsState{}
	for _, r := range issues {
		if err := s.toPayloadsAddIssue(r); err != nil {
			return nil, err
		}
	}
	return s.toPayloadsSorted(), nil
}

// toPayloadsAddIssue renders one Aderyn issue into a payload row.
func (s *toPayloadsState) toPayloadsAddIssue(r validation.Value) error {
	check := validation.ObjStr(r, "detector_name")
	if check == "" {
		return fmt.Errorf("aderyn: issue without 'detector_name' id")
	}
	desc := strings.TrimSpace(validation.ObjStr(r, "description"))
	if desc == "" {
		return nil
	}
	sites := toPayloadsSites(r)
	if len(sites) == 0 {
		return nil // a flag with no location cannot anchor; drop it
	}
	affected := toPayloadsAffected(sites)
	cls, ok := checkClasses[check]
	if !ok {
		cls = defaultClass
	}
	out := toPayloadsPayload(check, desc, cls, affected)
	s.rows = append(s.rows, toPayloadsRow{sites[0].path, sites[0].line, check, out})
	return nil
}

// toPayloadsSites collects an issue's anchorable instances, sorted by
// (path, line).
func toPayloadsSites(r validation.Value) []toPayloadsSite {
	var sites []toPayloadsSite
	for _, inst := range valsOf(validation.ObjAt(r, "instances")) {
		p := validation.ObjStr(inst, "contract_path")
		ln := validation.ObjAt(inst, "line_no")
		if p == "" || ln.Kind != validation.Int {
			continue // a location we cannot anchor is noise
		}
		sites = append(sites, toPayloadsSite{p, ln.I})
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].path != sites[j].path {
			return sites[i].path < sites[j].path
		}
		return sites[i].line < sites[j].line
	})
	return sites
}

// toPayloadsAffected renders the issue's affected-locations array.
func toPayloadsAffected(sites []toPayloadsSite) []validation.Value {
	affected := make([]validation.Value, 0, len(sites))
	for _, s := range sites {
		affected = append(affected, validation.VObj(
			kv("path", validation.VStr(s.path)),
			kv("lines", validation.VArr(
				validation.VInt(s.line), validation.VInt(s.line))),
			kv("entry_point", validation.VBool(false))))
	}
	return affected
}

// toPayloadsPayload renders the hypothesis payload object for one issue.
func toPayloadsPayload(check, desc, cls string,
	affected []validation.Value) validation.Value {
	title := "Aderyn " + check + ": " + firstLine(desc)
	if utf8.RuneCountInString(title) > 120 {
		title = string([]rune(title)[:117]) + "..."
	}
	return validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(cls)),
			kv("description", validation.VStr(clip(desc, 900))),
			kv("mechanism", validation.VStr("static pattern: aderyn/"+check)))),
		kv("affected", validation.VArr(affected...)),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("static analysis (Aderyn)")),
			kv("capabilities", validation.VArr()))),
		kv("evidence", validation.VArr()),
		kv("provenance", validation.VObj(
			kv("discovered_by", validation.VStr("sast/aderyn")),
			kv("sast_tools", validation.VArr(
				validation.VStr("aderyn:"+check))))),
	)
}

// toPayloadsSorted orders the rows by (path, line, check) and strips the
// sort keys.
func (s *toPayloadsState) toPayloadsSorted() []validation.Value {
	sort.SliceStable(s.rows, func(i, j int) bool {
		if s.rows[i].path != s.rows[j].path {
			return s.rows[i].path < s.rows[j].path
		}
		if s.rows[i].line != s.rows[j].line {
			return s.rows[i].line < s.rows[j].line
		}
		return s.rows[i].check < s.rows[j].check
	})
	out := make([]validation.Value, 0, len(s.rows))
	for _, r := range s.rows {
		out = append(out, r.out)
	}
	return out
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

// ---- local ordered-object helpers (duplicated on purpose: the datasets
// packages keep their own copy instead of sharing a helper package) ---------

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func valsOf(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}
