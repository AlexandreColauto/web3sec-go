// Package audit is the Campaign integrity audit (Task 13). Six P0
// sections (event_log, artifacts, execs, findings, projection,
// snapshots) check the framework's trust claims; every section lists
// concrete problems so a non-zero CLI exit is always explainable.
//
// Port of src/webv2/audit.py sections 1-6, message-for-message. The
// section registry runs in registration order = Python's code order
// (event_log first); the Plan's "deterministic name order" is the
// registration order the section files init in, which is part of the
// report contract (the P1 gate goldens pin it).
package audit

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"websec/internal/audit/sections"
	"websec/internal/state"
	"websec/internal/validation"
)

// Section is one named audit section: a value with checked/problems/ok
// (the event_log section carries the verify_log keys events/ok/problems/
// chained/legacy_unchained/malformed_lines instead). Section values are
// opaque here; consumers (AuditCampaign, AuditSummaryLine) read only the
// keys they need.
type Section = validation.Value

// SectionFunc produces one section from a campaign. It is the sections
// package's SectionFunc (the single definition, since the sections
// package cannot import audit but audit can import sections).
type SectionFunc = sections.SectionFunc

// registry maps section name -> producer, in registration order.
var (
	registry = map[string]SectionFunc{}
	order    []string
)

// Setup registers the six P0 sections (Python code order) exactly once.
// It is the single entry the CLI (and tests) call before AuditCampaign.
// sections does not import audit (which would be an audit<->sections
// import cycle); it reports back into this registry through
// RegisterAuditSection.
func Setup() {
	if setupDone {
		return
	}
	sections.RegisterAll(func(name string, fn sections.SectionFunc) {
		RegisterAuditSection(name, fn)
	})
	setupDone = true
}

var setupDone bool

// RegisterAuditSection registers a named section producer. Registration
// order is the report's section key order (Python code order).
func RegisterAuditSection(name string, fn SectionFunc) {
	if _, dup := registry[name]; dup {
		panic("audit: duplicate section " + name)
	}
	registry[name] = fn
	order = append(order, name)
}

// SectionNames lists the registered section names in report (registration)
// order. The Audited registry lists exactly the six P0 names.
func SectionNames() []string {
	out := make([]string, len(order))
	copy(out, order)
	return out
}

// AuditCampaign is audit_campaign: run every registered section and build
// {campaign_id, sections: {name: section}, ok}. Overall ok = all sections.
// A presence-gated section that returns sections.ErrSkip is omitted from
// the report (absent by construction — campaigns without an eval link
// keep byte-identical output); any other error fails the audit.
func AuditCampaign(c *state.Campaign) (validation.Value, error) {
	secs := make([]validation.KV, 0, len(order))
	ok := true
	for _, name := range order {
		sec, err := registry[name](c)
		if err != nil {
			if errors.Is(err, sections.ErrSkip) {
				continue
			}
			return validation.VNull(), err
		}
		if !sectionOK(sec) {
			ok = false
		}
		secs = append(secs, validation.KV{K: name, V: sec})
	}
	return validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "sections", V: validation.VObj(secs...)},
		validation.KV{K: "ok", V: validation.VBool(ok)},
	), nil
}

// sectionOK reports a section's ok flag (True only when the section is a
// proper object with ok=true; a missing section is "not ok", safe).
func sectionOK(sec validation.Value) bool {
	return sec.Kind == validation.Obj &&
		objAt(sec, "ok").Kind == validation.Bool &&
		objAt(sec, "ok").B
}

// AuditSummaryLine is audit_summary_line: "audit {PASS|FAIL}: {name}={n}
// problem(s), ..." over the report sections in report order.
func AuditSummaryLine(report validation.Value) string {
	ok := objAt(report, "ok").Kind == validation.Bool && objAt(report, "ok").B
	verdict := "FAIL"
	if ok {
		verdict = "PASS"
	}
	parts := []string{}
	sections := objAt(report, "sections")
	for _, kv := range sections.O {
		n := 0
		probs := objAt(kv.V, "problems")
		if probs.Kind == validation.Arr {
			n = len(probs.A)
		}
		parts = append(parts, kv.K+"="+strconv.Itoa(n)+" problem(s)")
	}
	return "audit " + verdict + ": " + strings.Join(parts, ", ")
}

// objAt is the object field lookup for validation.Value (Null when
// absent/non-object). Audit is its own package; state's objAt is private.
func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// objStr is the string field lookup ("" when absent/non-string).
func objStr(v validation.Value, key string) string {
	for _, kv := range v.O {
		if kv.K == key && kv.V.Kind == validation.Str {
			return kv.V.S
		}
	}
	return ""
}

// sortStrs sorts and returns a copy (Python sorted()).
func sortStrs(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// sortedKeys returns the sorted string keys of a set (Python sorted(set)).
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
