// cmd_verify_autoprove_helpers: the autoprove bind's
// shared value helpers and the ledger scans behind the holder,
// prior-digest and cite checks.
package cli

import (
	"fmt"
	"strings"

	"websec/internal/harness"
	"websec/internal/state"
	"websec/internal/validation"
)

func objKVs(o validation.Value) []validation.KV {
	if o.Kind == validation.Obj {
		return o.O
	}
	if o.Kind == validation.Arr {
		out := make([]validation.KV, 0, len(o.A))
		for _, v := range o.A {
			out = append(out, validation.KV{V: v})
		}
		return out
	}
	return nil
}

func intFrom(o validation.Value, key string) int {
	v := validation.ObjAt(o, key)
	switch v.Kind {
	case validation.Int:
		return int(v.I)
	case validation.Flt:
		return int(v.F)
	}
	return 0
}

func joinOrDash(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, "; ")
}

func joinHead(xs []string, n int) string {
	if len(xs) == 0 {
		return "none attributed"
	}
	if len(xs) > n {
		return strings.Join(xs[:n], ", ") + fmt.Sprintf(" (+%d more)",
			len(xs)-n)
	}
	return strings.Join(xs, ", ")
}

// orUnset rendered the schema gate's ABSENT state. r33 F3 moved the gate —
// sentence, state name and schema family — into harness (DecideReportSchema,
// harness.ReportSchemaMajor), so the default it applied lives there now and
// this verb holds no second copy of the wording.

// autoproveEventData is the harness_run payload for report-bound
// rungs: the shared four fields plus the report's own provenance
// (property title, sha256 of the bytes mapped, whether the review was
// independent at run time).
func autoproveEventData(invID, rung, exec, summary, property,
	digest string, bk validation.Value,
	rep validation.Value) validation.Value {
	return validation.VObj(
		validation.KV{K: "kind",
			V: validation.VStr(string(harness.Kind("miniprover")))},
		validation.KV{K: "rung", V: validation.VStr(rung)},
		validation.KV{K: "exec", V: validation.VStr(exec)},
		validation.KV{K: "invariant", V: validation.VStr(invID)},
		validation.KV{K: "summary", V: validation.VStr(summary)},
		validation.KV{K: "bounded_k", V: bk},
		// r23 F1: no proof sidecar on this path — the digest of ABSENCE
		// pins that fact so any slot-invented subtree burns the backstop.
		validation.KV{K: "proof_sha256",
			V: validation.VStr(harnessProofDigest(validation.VNull()))},
		validation.KV{K: "property", V: validation.VStr(property)},
		validation.KV{K: "report_sha256", V: validation.VStr(digest)},
		validation.KV{K: "review_independent",
			V: validation.VBool(t26Truthy(rep, "review_independent"))},
	)
}

// autoprovePropertyHolder scans harness_run events for a report+property
// pair already bound to some invariant. Returns (invariant, exec) of the
// FIRST binding (a re-bind of the same pair to the same invariant is a
// refresh, allowed; to a DIFFERENT invariant it is double credit).
func autoprovePropertyHolder(c *state.Campaign, property string) (string, string) {
	events, err := c.Events()
	if err != nil {
		// Unreadable ledger: the CALLER parses nothing silently either —
		// but refusing on a torn events file would block every bind; the
		// verify verb itself fails on the torn log BEFORE this point in
		// practice, and audit burns it. Return no-holder and let the
		// binding event itself become the second record.
		return "", ""
	}
	for _, e := range events {
		if validation.ObjStr(e, "type") != "harness_run" {
			continue
		}
		d := validation.ObjAt(e, "data")
		if !autoproveSameName(validation.ObjStr(d, "property"), property) {
			continue
		}
		if inv := validation.ObjStr(d, "invariant"); inv != "" {
			return inv, validation.ObjStr(d, "exec")
		}
	}
	return "", ""
}

// autoprovePriorDigest: report_sha256 of the last miniprover bind of
// this invariant ("" if none) — the re-bind disclosure's baseline.
func autoprovePriorDigest(c *state.Campaign, invID string) string {
	events, err := c.Events()
	if err != nil {
		return ""
	}
	last := ""
	for _, e := range events {
		if validation.ObjStr(e, "type") != "harness_run" {
			continue
		}
		d := validation.ObjAt(e, "data")
		if validation.ObjStr(d, "invariant") == invID &&
			validation.ObjStr(d, "report_sha256") != "" {
			last = validation.ObjStr(d, "report_sha256")
		}
	}
	return last
}

// autoproveSameName: property titles are AGENT-authored strings — the
// same verbatim-slop class r21 F2 fixed for verdicts. Attribution and
// consumption fold case + edges (display keeps the first spelling;
// identity is the folded form, so "P1" cannot launder a second bind
// nor dodge a suspect flag).
//
// r33 F2: the fold itself is harness.SamePropertyName — ONE implementation
// for the bind's holder scan, the SUSPECT gate and section 11's
// duplicate-attribution rail, which must collide on exactly the pairs this
// scan collides on. This is the cli's spelling of that function.
func autoproveSameName(a, b string) bool {
	return harness.SamePropertyName(a, b)
}

// artifactCitedByLiveBinds: does any live evidence still name this registry
// row? The implementation is state.ArtifactCitedByLiveBinds — the ONE cite
// predicate (r35 F1), which answers BOTH shapes: the row's sha256 as a bind
// pinned it (a harness_run event's report_sha256, or an exec record the event
// names hashing it in input_hashes/artifact_hashes — N1's EXEC rungs) AND the
// row's own id where an event or a registry field names it (a
// harness_scaffold event's ref, a verified_by link, a finding's artifact_id).
// This helper is the cli's spelling of that same decision so the bind's
// guard, the ghost-prune and the prune verb's warning cannot disagree.
func artifactCitedByLiveBinds(c *state.Campaign, id string) (bool,
	error) {
	cited, _, err := state.ArtifactCitedByLiveBinds(c, id)
	return cited, err
}

// harnessRowForPath: the registry row currently holding this path
// (resolved the registry's own way), if any.
func harnessRowForPath(c *state.Campaign, path string) (validation.Value,
	bool) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), false
	}
	want := state.ResolveArtifactPathFor(c, path)
	for _, arow := range validation.ObjAt(st, "artifacts").A {
		if state.ResolveArtifactPathFor(c, validation.ObjStr(arow, "path")) == want {
			return arow, true
		}
	}
	return validation.VNull(), false
}
