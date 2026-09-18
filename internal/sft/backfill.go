package sft

// backfill.go ports backfill_finding (Task D): deterministic draft
// reconstruction from a campaign's trajectory and a stored finding. No model
// calls; read-only on the campaign. The result is a DRAFT — it never touches
// the store; the CLI writes it to a file for the curator to complete, then
// `webv2 sft add` promotes it.
//
// The user turn is the proposer bundle AS SENT: the backfilled finding is
// excluded from existing_findings (it did not exist at request time, and its
// title in the input would leak the answer). Trajectory refs are
// [response_seq, request_seq] (reverse-chronological).

import (
	"strings"

	"websec/internal/boundary"
	"websec/internal/findings"
	"websec/internal/roles"
	"websec/internal/state"
	"websec/internal/trajectory"
	"websec/internal/validation"
)

// backfillStatusMap is _BACKFILL_STATUS_MAP: finding assumption status ->
// trace resolution status.
var backfillStatusMap = map[string]string{"SUPPORTED": "CONFIRMED",
	"REFUTED": "REFUTED"}

// BackfillFinding is backfill_finding.
func BackfillFinding(campaign *state.Campaign,
	findingID string) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	system, err := proposerPromptText()
	if err != nil {
		return validation.VNull(), err
	}
	bundle, err := roles.BuildProposerContext(campaign, nil)
	if err != nil {
		return validation.VNull(), err
	}
	bundle = setKey(bundle, "existing_findings",
		withoutFinding(validation.ObjAt(bundle, "existing_findings"), findingID))
	ch := boundary.ContextHash(bundle)

	traj, err := trajectory.ModelTrajectory(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	prov, refs, recordedHash := backfillProvenance(traj, findingID, ch)
	structured := backfillStructured(f)
	trace := backfillTrace(structured)
	return validation.VObj(
		validation.KV{K: "source", V: validation.VObj(
			validation.KV{K: "kind", V: validation.VStr("backfill")},
			validation.KV{K: "ref", V: validation.VStr(findingID)},
			validation.KV{K: "cluster", V: validation.VStr(findingID)})},
		validation.KV{K: "taxonomy", V: validation.VNull()},
		validation.KV{K: "status", V: validation.VStr("draft")},
		validation.KV{K: "rejection_reasons", V: validation.VArr()},
		validation.KV{K: "partition", V: validation.VNull()},
		validation.KV{K: "messages", V: validation.VArr(
			validation.VObj(
				validation.KV{K: "role", V: validation.VStr("system")},
				validation.KV{K: "content", V: validation.VStr(system)}),
			validation.VObj(
				validation.KV{K: "role", V: validation.VStr("user")},
				validation.KV{K: "content",
					V: validation.VStr(validation.DumpIndented(bundle))}),
			validation.VObj(
				validation.KV{K: "role", V: validation.VStr("assistant")},
				validation.KV{K: "content", V: validation.VStr(trace)}))},
		validation.KV{K: "structured", V: structured},
		validation.KV{K: "provenance", V: validation.VObj(
			validation.KV{K: "bundle_provenance", V: validation.VStr(prov)},
			validation.KV{K: "context_hash", V: recordedHash},
			validation.KV{K: "trajectory_refs", V: validation.StrArr(refs)})},
		validation.KV{K: "created_at", V: validation.VStr(state.NowIso())}), nil
}

// withoutFinding drops the backfilled finding from the sent bundle's
// existing_findings (selective exclusion, not a wipe).
func withoutFinding(list validation.Value, findingID string) validation.Value {
	out := []validation.Value{}
	if list.Kind == validation.Arr {
		for _, s := range list.A {
			if validation.ObjStr(s, "finding_id") != findingID {
				out = append(out, s)
			}
		}
	}
	return validation.VArr(out...)
}

// backfillProvenance pairs the finding's proposer response with the request
// that produced it, and proves the bundle hash when the request recorded one.
func backfillProvenance(traj []validation.Value, findingID,
	ch string) (string, []string, validation.Value) {
	responses := []validation.Value{}
	for _, e := range traj {
		data := validation.ObjAt(e, "data")
		if validation.ObjStr(e, "type") != "model.response" || validation.ObjStr(e, "ref") != findingID ||
			validation.ObjStr(data, "role") != "proposer" ||
			validation.ObjStr(data, "response_schema") != "hypothesis" {
			continue
		}
		responses = append(responses, e)
	}
	prov := "hand-written"
	refs := []string{}
	recorded := validation.VNull()
	if len(responses) == 0 {
		return prov, refs, recorded
	}
	rsp := maxBySeq(responses)
	refs = append(refs, pyStrValue(validation.ObjAt(rsp, "seq")))
	reqs := []validation.Value{}
	for _, e := range traj {
		data := validation.ObjAt(e, "data")
		if validation.ObjStr(e, "type") == "model.request" &&
			validation.ObjStr(data, "role") == "proposer" &&
			intOf(validation.ObjAt(e, "seq")) < intOf(validation.ObjAt(rsp, "seq")) {
			reqs = append(reqs, e)
		}
	}
	if len(reqs) == 0 {
		return prov, refs, recorded
	}
	req := maxBySeq(reqs)
	refs = append(refs, pyStrValue(validation.ObjAt(req, "seq")))
	got := objStrDefault(validation.ObjAt(req, "data"), "context_hash", "")
	if got == ch {
		prov = "hash-verified"
		recorded = validation.VStr(ch)
	} else {
		prov = "reconstructed"
	}
	return prov, refs, recorded
}

func maxBySeq(items []validation.Value) validation.Value {
	best := items[0]
	for _, e := range items[1:] {
		if intOf(validation.ObjAt(e, "seq")) > intOf(validation.ObjAt(best, "seq")) {
			best = e
		}
	}
	return best
}

// backfillStructured is the structured pre-fill: the finding's root cause,
// assumptions (with the status translation), invariants (head first, deduped)
// and impact, plus the TODO skeleton fields.
func backfillStructured(f validation.Value) validation.Value {
	rc := validation.ObjAt(f, "root_cause")
	econ := validation.ObjAt(f, "economic_impact")
	headInv := validation.ObjAt(f, "invariant")
	assumptions := []validation.Value{}
	if list := validation.ObjAt(f, "assumptions"); list.Kind == validation.Arr {
		for _, a := range list.A {
			if a.Kind != validation.Obj {
				continue
			}
			fstatus := "OPEN"
			if s, ok := backfillStatusMap[validation.ObjStr(a, "status")]; ok {
				fstatus = s
			}
			evidence := []validation.Value{}
			if fstatus == "CONFIRMED" {
				evidence = arrOf(validation.ObjAt(a, "support"))
			} else if fstatus == "REFUTED" {
				evidence = arrOf(validation.ObjAt(a, "contradictions"))
			}
			reason := "TODO: state the resolving evidence from the trajectory"
			if len(evidence) > 0 {
				bits := []string{}
				for _, x := range evidence[:minInt(3, len(evidence))] {
					bits = append(bits, pyStrValue(x))
				}
				reason = "evidence: " + strings.Join(bits, "; ")
			}
			assumptions = append(assumptions, validation.VObj(
				validation.KV{K: "id", V: validation.VStr(
					getDefaultStr(a, "id", "A?"))},
				validation.KV{K: "text", V: validation.VStr(
					getDefaultStr(a, "claim", ""))},
				validation.KV{K: "status", V: validation.VStr(fstatus)},
				validation.KV{K: "reason", V: validation.VStr(reason)}))
		}
	}
	invariants := []validation.Value{}
	addInv := func(statement string) {
		for _, i := range invariants {
			if validation.ObjStr(i, "statement") == statement {
				return
			}
		}
		invariants = append(invariants, validation.VObj(
			validation.KV{K: "statement", V: validation.VStr(statement)},
			validation.KV{K: "status", V: validation.VStr("UNCHECKED")},
			validation.KV{K: "depends_on", V: validation.VArr()}))
	}
	if validation.ObjStr(headInv, "statement") != "" {
		addInv(validation.ObjStr(headInv, "statement"))
	}
	if list := validation.ObjAt(f, "security_invariants"); list.Kind == validation.Arr {
		for _, inv := range list.A {
			if inv.Kind == validation.Obj && validation.ObjStr(inv, "statement") != "" {
				addInv(validation.ObjStr(inv, "statement"))
			}
		}
	}
	impactBits := []string{strings.TrimSpace(validation.ObjStr(econ, "asset"))}
	if loss := validation.ObjAt(econ, "max_loss_usd"); loss.Kind != validation.Null {
		impactBits = append(impactBits, "$"+pyNumText(loss)+" max loss")
	}
	expected := []string{}
	for _, b := range impactBits {
		if b != "" {
			expected = append(expected, b)
		}
	}
	expectedImpact := strings.Join(expected, " ")
	if expectedImpact == "" {
		expectedImpact = "TODO: state the concrete asset/actor/magnitude"
	}
	claim := strings.TrimSpace(validation.ObjStr(f, "title"))
	if len(claim) < 10 {
		claim = firstNonEmpty(validation.ObjStr(rc, "description"),
			validation.ObjStr(headInv, "statement"), claim)
	}
	return validation.VObj(
		validation.KV{K: "bug_class", V: validation.VStr(
			objStrDefault(rc, "class", "TODO-bug-class"))},
		validation.KV{K: "claim", V: validation.VStr(claim)},
		validation.KV{K: "assumptions", V: validation.VArr(assumptions...)},
		validation.KV{K: "invariants", V: validation.VArr(invariants...)},
		validation.KV{K: "expected_impact", V: validation.VStr(expectedImpact)},
		validation.KV{K: "next_test", V: validation.VStr("")},
		validation.KV{K: "pivot_count", V: validation.VInt(0)})
}

// clipRunes is Python's `s[:n]` for a string: a CHARACTER slice, so a
// multi-byte rune straddling the budget must not shorten the line relative
// to the reference (backfill_trace uses `a['text'][:60]`).
func clipRunes(s string, n int) string {
	if runes := []rune(s); len(runes) > n {
		return string(runes[:n])
	}
	return s
}

// backfillTrace is the assistant trace skeleton: the arc markers, the
// assumption lines translated from the finding, and the structured JSON block.
func backfillTrace(structured validation.Value) string {
	aLines := []string{}
	if list := validation.ObjAt(structured, "assumptions"); list.Kind == validation.Arr {
		for _, a := range list.A {
			text := clipRunes(getDefaultStr(a, "text", ""), 60)
			aLines = append(aLines, getDefaultStr(a, "id", "A?")+" ("+text+
				"): -> "+validation.ObjStr(a, "status")+". "+validation.ObjStr(a, "reason"))
		}
	}
	if len(aLines) == 0 {
		aLines = []string{"A1 (TODO: first checkable proposition): -> TODO. evidence"}
	}
	lines := []string{
		"OBSERVATION:",
		"TODO: what looked unusual, with the concrete code reference.",
		"",
		"INITIAL FRAMING:",
		"TODO: the first bug-class hypothesis, stated as a hypothesis.",
		"",
	}
	lines = append(lines, aLines...)
	lines = append(lines,
		"",
		"INVARIANT:",
		"TODO: the specific property violated, precise enough to check "+
			"against code.",
		"",
		"IMPACT:",
		"TODO: concrete asset/actor/magnitude. Finding pre-fill: "+
			validation.ObjStr(structured, "expected_impact"),
		"",
		"```json",
		validation.DumpIndentedASCII(structured),
		"```")
	return strings.Join(lines, "\n")
}

func arrOf(v validation.Value) []validation.Value {
	if v.Kind == validation.Arr {
		return v.A
	}
	return nil
}

func getDefaultStr(v validation.Value, key, def string) string {
	if !validation.HasKey(v, key) {
		return def
	}
	return pyStrValue(validation.ObjAt(v, key))
}

func firstNonEmpty(items ...string) string {
	for _, s := range items {
		if s != "" {
			return s
		}
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
