// guard.go: the invariants 2.1 guardrail wired into findings through
// findings.SetInvariantGuard (webv2.findings._assert_invariants_verified and
// its _invariant_ids helper). It lives here because the verdict is the
// invariants registry's: the add_evidence half and the CONFIRMED gate half
// share this one function so the two can never disagree.
package invariants

import (
	"fmt"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// AssertInvariantsVerified is _assert_invariants_verified: a level rise on a
// finding whose invariants are not log-anchored verified is refused.
// Fail-closed — an unknown invariant id blocks, and any status other than
// log-anchored CHECKED_AGAINST_CODE blocks for non-documented invariants.
// Documented invariants (stored source or the LIVE documented set) are exempt.
func AssertInvariantsVerified(c *state.Campaign, finding validation.Value) error {
	links, err := LoadLinks(c)
	if err != nil {
		return err
	}
	norm := map[string]validation.Value{}
	for _, e := range regOf(links).O {
		if e.V.Kind == validation.Obj {
			norm[NormalizeInvID(e.K)] = e.V
		}
	}
	doc, err := DocumentedInvariants(c, nil)
	if err != nil {
		return err
	}
	events, err := c.Events()
	if err != nil {
		return err
	}
	var bad []string
	for _, iid := range invariantIDs(finding) {
		e, ok := norm[iid]
		if !ok {
			bad = append(bad, fmt.Sprintf("invariant-unverified: %s not in "+
				"registry — seed it or correct the id", iid))
			continue
		}
		if hasKey(doc, iid) || objStr(e, "source") == "documented" {
			continue
		}
		if !IsVerified(e, c, iid, events) {
			bad = append(bad, fmt.Sprintf("%s (%s)", iid,
				pyStr(objAt(e, "status"))))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("level rise blocked: invariant(s) %s are not "+
			"CHECKED_AGAINST_CODE — verify the statement against code "+
			"(invariants.verify_invariant_statement with a registered "+
			"artifact) before adding evidence that raises this finding's "+
			"level", strings.Join(bad, ", "))
	}
	return nil
}

// IsVerified is _is_verified: the single shared verdict. An invariant counts
// as verified only if its status is CHECKED_AGAINST_CODE, its verified_by
// resolves to a REGISTERED artifact, AND the append-only log carries an
// invariant.verified event for that id referencing that same artifact — a
// hand-edited registry entry cannot forge a hash-chained log event.
func IsVerified(entry validation.Value, c *state.Campaign, invariantID string,
	events []validation.Value) bool {
	if entry.Kind != validation.Obj {
		return false
	}
	if objStr(entry, "status") != "CHECKED_AGAINST_CODE" {
		return false
	}
	artID := objStr(entry, "verified_by")
	if artID == "" {
		return false
	}
	if _, err := c.Artifact(artID); err != nil {
		return false
	}
	want := NormalizeInvID(invariantID)
	for _, ev := range events {
		if objStr(ev, "type") != "invariant.verified" {
			continue
		}
		if NormalizeInvID(pyStr(objAt(ev, "ref"))) != want {
			continue
		}
		if objStr(objAt(ev, "data"), "artifact") == artID {
			return true
		}
	}
	return false
}

// invariantIDs is _invariant_ids: every invariant id a finding hangs off
// (singular + structured list), canonicalized and deduplicated in order.
func invariantIDs(finding validation.Value) []string {
	var ids []string
	if inv := objAt(finding, "invariant"); inv.Kind == validation.Obj {
		if id, ok := fieldAt(inv, "id"); ok && pyTruthy(id) {
			ids = append(ids, normalizeValue(id))
		}
	}
	sec := objAt(finding, "security_invariants")
	if sec.Kind != validation.Arr {
		return ids
	}
	for _, s := range sec.A {
		if s.Kind != validation.Obj {
			continue
		}
		id, ok := fieldAt(s, "id")
		if !ok || !pyTruthy(id) {
			continue
		}
		nid := normalizeValue(id)
		if nid == "" || inList(ids, nid) {
			continue
		}
		ids = append(ids, nid)
	}
	return ids
}

// normalizeValue is normalize_inv_id on a JSON value: strings normalize,
// anything else folds to its str() (Python returns the value unchanged and
// the f-string renders it the same way).
func normalizeValue(v validation.Value) string {
	if v.Kind == validation.Str {
		return NormalizeInvID(v.S)
	}
	return pyStr(v)
}
