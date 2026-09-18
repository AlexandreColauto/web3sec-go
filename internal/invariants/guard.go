// guard.go: the invariants 2.1 guardrail wired into findings through
// findings.SetInvariantGuard (webv2.findings._assert_invariants_verified and
// its _invariant_ids helper). It lives here because the verdict is the
// invariants registry's: the add_evidence half and the CONFIRMED gate half
// share this one function so the two can never disagree.
package invariants

import (
	"fmt"
	"slices"
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
		if validation.HasKey(doc, iid) || validation.ObjStr(e, "source") == "documented" {
			continue
		}
		if !IsVerified(e, c, iid, events) {
			bad = append(bad, fmt.Sprintf("%s (%s)", iid,
				validation.PyStr(validation.ObjAt(e, "status"))))
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
// as verified if it carries a CONFIRMING verdict backed by the append-only
// log — a hand-edited registry entry cannot forge a hash-chained log event:
//
//   - CHECKED_AGAINST_CODE: verified_by resolves to a REGISTERED artifact and
//     the log carries an invariant.verified event for that id referencing that
//     same artifact.
//   - CONTRADICTED (B3): the invariant is FALSIFIED by code — the attack
//     works — the strongest confirming outcome. Its contradiction anchor is
//     non-empty (and, when it is a registered artifact id, resolves), and the
//     log carries an invariant.contradicted event for that id referencing that
//     same anchor. Previously only CHECKED_AGAINST_CODE was accepted, which
//     gated out the very evidence that the exploit works.
func IsVerified(entry validation.Value, c *state.Campaign, invariantID string,
	events []validation.Value) bool {
	if entry.Kind != validation.Obj {
		return false
	}
	switch validation.ObjStr(entry, "status") {
	case "CONTRADICTED":
		evid := validation.ObjStr(entry, "contradiction")
		if evid == "" {
			return false
		}
		if isArtifactID(evid) {
			if _, err := c.Artifact(evid); err != nil {
				return false
			}
		}
		want := NormalizeInvID(invariantID)
		for _, ev := range events {
			if validation.ObjStr(ev, "type") != "invariant.contradicted" {
				continue
			}
			if NormalizeInvID(validation.PyStr(validation.ObjAt(ev, "ref"))) != want {
				continue
			}
			if validation.ObjStr(validation.ObjAt(ev, "data"), "evidence") == evid {
				return true
			}
		}
		return false
	case "CHECKED_AGAINST_CODE":
		artID := validation.ObjStr(entry, "verified_by")
		if artID == "" {
			return false
		}
		if _, err := c.Artifact(artID); err != nil {
			return false
		}
		want := NormalizeInvID(invariantID)
		for _, ev := range events {
			if validation.ObjStr(ev, "type") != "invariant.verified" {
				continue
			}
			if NormalizeInvID(validation.PyStr(validation.ObjAt(ev, "ref"))) != want {
				continue
			}
			if validation.ObjStr(validation.ObjAt(ev, "data"), "artifact") == artID {
				return true
			}
		}
		return false
	}
	return false
}

// isArtifactID reports whether s matches the registered-artifact id shape
// <KIND3UPPER>-<8 lowercase hex> (state.newId + RegisterArtifact). A file
// anchor such as "src/Vault.sol:42" never matches, so a CONTRADICTED entry
// anchored to source text is accepted as written.
func isArtifactID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := 0; i < 3; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	if s[3] != '-' {
		return false
	}
	for i := 4; i < 12; i++ {
		ch := s[i]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

// invariantIDs is _invariant_ids: every invariant id a finding hangs off
// (singular + structured list), canonicalized and deduplicated in order.
func invariantIDs(finding validation.Value) []string {
	var ids []string
	if inv := validation.ObjAt(finding, "invariant"); inv.Kind == validation.Obj {
		if id, ok := fieldAt(inv, "id"); ok && validation.PyTruthy(id) {
			ids = append(ids, normalizeValue(id))
		}
	}
	sec := validation.ObjAt(finding, "security_invariants")
	if sec.Kind != validation.Arr {
		return ids
	}
	for _, s := range sec.A {
		if s.Kind != validation.Obj {
			continue
		}
		id, ok := fieldAt(s, "id")
		if !ok || !validation.PyTruthy(id) {
			continue
		}
		nid := normalizeValue(id)
		if nid == "" || slices.Contains(ids, nid) {
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
	return validation.PyStr(v)
}
