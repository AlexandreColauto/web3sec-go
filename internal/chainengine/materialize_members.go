package chainengine

import (
	"fmt"
	"slices"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// loadChainMembers loads the members and enforces the two gates every
// materialization needs: each member CONFIRMED (or CHAIN), and every member
// pinned to the SAME source snapshot.
func loadChainMembers(c *state.Campaign,
	memberIDs []string) ([]validation.Value, error) {
	return loadChainMembersMode(c, memberIDs, false)
}

// loadChainMembersMode is loadChainMembers with the B3 switch: the
// unproven mode drops the status gate (a HYPOTHESIS .. POSSIBLE member is
// the whole point) and relaxes the pin gate to "one shared pin, or every
// member pinned to the active snapshot". The proven mode is unchanged.
func loadChainMembersMode(c *state.Campaign, memberIDs []string,
	unproven bool) ([]validation.Value, error) {
	members := make([]validation.Value, 0, len(memberIDs))
	for _, m := range memberIDs {
		f, err := findings.LoadFinding(c, m)
		if err != nil {
			return nil, err
		}
		members = append(members, f)
	}
	if !unproven {
		unconfirmed := []string{}
		for _, m := range members {
			switch validation.ObjStr(m, "status") {
			case "CONFIRMED", "CHAIN":
			default:
				unconfirmed = append(unconfirmed, validation.ObjStr(m, "finding_id"))
			}
		}
		if len(unconfirmed) > 0 {
			return nil, &findings.IllegalTransition{Msg: fmt.Sprintf(
				"chain members must each be CONFIRMED first: %s",
				validation.PyListRepr(unconfirmed))}
		}
	}
	pins := []validation.Value{}
	for _, m := range members {
		pins = append(pins, validation.ObjAt(validation.ObjAt(m, "snapshot_ids"), "source"))
	}
	if !unproven {
		if err := checkPins(pins); err != nil {
			return nil, err
		}
		return members, nil
	}
	if err := checkPinsMode(pins, true); err != nil {
		return nil, err
	}
	return members, nil
}

// terminalAnnotation validates the caller's terminal claim against the
// members, never trusting it.
func terminalAnnotation(c *state.Campaign, memberIDs []string,
	members []validation.Value, terminal *validation.Value) (*validation.Value, error) {
	if terminal == nil {
		return nil, nil
	}
	t := *terminal
	if t.Kind != validation.Obj || validation.ObjStr(t, "capability") == "" {
		return nil, fmt.Errorf("terminal annotation needs a 'capability'")
	}
	via := validation.ObjStr(t, "via_finding")
	if !validation.HasKey(t, "via_finding") || validation.ObjAt(t, "via_finding").Kind == validation.Null {
		via = validation.ObjStr(members[len(members)-1], "finding_id")
	}
	vf, err := findings.LoadFinding(c, via)
	if err != nil {
		return nil, err
	}
	granted := norm(capInput(validation.ObjAt(validation.AsObj(validation.ObjAt(vf, "capabilities")), "granted")))
	if !slices.Contains(granted, validation.ObjStr(t, "capability")) {
		return nil, fmt.Errorf(
			"terminal capability %s is not granted by %s (grants %s))",
			validation.PyReprStr(validation.ObjStr(t, "capability")), via,
			validation.PyListRepr(sortedStrings(granted)))
	}
	if !slices.Contains(memberIDs, via) {
		return nil, fmt.Errorf("terminal via_finding %s is not a chain member", via)
	}
	doc := validation.VObj(
		kvOf("capability", validation.VStr(validation.ObjStr(t, "capability"))),
		kvOf("via_finding", validation.VStr(via)),
		kvOf("total_capital_required_usd", validation.ObjAt(t, "total_capital_required_usd")),
	)
	if bd := validation.ObjAt(t, "capital_breakdown"); bd.Kind != validation.Null {
		if bd.Kind != validation.Obj {
			return nil, fmt.Errorf("capital_breakdown must be an object")
		}
		if err := validateBreakdown(bd); err != nil {
			return nil, err
		}
		doc.O = append(doc.O, kvOf("capital_breakdown", bd))
	}
	return &doc, nil
}
