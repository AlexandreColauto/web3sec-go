package chainengine

import (
	"fmt"
	"slices"
	"sort"

	"websec/internal/validation"
)

// chainBlastRadius is the widest blast radius any member claims.
func chainBlastRadius(members []validation.Value) validation.Value {
	blast := ""
	for _, m := range members {
		b := validation.ObjStr(validation.ObjAt(m, "economic_impact"), "blast_radius")
		if b != "" && blastRank(b) >= 0 && (blast == "" ||
			blastRank(b) > blastRank(blast)) {
			blast = b
		}
	}
	if blast == "" {
		return validation.VObj()
	}
	return validation.VObj(kvOf("blast_radius", validation.VStr(blast)))
}

// livenessImpact is the B1 pricing of a chain that ends at a liveness
// terminal: economic_impact.kind = "liveness", the blast-radius FLOOR
// protocol-solvency (a frozen chain freezes every user's funds — the
// validated_risk weight table prices it 7.0; a member already claiming
// bridge-canonical keeps its 8.0), and the named non-USD decision
// (priceable: false + ceiling) — no USD figure for a freeze is defensible,
// and the E7 clause accepts false+ceiling in place of an artifact.
func livenessImpact(impact validation.Value) validation.Value {
	pairs := make([]validation.KV, 0, len(impact.O)+3)
	blast := ""
	for _, p := range impact.O {
		if p.K == "blast_radius" {
			blast = p.V.S
		}
		pairs = append(pairs, p)
	}
	if blastRank(blast) < blastRank("protocol-solvency") {
		if blast == "" {
			pairs = append(pairs, kvOf("blast_radius",
				validation.VStr("protocol-solvency")))
		} else {
			for i, p := range pairs {
				if p.K == "blast_radius" {
					pairs[i] = kvOf("blast_radius",
						validation.VStr("protocol-solvency"))
				}
			}
		}
	}
	pairs = append(pairs,
		kvOf("kind", validation.VStr("liveness")),
		kvOf("priceable", validation.VBool(false)),
		kvOf("ceiling", validation.VStr("liveness terminal: no USD figure is "+
			"defensible — a frozen chain freezes every user's funds; the "+
			"blast radius is the price")))
	return validation.VObj(pairs...)
}

// checkPins is the snapshot guard: exactly one distinct, non-null source pin.
func checkPins(pins []validation.Value) error {
	return checkPinsMode(pins, false)
}

// checkPinsMode is checkPins with the B3 switch. The shared-pin rule is a
// PROOF constraint: it exists so every member of a proven chain was verified
// against the same code. A hypothesis-level chain proves nothing, so the
// honest relaxation is "every member carries a source pin" — mixed pins
// (including the "unpinned" placeholder ingest writes when no snapshot was
// active yet) are legal, because a proposal is allowed to span the snapshots
// its members were filed against. A member with NO pin at all is still
// refused: that chain has no stated basis even as a lead.
func checkPinsMode(pins []validation.Value, unproven bool) error {
	distinct := map[string]struct{}{}
	hasNone := false
	for _, p := range pins {
		if p.Kind == validation.Null {
			hasNone = true
			continue
		}
		distinct[pyStr(p)] = struct{}{}
	}
	if !unproven {
		if len(distinct) > 1 || hasNone {
			shown := setKeys(distinct)
			if hasNone {
				shown = append(shown, "None")
				sort.Strings(shown)
			}
			return fmt.Errorf("chain members are pinned to different/missing "+
				"source snapshots (%s); re-verify onto one pin first",
				validation.PyListRepr(shown))
		}
		return nil
	}
	if hasNone {
		shown := setKeys(distinct)
		shown = append(shown, "None")
		sort.Strings(shown)
		return fmt.Errorf("chain members must each carry a source pin: "+
			"unpinned member(s) among %s — pin the finding, or start from "+
			"a snapshot, before proposing a hypothesis-level chain",
			validation.PyListRepr(shown))
	}
	// unproven: any non-null pin set is accepted (see the doc comment).
	return nil
}

// validateBreakdown enforces the known keys and the number >= 0 or null rule.
func validateBreakdown(bd validation.Value) error {
	unknown := []string{}
	for _, kv := range bd.O {
		if slices.Contains(CapitalFields, kv.K) || kv.K == "net_at_risk_usd" {
			continue
		}
		unknown = append(unknown, kv.K)
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("unknown capital_breakdown fields: %s", validation.PyListRepr(unknown))
	}
	for _, kv := range bd.O {
		v := kv.V
		if v.Kind == validation.Null {
			continue
		}
		if v.Kind == validation.Bool {
			return fmt.Errorf("capital_breakdown.%s must be a number >= 0 or null", kv.K)
		}
		f, ok := pyFloat(v)
		if !ok || f < 0 {
			return fmt.Errorf("capital_breakdown.%s must be a number >= 0 or null", kv.K)
		}
	}
	return nil
}
