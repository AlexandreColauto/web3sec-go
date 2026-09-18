// gate_reachability.go: the gate's structural-reachability half — the
// active snapshot's fork-target pin read, reachability_diagnostic, the
// invariant-id collection, and the tier helpers (webv2.findings).
package findings

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"websec/internal/state"
	"websec/internal/validation"
)

// activeForkTargetPin reads the ACTIVE snapshot's pin manifest — the same
// FILE sequencepoc reads for snapshot_has_fork_target, in the immutable tree,
// never the state mirror.
//
// The triple is (pin, present, err). present=false with err=nil is the FACT
// that there is no active snapshot or no pin manifest at all (ENOENT). Any
// other stat/read failure is a REFUSAL naming the path and the errno: a pin
// the tool could not read must never be folded into "no deployment/chain pin"
// (r45b — the r44 pinnedCompiler shape).
func activeForkTargetPin(campaign *state.Campaign) (validation.Value, bool, error) {
	sid, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), false, err
	}
	if sid == nil || *sid == "" {
		return validation.VNull(), false, nil
	}
	pinPath := filepath.Join(campaign.Dir, "snapshots", *sid, "snapshot.json")
	if st, serr := os.Stat(pinPath); serr != nil {
		if os.IsNotExist(serr) {
			return validation.VNull(), false, nil
		}
		return validation.VNull(), false, fmt.Errorf(
			"the active snapshot's pin manifest %s cannot be read: %v",
			pinPath, serr)
	} else if st.IsDir() {
		return validation.VNull(), false, fmt.Errorf(
			"the active snapshot's pin manifest %s is a directory", pinPath)
	}
	pin, rerr := validation.ReadJson(pinPath)
	if rerr != nil {
		return validation.VNull(), false, fmt.Errorf(
			"the active snapshot's pin manifest %s cannot be read: %v",
			pinPath, rerr)
	}
	return pin, true, nil
}

// ReachabilityDiagnostic is reachability_diagnostic: the structural
// prerequisites for reaching *minLevel* IN THIS CAMPAIGN. E5/E6 evidence is
// not a matter of effort but of infrastructure. bugClass nil is Python's
// None (conservative: every class is treated as cross-chain).
func ReachabilityDiagnostic(campaign *state.Campaign, minLevel string,
	bugClass *string) ([]string, error) {
	li, err := LevelIndex(minLevel)
	if err != nil {
		return nil, err
	}
	e5 := levelIndexValue("E5")
	if li < e5 {
		return []string{}, nil
	}
	missing := []string{}
	// the state mirror carries only the lean registry row (id/pass/pinned);
	// the pins themselves live in the snapshot FILE inside the immutable
	// tree — read the file, not the mirror.
	pin, present, err := activeForkTargetPin(campaign)
	if err != nil {
		return nil, err
	}
	hasDep, hasChain := false, false
	if present {
		hasDep = validation.PyTruthy(validation.ObjAt(pin, "deployment"))
		hasChain = validation.PyTruthy(validation.ObjAt(pin, "chain"))
	}
	if !(hasDep || hasChain) {
		missing = append(missing,
			"no deployment/chain pin on the active snapshot — fork evidence "+
				"(E5+) has no fork target, for single-call PoCs and multi-tx "+
				"sequence PoCs (`webv2 sequence run`) alike; pin one "+
				"(`webv2 snap`) or record a floor override (`webv2 floors set`)")
	}
	e6 := levelIndexValue("E6")
	if li >= e6 && !hasChain {
		// Class-aware: the cross-chain-witness requirement applies only to
		// classes whose E6 flavor IS a cross-chain witness. Campaign-level
		// calls (bug_class=None) keep the conservative warning.
		if bugClass == nil || inSet(CROSS_CHAIN_E6_CLASSES, *bugClass) {
			missing = append(missing, "no chain pin on the active snapshot — "+
				"cross-chain witnesses (E6) need one")
		}
	}
	if os.Getenv("FORK_RPC_URL") == "" {
		missing = append(missing, "FORK_RPC_URL is not set — the fork-runner "+
			"profile cannot reach a chain")
	}
	return missing, nil
}

// invariantIDs is _invariant_ids: every invariant id a finding hangs off
// (singular + structured list), in canonical form so zero-padded citations
// match the registry regardless of spelling.
func invariantIDs(finding validation.Value) []string {
	var ids []string
	if iid := validation.ObjAt(asDict(validation.ObjAt(finding, "invariant")), "id"); validation.PyTruthy(iid) &&
		iid.Kind == validation.Str {
		ids = append(ids, normalizeInvIDFunc(iid.S))
	}
	sec := validation.ObjAt(finding, "security_invariants")
	if !validation.PyTruthy(sec) || sec.Kind != validation.Arr {
		return ids
	}
	for _, s := range sec.A {
		if s.Kind != validation.Obj {
			continue
		}
		id := validation.ObjAt(s, "id")
		if !validation.PyTruthy(id) || id.Kind != validation.Str {
			continue
		}
		nid := normalizeInvIDFunc(id.S)
		if nid != "" && !slices.Contains(ids, nid) {
			ids = append(ids, nid)
		}
	}
	return ids
}

// bugClassPtr is _as_dict(...).get("class") as Python's None-vs-str: nil for
// an absent/null class, else the string.
func bugClassPtr(v validation.Value) *string {
	if v.Kind != validation.Str {
		return nil
	}
	s := v.S
	return &s
}

// tierBelowT3 is (tier not in TIER_ORDER or index(tier) < index("T3")).
func tierBelowT3(tier validation.Value, order []string) bool {
	if tier.Kind != validation.Str {
		return true
	}
	i, j := indexOfStr(order, tier.S), indexOfStr(order, "T3")
	if i < 0 {
		return true
	}
	return i < j
}

func indexOfStr(items []string, want string) int {
	for i, it := range items {
		if it == want {
			return i
		}
	}
	return -1
}
