package briefing

import (
	"fmt"
	"sort"

	"websec/internal/chainengine"
	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

var confirmedStatuses = map[string]bool{"CONFIRMED": true, "CHAIN": true}

var junkStatuses = map[string]bool{
	"DUPLICATE": true, "OUT_OF_SCOPE": true, "INFORMATIONAL": true,
	"SUPERSEDED": true,
}

// Materializable is _materializable: proposals whose members are all
// confirmed and that are not yet materialized.
func Materializable(campaign *state.Campaign) ([]validation.Value, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	byID := map[string]validation.Value{}
	superIDs := map[string]bool{}
	for _, f := range all {
		byID[validation.ObjStr(f, "finding_id")] = f
		if validation.ObjStr(f, "status") == "CHAIN" {
			superIDs[validation.ObjStr(f, "finding_id")] = true
		}
	}
	memberSets := [][]string{}
	// r43a: an absent chains/ directory is a campaign with nothing
	// materialized; a chains/ directory that cannot be listed refuses — the
	// old `if dirExists(...)` guard read an unreadable store as "no chains".
	paths, err := validation.ListPrefixedOptional(campaign.ChainsDir,
		"CHAIN-", ".json")
	if err != nil {
		return nil, fmt.Errorf("the chain store %s cannot be listed: %v",
			campaign.ChainsDir, err)
	}
	sort.Strings(paths)
	for _, p := range paths {
		doc, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		memberSets = append(memberSets, strListOf(validation.ObjAt(doc, "members")))
	}
	props, err := chainengine.FindChains(campaign, 2)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, prop := range props {
		members := strListOf(validation.ObjAt(prop, "members"))
		skip := false
		for _, m := range members {
			if superIDs[m] {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		for _, ms := range memberSets {
			if len(ms) > 0 && subsetOf(ms, members) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		ok := true
		for _, m := range members {
			f, found := byID[m]
			if !found || !confirmedStatuses[validation.ObjStr(f, "status")] {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		out = append(out, validation.VObj(
			kv("members", validation.StrArr(members)),
			kv("capabilities", validation.ObjAt(prop, "capabilities")),
			kv("action", validation.VStr("materialize_chain("+
				validation.PyListRepr(members)+")"))))
	}
	return out, nil
}

// GateDeficits is _gate_deficits: findings alive but not confirmed, with the
// exact gate deficit standing between them and CONFIRMED, ordered by
// risk.work_order_key.
func GateDeficits(campaign *state.Campaign) ([]validation.Value, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	type pair struct {
		key risk.WorkOrderKey
		row validation.Value
	}
	rows := []pair{}
	for _, f := range all {
		st := validation.ObjStr(f, "status")
		if confirmedStatuses[st] || junkStatuses[st] {
			continue
		}
		deficit := findings.EvidenceDeficit(f, "CONFIRMED", campaign)
		if deficit == nil {
			continue
		}
		level, err := findings.FindingLevel(f)
		if err != nil {
			return nil, err
		}
		key, err := risk.WorkOrderKeyFor(f)
		if err != nil {
			return nil, err
		}
		rows = append(rows, pair{key, validation.VObj(
			kv("finding_id", validation.ObjAt(f, "finding_id")),
			kv("title", validation.ObjAt(f, "title")),
			kv("status", validation.ObjAt(f, "status")),
			kv("level", validation.VStr(level)),
			kv("deficit", validation.VStr(*deficit)))})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].key.Less(rows[j].key)
	})
	out := make([]validation.Value, len(rows))
	for i, r := range rows {
		out[i] = r.row
	}
	return out, nil
}

// Reachability is _reachability: live findings whose CONFIRMED floor is
// E5/E6 and structurally unreachable in this campaign.
func Reachability(campaign *state.Campaign) ([]validation.Value, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	type pair struct {
		key risk.WorkOrderKey
		row validation.Value
	}
	rows := []pair{}
	for _, f := range all {
		st := validation.ObjStr(f, "status")
		if junkStatuses[st] {
			continue
		}
		classVal := validation.ObjAt(validation.ObjAt(f, "root_cause"), "class")
		class := ""
		if classVal.Kind == validation.Str {
			class = classVal.S
		}
		floor := findings.RequiredLevelForCampaign(campaign, "CONFIRMED", class)
		floorIdx, err := findings.LevelIndex(floor)
		if err != nil {
			return nil, err
		}
		e5, _ := findings.LevelIndex("E5")
		if floorIdx < e5 {
			continue
		}
		level, err := findings.FindingLevel(f)
		if err != nil {
			return nil, err
		}
		levelIdx, err := findings.LevelIndex(level)
		if err != nil {
			return nil, err
		}
		if levelIdx >= floorIdx {
			continue
		}
		var bugClass *string
		if classVal.Kind == validation.Str {
			bugClass = &class
		}
		diag, err := findings.ReachabilityDiagnostic(campaign, floor, bugClass)
		if err != nil {
			return nil, err
		}
		if len(diag) == 0 {
			continue
		}
		key, err := risk.WorkOrderKeyFor(f)
		if err != nil {
			return nil, err
		}
		var classOut validation.Value
		if bugClass != nil {
			classOut = validation.VStr(*bugClass)
		} else {
			classOut = validation.VNull()
		}
		rows = append(rows, pair{key, validation.VObj(
			kv("finding_id", validation.ObjAt(f, "finding_id")),
			kv("title", validation.ObjAt(f, "title")),
			kv("status", validation.ObjAt(f, "status")),
			kv("bug_class", classOut),
			kv("floor", validation.VStr(floor)),
			kv("level", validation.VStr(level)),
			kv("missing", validation.StrArr(diag)))})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].key.Less(rows[j].key)
	})
	out := make([]validation.Value, len(rows))
	for i, r := range rows {
		out[i] = r.row
	}
	return out, nil
}

// MemoryRecallHints is _memory_recall_hints: findings one gate clause from
// CONFIRMED whose VERIFIED graph-memory recall is still missing.
func MemoryRecallHints(campaign *state.Campaign) ([]string, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	type pair struct {
		key risk.WorkOrderKey
		id  string
	}
	rows := []pair{}
	for _, f := range all {
		st := validation.ObjStr(f, "status")
		if st != "POSSIBLE" && st != "PROVISIONALLY_VALID" {
			continue
		}
		v := validation.AsObj(validation.ObjAt(f, "verification"))
		if validation.ObjStr(v, "critic_verdict") != "confirmed" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(v, "reproduction"), "status") != "reproduced" {
			continue
		}
		level, err := findings.FindingLevel(f)
		if err != nil {
			return nil, err
		}
		li, err := findings.LevelIndex(level)
		if err != nil {
			return nil, err
		}
		e4, _ := findings.LevelIndex("E4")
		if li < e4 {
			continue
		}
		id := validation.ObjStr(f, "finding_id")
		fail, err := findings.MemoryCheckFails(campaign, id)
		if err != nil {
			return nil, err
		}
		if fail == nil {
			continue
		}
		key, err := risk.WorkOrderKeyFor(f)
		if err != nil {
			return nil, err
		}
		rows = append(rows, pair{key, id})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key.Less(rows[j].key) })
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.id
	}
	return out, nil
}
