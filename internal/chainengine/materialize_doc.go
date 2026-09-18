package chainengine

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// chainDocInput is the chain-document writer's arguments.
type chainDocInput struct {
	campaign  *state.Campaign
	chainID   string
	signature string
	title     string
	narrative string
	memberIDs []string
	links     []validation.Value
	floor     string
	// provenance is "unproven" for a hypothesis-level chain (B3); empty
	// means the doc carries no provenance key at all, so every chain
	// materialized before B3 keeps its exact bytes (the schema's implied
	// default is "proven").
	provenance string
	terminal   *validation.Value
}

// writeChainDoc builds, validates and persists the CHAIN document.
func writeChainDoc(in chainDocInput) (validation.Value, error) {
	chainDoc := validation.VObj(
		kvOf("chain_id", validation.VStr(in.chainID)),
		kvOf("chain_signature", validation.VStr(in.signature)),
		kvOf("campaign_id", validation.VStr(in.campaign.CampaignID)),
		kvOf("title", validation.VStr(in.title)),
		kvOf("narrative", validation.VStr(in.narrative)),
		kvOf("members", validation.StrArr(in.memberIDs)),
		kvOf("capability_links", validation.VArr(in.links...)),
		kvOf("evidence_floor", validation.VStr(in.floor)),
		kvOf("status", validation.VStr("proposed")),
		kvOf("created_at", validation.VStr(state.NowIso())),
	)
	if in.terminal != nil {
		chainDoc.O = append(chainDoc.O, kvOf("terminal", *in.terminal))
	}
	// B3: only present for an unproven chain (see chainDocInput.provenance).
	if in.provenance != "" {
		chainDoc.O = append(chainDoc.O,
			kvOf("provenance", validation.VStr(in.provenance)))
	}
	if err := validation.Validate(chainDoc, "chain", 1); err != nil {
		return validation.VNull(), err
	}
	if err := validation.WriteJson(chainPath(in.campaign, in.chainID), chainDoc,
		"chain"); err != nil {
		return validation.VNull(), err
	}
	return chainDoc, nil
}

// chainCapabilities is the union of every member's granted/required
// capabilities, sorted.
func chainCapabilities(members []validation.Value) ([]string, []string) {
	gset, rset := map[string]struct{}{}, map[string]struct{}{}
	for _, m := range members {
		g, r := capBlock(m)
		for _, x := range g {
			gset[x] = struct{}{}
		}
		for _, x := range r {
			rset[x] = struct{}{}
		}
	}
	return setKeys(gset), setKeys(rset)
}

// chainFindingDoc builds the CHAIN super-finding in Python's key order.
func chainFindingDoc(c *state.Campaign, memberIDs []string, members []validation.Value,
	title, narrative, chainID, csig, floor string, computed []validation.Value,
	economicImpact validation.Value, terminalDoc *validation.Value) (validation.Value, error) {
	first := members[0]
	granted, required := chainCapabilities(members)
	affected := []validation.Value{}
	if a := listOf(first, "affected"); len(a.A) > 0 {
		affected = a.A[:1]
	}
	attacker := validation.VObj(
		kvOf("profile", validation.VStr("arbitrary EOA")),
		kvOf("capabilities", validation.VArr()))
	if validation.HasKey(first, "attacker") {
		attacker = validation.ObjAt(first, "attacker")
	}
	dedupMeta := []validation.KV{
		kvOf("chain_id", validation.VStr(chainID)),
		kvOf("members", validation.VStr(validation.CanonSpaced(validation.StrArr(memberIDs)))),
		kvOf("capability_links", validation.VStr(validation.CanonSpaced(valueArr(computed)))),
		kvOf("evidence_floor", validation.VStr(floor)),
		kvOf("chain_signature", validation.VStr(csig)),
	}
	if terminalDoc != nil {
		dedupMeta = append(dedupMeta,
			kvOf("terminal", validation.VStr(validation.CanonSpaced(*terminalDoc))))
	}
	reason := fmt.Sprintf("chain %s materialized from %s", chainID,
		validation.PyListRepr(memberIDs))
	at := state.NowIso()
	return validation.VObj(
		kvOf("finding_id", validation.VStr("F-"+tailOf(state.NewID("x", 12)))),
		kvOf("campaign_id", validation.VStr(c.CampaignID)),
		kvOf("snapshot_ids", validation.VObj(
			kvOf("source", validation.ObjAt(validation.ObjAt(first, "snapshot_ids"), "source")))),
		kvOf("title", validation.VStr(title)),
		kvOf("status", validation.VStr("CHAIN")),
		kvOf("trajectory", validation.VStr("chain")),
		kvOf("root_cause", validation.VObj(
			kvOf("class", validation.VStr("exploit-chain")),
			kvOf("description", validation.VStr(narrativeOrDefault(narrative))))),
		kvOf("affected", validation.VArr(affected...)),
		kvOf("attacker", attacker),
		kvOf("evidence", validation.VArr()),
		kvOf("risk", validation.VObj()),
		kvOf("dedup", validation.VObj()),
		kvOf("capabilities", validation.VObj(
			kvOf("granted", validation.StrArr(granted)),
			kvOf("required", validation.StrArr(required)))),
		kvOf("economic_impact", economicImpact),
		kvOf("dedup_meta", validation.VObj(dedupMeta...)),
		kvOf("history", validation.VArr(validation.VObj(
			kvOf("at", validation.VStr(at)),
			kvOf("from", validation.VStr("NEW")),
			kvOf("to", validation.VStr("CHAIN")),
			kvOf("reason", validation.VStr(reason)),
			kvOf("actor", validation.VStr("chain_engine"))))),
		kvOf("created_at", validation.VStr(at)),
		kvOf("updated_at", validation.VStr(at)),
	), nil
}

// narrativeOrDefault is `narrative or "composed exploit chain"`.
func narrativeOrDefault(narrative string) string {
	if narrative != "" {
		return narrative
	}
	return "composed exploit chain"
}

// tailOf is `new_id(...).split("-")[1]`.
func tailOf(id string) string {
	for i := 0; i < len(id); i++ {
		if id[i] == '-' {
			return id[i+1:]
		}
	}
	return id
}
