// materialize.go: chain materialization (chain_engine.py's
// materialize_chain) — the HARD GATES that turn "medium individually,
// critical as a chain" into a first-class result.
package chainengine

import (
	"fmt"
	"sort"

	"websec/internal/capabilities"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// blastOrder is the shared blast-radius ladder (same order as the privileged
// track's BLAST_ORDER).
var blastOrder = []string{"single-user", "subset-of-users", "all-users",
	"protocol-solvency", "bridge-canonical"}

// blastRank is the ladder position, -1 for values outside it.
func blastRank(b string) int {
	for i, x := range blastOrder {
		if x == b {
			return i
		}
	}
	return -1
}

// MaterializeChain is materialize_chain(): create a CHAIN super-finding.
// A nil terminal skips the annotation; links is accepted for signature
// compatibility but never trusted (continuity is recomputed).
func MaterializeChain(c *state.Campaign, memberIDs []string, title, narrative string,
	links []validation.Value, terminal *validation.Value) (validation.Value, error) {
	if len(memberIDs) < 2 {
		return validation.VNull(), fmt.Errorf("a chain needs >= 2 members")
	}
	members, err := loadChainMembers(c, memberIDs)
	if err != nil {
		return validation.VNull(), err
	}
	computed, err := chainLinks(members)
	if err != nil {
		return validation.VNull(), err
	}

	floor, err := chainFloor(members)
	if err != nil {
		return validation.VNull(), err
	}
	chainID := "CHAIN-" + tailOf(state.NewID("x", 8))
	csig := ChainSignature(memberIDs)
	if err := chainDuplicate(c, csig); err != nil {
		return validation.VNull(), err
	}
	terminalDoc, err := terminalAnnotation(c, memberIDs, members, terminal)
	if err != nil {
		return validation.VNull(), err
	}
	economicImpact := chainBlastRadius(members)
	if terminalDoc != nil &&
		capabilities.IsLivenessTerminal(objStr(*terminalDoc, "capability")) {
		economicImpact = livenessImpact(economicImpact)
	}

	chainFinding, err := chainFindingDoc(c, memberIDs, members, title, narrative,
		chainID, csig, floor, computed, economicImpact, terminalDoc)
	if err != nil {
		return validation.VNull(), err
	}
	if err := findings.SaveFinding(c, &chainFinding); err != nil {
		return validation.VNull(), err
	}
	ref := chainID
	data := validation.VObj(
		kvOf("members", strArr(memberIDs)),
		kvOf("evidence_floor", validation.VStr(floor)),
		kvOf("super_finding", validation.VStr(objStr(chainFinding, "finding_id"))),
	)
	if _, err := c.Log("chain.materialized", &ref, &data); err != nil {
		return validation.VNull(), err
	}

	return writeChainDoc(chainDocInput{campaign: c, chainID: chainID,
		signature: csig, title: title, narrative: narrative,
		memberIDs: memberIDs, links: computed, floor: floor,
		terminal: terminalDoc})
}

// chainDuplicate is the idempotence guard: a chain over this exact member set
// may exist only once.
func chainDuplicate(c *state.Campaign, signature string) error {
	existing, err := chainDocs(c, false)
	if err != nil {
		return err
	}
	for _, ch := range existing {
		if objStr(ch, "chain_signature") == signature {
			return fmt.Errorf(
				"a chain over this member set already exists: %s",
				objStr(ch, "chain_id"))
		}
	}
	return nil
}

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
	terminal  *validation.Value
}

// writeChainDoc builds, validates and persists the CHAIN document.
func writeChainDoc(in chainDocInput) (validation.Value, error) {
	chainDoc := validation.VObj(
		kvOf("chain_id", validation.VStr(in.chainID)),
		kvOf("chain_signature", validation.VStr(in.signature)),
		kvOf("campaign_id", validation.VStr(in.campaign.CampaignID)),
		kvOf("title", validation.VStr(in.title)),
		kvOf("narrative", validation.VStr(in.narrative)),
		kvOf("members", strArr(in.memberIDs)),
		kvOf("capability_links", validation.VArr(in.links...)),
		kvOf("evidence_floor", validation.VStr(in.floor)),
		kvOf("status", validation.VStr("proposed")),
		kvOf("created_at", validation.VStr(nowIso())),
	)
	if in.terminal != nil {
		chainDoc.O = append(chainDoc.O, kvOf("terminal", *in.terminal))
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

// loadChainMembers loads the members and enforces the two gates every
// materialization needs: each member CONFIRMED (or CHAIN), and every member
// pinned to the SAME source snapshot.
func loadChainMembers(c *state.Campaign,
	memberIDs []string) ([]validation.Value, error) {
	members := make([]validation.Value, 0, len(memberIDs))
	for _, m := range memberIDs {
		f, err := findings.LoadFinding(c, m)
		if err != nil {
			return nil, err
		}
		members = append(members, f)
	}
	unconfirmed := []string{}
	for _, m := range members {
		switch objStr(m, "status") {
		case "CONFIRMED", "CHAIN":
		default:
			unconfirmed = append(unconfirmed, objStr(m, "finding_id"))
		}
	}
	if len(unconfirmed) > 0 {
		return nil, &findings.IllegalTransition{Msg: fmt.Sprintf(
			"chain members must each be CONFIRMED first: %s",
			pyListRepr(unconfirmed))}
	}
	pins := []validation.Value{}
	for _, m := range members {
		pins = append(pins, objAt(objAt(m, "snapshot_ids"), "source"))
	}
	if err := checkPins(pins); err != nil {
		return nil, err
	}
	return members, nil
}

// chainBlastRadius is the widest blast radius any member claims.
func chainBlastRadius(members []validation.Value) validation.Value {
	blast := ""
	for _, m := range members {
		b := objStr(objAt(m, "economic_impact"), "blast_radius")
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
	distinct := map[string]struct{}{}
	hasNone := false
	for _, p := range pins {
		if p.Kind == validation.Null {
			hasNone = true
			continue
		}
		distinct[pyStr(p)] = struct{}{}
	}
	if len(distinct) > 1 || hasNone {
		shown := setKeys(distinct)
		if hasNone {
			shown = append(shown, "None")
			sort.Strings(shown)
		}
		return fmt.Errorf("chain members are pinned to different/missing "+
			"source snapshots (%s); re-verify onto one pin first",
			pyListRepr(shown))
	}
	return nil
}

// chainLinks recomputes capability continuity from the members themselves.
func chainLinks(members []validation.Value) ([]validation.Value, error) {
	out := []validation.Value{}
	for i := 0; i+1 < len(members); i++ {
		a, b := members[i], members[i+1]
		aCaps := setOf(norm(capInput(objAt(asObj(objAt(a, "capabilities")), "granted"))))
		bNeeds := setOf(norm(capInput(objAt(asObj(objAt(b, "capabilities")), "required"))))
		overlap := []string{}
		for cap := range aCaps {
			if _, ok := bNeeds[cap]; ok {
				overlap = append(overlap, cap)
			}
		}
		if len(overlap) == 0 {
			return nil, fmt.Errorf("capability gap: %s -> %s (grants %s, needs %s)",
				objStr(a, "finding_id"), objStr(b, "finding_id"),
				pyListRepr(setKeys(aCaps)), pyListRepr(setKeys(bNeeds)))
		}
		sort.Strings(overlap)
		out = append(out, validation.VObj(
			kvOf("from_finding", validation.VStr(objStr(a, "finding_id"))),
			kvOf("granted", validation.VStr(overlap[0])),
			kvOf("to_finding", validation.VStr(objStr(b, "finding_id"))),
			kvOf("required", validation.VStr(overlap[0])),
		))
	}
	return out, nil
}

// chainFloor is the weakest member's best evidence level.
func chainFloor(members []validation.Value) (string, error) {
	floor := ""
	floorIdx := 0
	for _, m := range members {
		best, bestIdx := "E0", 0
		first := true
		for _, e := range listOf(m, "evidence").A {
			idx, err := findings.LevelIndex(objStr(e, "level"))
			if err != nil {
				return "", err
			}
			if first || idx > bestIdx {
				best, bestIdx, first = objStr(e, "level"), idx, false
			}
		}
		if floor == "" || bestIdx < floorIdx {
			floor, floorIdx = best, bestIdx
		}
	}
	return floor, nil
}

// terminalAnnotation validates the caller's terminal claim against the
// members, never trusting it.
func terminalAnnotation(c *state.Campaign, memberIDs []string,
	members []validation.Value, terminal *validation.Value) (*validation.Value, error) {
	if terminal == nil {
		return nil, nil
	}
	t := *terminal
	if t.Kind != validation.Obj || objStr(t, "capability") == "" {
		return nil, fmt.Errorf("terminal annotation needs a 'capability'")
	}
	via := objStr(t, "via_finding")
	if !hasKey(t, "via_finding") || objAt(t, "via_finding").Kind == validation.Null {
		via = objStr(members[len(members)-1], "finding_id")
	}
	vf, err := findings.LoadFinding(c, via)
	if err != nil {
		return nil, err
	}
	granted := norm(capInput(objAt(asObj(objAt(vf, "capabilities")), "granted")))
	if !containsStr(granted, objStr(t, "capability")) {
		return nil, fmt.Errorf(
			"terminal capability %s is not granted by %s (grants %s))",
			validation.PyReprStr(objStr(t, "capability")), via,
			pyListRepr(sortedStrings(granted)))
	}
	if !containsStr(memberIDs, via) {
		return nil, fmt.Errorf("terminal via_finding %s is not a chain member", via)
	}
	doc := validation.VObj(
		kvOf("capability", validation.VStr(objStr(t, "capability"))),
		kvOf("via_finding", validation.VStr(via)),
		kvOf("total_capital_required_usd", objAt(t, "total_capital_required_usd")),
	)
	if bd := objAt(t, "capital_breakdown"); bd.Kind != validation.Null {
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

// validateBreakdown enforces the known keys and the number >= 0 or null rule.
func validateBreakdown(bd validation.Value) error {
	unknown := []string{}
	for _, kv := range bd.O {
		if containsStr(CapitalFields, kv.K) || kv.K == "net_at_risk_usd" {
			continue
		}
		unknown = append(unknown, kv.K)
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("unknown capital_breakdown fields: %s", pyListRepr(unknown))
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
	if hasKey(first, "attacker") {
		attacker = objAt(first, "attacker")
	}
	dedupMeta := []validation.KV{
		kvOf("chain_id", validation.VStr(chainID)),
		kvOf("members", validation.VStr(pyJSONDump(strArr(memberIDs)))),
		kvOf("capability_links", validation.VStr(pyJSONDump(valueArr(computed)))),
		kvOf("evidence_floor", validation.VStr(floor)),
		kvOf("chain_signature", validation.VStr(csig)),
	}
	if terminalDoc != nil {
		dedupMeta = append(dedupMeta,
			kvOf("terminal", validation.VStr(pyJSONDump(*terminalDoc))))
	}
	reason := fmt.Sprintf("chain %s materialized from %s", chainID,
		pyListRepr(memberIDs))
	at := nowIso()
	return validation.VObj(
		kvOf("finding_id", validation.VStr("F-"+tailOf(state.NewID("x", 12)))),
		kvOf("campaign_id", validation.VStr(c.CampaignID)),
		kvOf("snapshot_ids", validation.VObj(
			kvOf("source", objAt(objAt(first, "snapshot_ids"), "source")))),
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
			kvOf("granted", strArr(granted)),
			kvOf("required", strArr(required)))),
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
