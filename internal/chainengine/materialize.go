// materialize.go: chain materialization (chain_engine.py's
// materialize_chain) — the HARD GATES that turn "medium individually,
// critical as a chain" into a first-class result.
package chainengine

import (
	"fmt"
	"slices"
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

// MaterializeOpts are the B3 switches. The zero value is the original
// CONFIRMED-only materialization, byte-for-byte.
type MaterializeOpts struct {
	// Unproven materializes a HYPOTHESIS-LEVEL chain: members may sit at
	// any status, the shared-pin gate relaxes to "every member carries a
	// source pin" (mixed pins are legal — see checkPinsMode), every link
	// carries its member's evidence level, the chain doc is stamped
	// provenance "unproven", the event is chain.materialized_unproven, and
	// NO super-finding is created. An unproven chain is a document, never a
	// finding, so no CONFIRMED/CHAIN consumer (submission table, gate,
	// counting, audit) can mistake it for an evidence-confirmed result.
	Unproven bool
}

// MaterializeChain is materialize_chain(): create a CHAIN super-finding.
// A nil terminal skips the annotation; links is accepted for signature
// compatibility but never trusted (continuity is recomputed).
func MaterializeChain(c *state.Campaign, memberIDs []string, title, narrative string,
	links []validation.Value, terminal *validation.Value) (validation.Value, error) {
	return MaterializeChainOpts(c, memberIDs, title, narrative, links, terminal,
		MaterializeOpts{})
}

// MaterializeChainOpts is MaterializeChain with the B3 switches (see
// MaterializeOpts). Only the unproven branch differs; the proven branch is
// the original code path, unchanged.
func MaterializeChainOpts(c *state.Campaign, memberIDs []string, title, narrative string,
	links []validation.Value, terminal *validation.Value,
	opts MaterializeOpts) (validation.Value, error) {
	if len(memberIDs) < 2 {
		return validation.VNull(), fmt.Errorf("a chain needs >= 2 members")
	}
	members, err := loadChainMembersMode(c, memberIDs, opts.Unproven)
	if err != nil {
		return validation.VNull(), err
	}
	computed, err := chainLinksMode(members, opts.Unproven)
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
	// B3: an unproven chain derives its terminal from the hypothesis-mode
	// terminal search (B1's includeHypothesis seam) when the caller names
	// none, so a HYPOTHESIS liveness finding can still price its liveness
	// terminal. The derivation only *offers* an annotation — terminalAnnotation
	// still verifies the capability against the via_finding.
	if opts.Unproven && terminal == nil {
		terminal = derivedTerminal(c, memberIDs)
	}
	terminalDoc, err := terminalAnnotation(c, memberIDs, members, terminal)
	if err != nil {
		return validation.VNull(), err
	}

	provenance, superID := "", ""
	if opts.Unproven {
		// No finding, hence no priceable artifact: the terminal the doc
		// names is a LEAD's destination, and the report states that the
		// liveness price (blast-radius floor, no USD figure) is NOT
		// asserted for a hypothesis-level chain. Creating a CHAIN-status
		// super-finding here would make the lead indistinguishable from a
		// confirmed result in every downstream consumer (the submission
		// count, the bounty gate re-run in report generation, the terminal
		// search), which is exactly what "unproven" must prevent.
		provenance = "unproven"
	} else {
		economicImpact := chainBlastRadius(members)
		if terminalDoc != nil &&
			capabilities.IsLivenessTerminal(validation.ObjStr(*terminalDoc, "capability")) {
			economicImpact = livenessImpact(economicImpact)
		}
		chainFinding, err := chainFindingDoc(c, memberIDs, members, title,
			narrative, chainID, csig, floor, computed, economicImpact,
			terminalDoc)
		if err != nil {
			return validation.VNull(), err
		}
		if err := findings.SaveFinding(c, &chainFinding); err != nil {
			return validation.VNull(), err
		}
		superID = validation.ObjStr(chainFinding, "finding_id")
	}
	ref := chainID
	data := validation.VObj(
		kvOf("members", validation.StrArr(memberIDs)),
		kvOf("evidence_floor", validation.VStr(floor)),
	)
	if provenance != "" {
		data.O = append(data.O, kvOf("provenance", validation.VStr(provenance)))
	}
	if superID != "" {
		data.O = append(data.O, kvOf("super_finding", validation.VStr(superID)))
	}
	event := "chain.materialized"
	if opts.Unproven {
		event = "chain.materialized_unproven"
	}
	if _, err := c.Log(event, &ref, &data); err != nil {
		return validation.VNull(), err
	}

	return writeChainDoc(chainDocInput{campaign: c, chainID: chainID,
		signature: csig, title: title, narrative: narrative,
		memberIDs: memberIDs, links: computed, floor: floor,
		terminal: terminalDoc, provenance: provenance})
}

// maxDeriveDepth is the B3 terminal-search depth (the terminal report's
// working depth).
const maxDeriveDepth = 5

// derivedTerminal is the B3 terminal derivation: the hypothesis-mode
// terminal search is asked for reachable terminal paths, and a path whose
// member set is exactly this chain's members becomes the terminal
// annotation. No match (or a search error) means no annotation — the chain
// still materializes, just unpriced. The search's own proposal cap applies,
// so a campaign with hundreds of competing paths may miss a match; that
// degrades to "unpriced", never to a wrong price.
func derivedTerminal(c *state.Campaign, memberIDs []string) *validation.Value {
	paths, err := FindTerminalChainsMode(c, nil, maxDeriveDepth,
		len(memberIDs), true)
	if err != nil {
		return nil
	}
	want := setOf(memberIDs)
	for _, p := range paths {
		path := strList(validation.ObjAt(p, "path"))
		if len(path) != len(want) {
			continue
		}
		got := setOf(path)
		if len(got) != len(want) {
			continue
		}
		if !subsetOf(got, want) {
			continue
		}
		term := validation.ObjStr(p, "terminal_finding")
		if term == "" {
			continue
		}
		doc := validation.VObj(
			kvOf("capability", validation.VStr(validation.ObjStr(p, "terminal_capability"))),
			kvOf("via_finding", validation.VStr(term)),
			kvOf("total_capital_required_usd",
				validation.ObjAt(p, "total_capital_required_usd")),
		)
		return &doc
	}
	return nil
}

// chainDuplicate is the idempotence guard: a chain over this exact member set
// may exist only once.
func chainDuplicate(c *state.Campaign, signature string) error {
	existing, err := chainDocs(c, false)
	if err != nil {
		return err
	}
	for _, ch := range existing {
		if validation.ObjStr(ch, "chain_signature") == signature {
			return fmt.Errorf(
				"a chain over this member set already exists: %s",
				validation.ObjStr(ch, "chain_id"))
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

// chainLinks recomputes capability continuity from the members themselves.
func chainLinks(members []validation.Value) ([]validation.Value, error) {
	return chainLinksMode(members, false)
}

// chainLinksMode is chainLinks with the B3 switch: an unproven chain stamps
// every link with its FROM member's own best evidence level, so a reader (and
// the report) can see how thin each hop of a hypothesis-level chain is.
func chainLinksMode(members []validation.Value,
	unproven bool) ([]validation.Value, error) {
	out := []validation.Value{}
	for i := 0; i+1 < len(members); i++ {
		a, b := members[i], members[i+1]
		aCaps := setOf(norm(capInput(validation.ObjAt(validation.AsObj(validation.ObjAt(a, "capabilities")), "granted"))))
		bNeeds := setOf(norm(capInput(validation.ObjAt(validation.AsObj(validation.ObjAt(b, "capabilities")), "required"))))
		overlap := []string{}
		for cap := range aCaps {
			if _, ok := bNeeds[cap]; ok {
				overlap = append(overlap, cap)
			}
		}
		if len(overlap) == 0 {
			return nil, fmt.Errorf("capability gap: %s -> %s (grants %s, needs %s)",
				validation.ObjStr(a, "finding_id"), validation.ObjStr(b, "finding_id"),
				validation.PyListRepr(setKeys(aCaps)), validation.PyListRepr(setKeys(bNeeds)))
		}
		sort.Strings(overlap)
		link := validation.VObj(
			kvOf("from_finding", validation.VStr(validation.ObjStr(a, "finding_id"))),
			kvOf("granted", validation.VStr(overlap[0])),
			kvOf("to_finding", validation.VStr(validation.ObjStr(b, "finding_id"))),
			kvOf("required", validation.VStr(overlap[0])),
		)
		if unproven {
			link.O = append(link.O, kvOf("link_evidence",
				validation.VStr(bestEvidenceLevel(a))))
		}
		out = append(out, link)
	}
	return out, nil
}

// bestEvidenceLevel is a member's strongest evidence item, "E0" when it has
// none (a HYPOTHESIS member with no evidence yet). An unknown level is
// skipped rather than fatal: this is a rendering aid, not a gate.
func bestEvidenceLevel(m validation.Value) string {
	best, bestIdx := "E0", 0
	for _, e := range listOf(m, "evidence").A {
		idx, err := findings.LevelIndex(validation.ObjStr(e, "level"))
		if err != nil {
			continue
		}
		if idx > bestIdx {
			best, bestIdx = validation.ObjStr(e, "level"), idx
		}
	}
	return best
}

// chainFloor is the weakest member's best evidence level.
func chainFloor(members []validation.Value) (string, error) {
	floor := ""
	floorIdx := 0
	for _, m := range members {
		best, bestIdx := "E0", 0
		first := true
		for _, e := range listOf(m, "evidence").A {
			idx, err := findings.LevelIndex(validation.ObjStr(e, "level"))
			if err != nil {
				return "", err
			}
			if first || idx > bestIdx {
				best, bestIdx, first = validation.ObjStr(e, "level"), idx, false
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
