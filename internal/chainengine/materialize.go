// materialize.go: chain materialization (chain_engine.py's
// materialize_chain) — the HARD GATES that turn "medium individually,
// critical as a chain" into a first-class result.
package chainengine

import (
	"fmt"

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
