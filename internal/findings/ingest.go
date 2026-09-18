// ingest.go: ingest_hypothesis / add_evidence and the shared evidence gates
// (webv2.findings). The gate set lives in ONE place per concern so the
// ingest and add paths cannot drift apart — the same law as Python.
package findings

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- seams into modules that land later (taxonomy: Task 3; invariants:
// ---- Task 8). Defaults are the safe no-ops; the real implementations are
// ---- wired with Set* once the module exists.

// classAdvisoryFunc is the taxonomy.class_advisory seam: one-line advisory
// for ingest output/logs, or "" when the class is known and at the loosest
// floor. Nil bugClass is Python's None (the message text for unknown classes
// shows it as such); nil campaign asks with the built-in table (tests, and
// any caller that has no campaign) — a non-nil campaign makes the advisory
// floor-aware, so it can never contradict the campaign-aware line the CLI
// prints one line above it (critic I-2).
var classAdvisoryFunc = func(bugClass *string, campaign *state.Campaign) string {
	return ""
}

// SetClassAdvisory wires the real taxonomy.class_advisory (Task 3; the
// campaign parameter arrived with critic fix I-2).
func SetClassAdvisory(f func(bugClass *string, campaign *state.Campaign) string) {
	if f == nil {
		panic("findings: nil class advisory")
	}
	classAdvisoryFunc = f
}

// assertInvariantsVerified is the invariants 2.1 guardrail seam: a level
// rise on a finding hung off unverified invariants is refused.
var assertInvariantsVerified = func(*state.Campaign, validation.Value) error {
	return nil
}

// SetInvariantGuard wires the real invariants guardrail (Task 8).
func SetInvariantGuard(f func(*state.Campaign, validation.Value) error) {
	if f == nil {
		panic("findings: nil invariant guard")
	}
	assertInvariantsVerified = f
}

// IngestHypothesis is ingest_hypothesis: create a finding from a specialist
// pass. stage/model are "" for None (both are falsy in every Python use).
func IngestHypothesis(campaign *state.Campaign, payload validation.Value,
	trajectory, stage, model string) (validation.Value, error) {
	return ingestHypothesis(campaign, payload, trajectory, stage, model, false)
}

// LintHypothesis is `ingest --lint` (wave N, T4): ingest_hypothesis with the
// writes suppressed. It is the SAME call path — the same payload build, the
// same full-payload schema validation, the same exec_ref ledger checks, the
// same gate math (rise guardrail + discovery slot, budget refusal included) —
// so a lint run can never disagree with the real verb about what a payload
// means. The returned finding is the one a real ingest WOULD have written; the
// one write guard below keeps the campaign untouched.
func LintHypothesis(campaign *state.Campaign, payload validation.Value,
	trajectory, stage, model string) (validation.Value, error) {
	return ingestHypothesis(campaign, payload, trajectory, stage, model, true)
}

// ingestHypothesis runs the ingest pipeline in its documented order: build
// the HYPOTHESIS payload, validate and gate it (read-only), then — unless
// linting — write the finding, its event, and the intake scans.
func ingestHypothesis(campaign *state.Campaign, payload validation.Value,
	trajectory, stage, model string, lint bool) (validation.Value, error) {
	p, fid, rootClass := ingestBuildPayload(campaign, payload, trajectory, stage)
	gated, err := ingestValidateAndGate(campaign, p, fid, rootClass, lint)
	if err != nil {
		return validation.VNull(), err
	}
	// ---- the write guard (wave N, T4) ------------------------------------
	// Everything below TOUCHES the campaign: the finding file, the event log,
	// the ack/mitigation scan ledgers. `--lint` answers "would this payload be
	// accepted?" and must not answer "and now it is recorded", so the ONE
	// guard sits here — after the whole pipeline (schema, ledger, gate math)
	// has run, before the first write. The finding above is the one a real
	// ingest would write, which is what the caller prints.
	if lint {
		return gated, nil
	}
	return ingestWriteFinding(campaign, gated, fid, rootClass, trajectory,
		stage, model)
}

// ingestBuildPayload builds the HYPOTHESIS finding a payload ingests into:
// the minted id and timestamps, the snapshot pin, the default evidence/risk/
// dedup blocks, the opening history row, and the technical signature. It
// returns the payload, its finding id, and the resolved root bug class.
func ingestBuildPayload(campaign *state.Campaign, payload validation.Value,
	trajectory, stage string) (validation.Value, string, *string) {
	fid := NewFindingID()
	ts := state.NowIso()
	p := validation.Value{Kind: validation.Obj,
		O: append([]validation.KV(nil), payload.O...)}
	p.O = validation.SetOrAppend(p.O, "finding_id", validation.VStr(fid))
	p.O = validation.SetOrAppend(p.O, "campaign_id", validation.VStr(campaign.CampaignID))
	p.O = validation.SetOrAppend(p.O, "snapshot_ids", validation.VObj(
		validation.KV{K: "source", V: sourcePinOrUnpinned(campaign)},
		validation.KV{K: "deployment", V: validation.VNull()},
		validation.KV{K: "chain", V: validation.VNull()},
	))
	p.O = validation.SetOrAppend(p.O, "created_at", validation.VStr(ts))
	p.O = validation.SetOrAppend(p.O, "updated_at", validation.VStr(ts))
	p.O = validation.SetOrAppend(p.O, "status", validation.VStr("HYPOTHESIS"))
	p.O = validation.SetOrAppend(p.O, "trajectory", validation.VStr(trajectory))
	for _, k := range []string{"evidence", "risk", "dedup"} {
		if _, ok := fieldAt(p, k); !ok {
			if k == "evidence" {
				p.O = append(p.O, validation.KV{K: k, V: validation.VArr()})
			} else {
				p.O = append(p.O, validation.KV{K: k, V: validation.VObj()})
			}
		}
	}
	reason := "ingested from " + orDefault(stage, "unknown stage")
	actor := orDefault(stage, "ingest")
	p.O = validation.SetOrAppend(p.O, "history", validation.VArr(validation.VObj(
		validation.KV{K: "at", V: validation.VStr(ts)},
		validation.KV{K: "from", V: validation.VStr("NEW")},
		validation.KV{K: "to", V: validation.VStr("HYPOTHESIS")},
		validation.KV{K: "reason", V: validation.VStr(reason)},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	)))

	rootClassV, hasClass := fieldAt(validation.ObjAt(p, "root_cause"), "class")
	var rootClass *string
	if !hasClass {
		u := "unclassified"
		rootClass = &u
	} else if rootClassV.Kind == validation.Str {
		rootClass = &rootClassV.S
	}
	first := validation.VObj()
	if aff := validation.ObjAt(p, "affected"); aff.Kind == validation.Arr &&
		len(aff.A) > 0 {
		first = aff.A[0]
	}
	sig := TechnicalSignature(classSig(rootClass), sigPath(first),
		sigOpt(first, "function"), sigOpt(validation.ObjAt(p, "invariant"), "id"))
	dedup := validation.ObjAt(p, "dedup")
	dedup.O = validation.SetOrAppend(dedup.O, "technical_signature", validation.VStr(sig))
	p.O = validation.SetOrAppend(p.O, "dedup", dedup)
	return p, fid, rootClass
}

// ingestValidateAndGate is the read-only half of the ingest pipeline: schema
// validation, the affected-path discipline, the exec_ref ledger, the shared
// exec gate, the rise guardrail, and the discovery-slot charge. It returns
// the payload with the ledger-landed evidence items in place.
func ingestValidateAndGate(campaign *state.Campaign, p validation.Value,
	fid string, rootClass *string, lint bool) (validation.Value, error) {
	if err := validation.Validate(p, "finding", 5); err != nil {
		return validation.VNull(), err
	}
	// r6 (critic issue 6): affected.path is a claim ABOUT the pinned tree.
	// An absolute path or a ..-escaping one can name nothing inside a
	// snapshot and flows unflagged into report.md — refuse it at intake,
	// where the vocabulary is still the author's mistake, not the ledger's
	// lie. Schema keeps the shape rule out of RE2's no-lookahead reach.
	for i, aff := range validation.ObjAt(p, "affected").A {
		if v := validation.ObjAt(aff, "path"); v.Kind == validation.Str {
			if err := checkAffectedPath(i, v.S); err != nil {
				return validation.VNull(), err
			}
		}
	}
	// ---- ingest phase order (wave N, T2 ruling) ---------------------------
	// 1. SCHEMA: the WHOLE payload is validated above — before any ledger read
	//    or gate math — so a schema typo is never masked by a later refusal.
	// 2. LEDGER: an item carrying exec_ref must cite an EXEC this campaign's
	//    ledger holds, SUCCEEDED, and bound to this finding (or generic); the
	//    item then LANDS as the evidence mint would have minted from that exec
	//    (same gate, same shape — see exec_evidence.go).
	// 3. GATE MATH: the shared exec gate for items that did NOT come from
	//    exec_ref, then the rise guardrail and the discovery slot below.
	items := append([]validation.Value(nil), validation.ObjAt(p, "evidence").A...)
	fromExecRef := map[int]bool{}
	for i := range items {
		if validation.ObjStr(items[i], "exec_ref") == "" {
			continue
		}
		item, err := IngestExecRefEvidence(campaign, fid, p, items[i])
		if err != nil {
			return validation.VNull(), err
		}
		items[i] = item
		fromExecRef[i] = true
	}
	p.O = validation.SetOrAppend(p.O, "evidence", validation.VArr(items...))
	// Ingest-path gates (shared helpers with add_evidence): pre-loaded
	// EXECUTION evidence WITHOUT an exec_ref is rejected outright (the ledger
	// is the only door to E4+), and any pre-loaded items that rise above the
	// HYPOTHESIS baseline run the invariant guardrail. Items that arrived
	// through exec_ref were already gated by mint's own exec gate above.
	for i, item := range items {
		if fromExecRef[i] {
			continue
		}
		if err := checkExecGate(campaign, fid, item, true); err != nil {
			return validation.VNull(), err
		}
	}
	if len(items) > 0 {
		top, err := FindingLevel(p)
		if err != nil {
			return validation.VNull(), err
		}
		if err := enforceRiseGuardrail(campaign, p, top, "E0"); err != nil {
			return validation.VNull(), err
		}
		// A payload that arrives ALREADY above the E0 baseline is a rise: it
		// pays the discovery slot here, exactly as add_evidence would. A bare
		// hypothesis (E0, no evidence) pays nothing — suspicion is free.
		topIdx, err := LevelIndex(top)
		if err != nil {
			return validation.VNull(), err
		}
		if e0 := levelIndexValue("E0"); topIdx > e0 {
			if err := chargeSlot(campaign, &p, lint); err != nil {
				return validation.VNull(), err
			}
		}
	}
	return p, nil
}

// ingestWriteFinding is the write half of the ingest pipeline: the finding
// file and its finding.ingested event land together (unwind on a refused
// log), then the fail-open ack and mitigation scans, then the intake
// warnings event when there are warnings to record.
func ingestWriteFinding(campaign *state.Campaign, p validation.Value,
	fid string, rootClass *string, trajectory, stage, model string) (validation.Value, error) {
	// The finding is written AFTER any slot charge: the slot is a budget, and
	// a crash between the two writes must cost the operator a slot
	// (recoverable, visible) rather than hand out a free one.
	advisory := classAdvisoryFunc(rootClass, campaign)
	warnings := IntakeCheckpoint(p, trajectory, campaign.CampaignID, campaign)
	// r40b P2 sweep: the finding file without its finding.ingested event is
	// a live HYPOTHESIS the ledger never recorded — and the retry after the
	// heal ingests the payload AGAIN (two findings, one event, the dedup
	// mirror none the wiser). Unwind: on a refused log the pre-write state
	// is the file's absence, which restoreBytes puts back exactly.
	if err := SaveThenLog(campaign, &p, func() error {
		_, lerr := campaign.Log("finding.ingested", &fid,
			ingestLogData(trajectory, stage, model, rootClass, advisory,
				warnings))
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	// A2: scan the pinned source for in-code acknowledgements around the
	// finding's anchors, so the demotion flag is present from the moment the
	// finding is filed. Fail-open: a finding ingested against an unpinned or
	// missing source (or with no resolvable anchor) simply has no ack record.
	if _, err := RecordAckScan(campaign, fid); err != nil {
		// skipped — nothing to record
	}
	// G5: scan the pinned source for structural defenses covering the
	// flagged code, so the soundness flag is present from the moment the
	// finding is filed. Fail-open, same posture as the ack scan: a finding
	// ingested against an unpinned or missing source (or with no resolvable
	// anchor) simply has no mitigation record.
	if _, err := RecordMitigationScan(campaign, fid); err != nil {
		// skipped — nothing to record
	}
	if len(warnings) > 0 {
		if _, err := campaign.Log("finding.intake_warnings", &fid,
			warningsLogData(warnings)); err != nil {
			return validation.VNull(), err
		}
	}
	return p, nil
}
