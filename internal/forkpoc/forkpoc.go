// Package forkpoc ports webv2.fork_poc: the mainnet FORK PoC — the latest
// required step before the bounty gate.
//
// A unit harness (E4) proves the exploit's SEMANTICS; only a FORK run proves
// it where the money is. The proof is deterministic and read-only:
//
//   - the finding carries execution evidence at E5 (fork reality) or E6
//     (cross-chain independent);
//   - that evidence names the fork-runner sandbox profile;
//   - its artifact_id resolves to an EXEC record in the campaign ledger that
//     ran under fork-runner and SUCCEEDED (exit 0).
//
// The EXEC ledger is the source of truth: an evidence item that CLAIMS a fork
// profile without a matching ledger record is a lie the proof refuses.
package forkpoc

import (
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ForkProfile is FORK_PROFILE.
const ForkProfile = "fork-runner"

// ForkLevels is FORK_LEVELS (the Python tuple, used for membership).
var ForkLevels = []string{"E5", "E6"}

// --- seams for modules that are not ported yet (rule 5) --------------------
//
// onchain_sequence_required / verify_sequence_coverage live in sequence_poc
// (not this wave's ownership). Both defaults match Python on the data this
// module can see without it: a campaign whose active snapshot pins no fork
// target answers False (the pin FILE, not the state mirror, decides), and the
// coverage verifier is therefore unreachable. An installed implementation
// takes over for fork-targeted campaigns.

var onchainSequenceRequiredFunc = func(*state.Campaign, validation.Value) bool {
	return false
}

// SetOnchainSequenceRequired wires sequence_poc.onchain_sequence_required.
func SetOnchainSequenceRequired(f func(*state.Campaign, validation.Value) bool) {
	if f == nil {
		f = func(*state.Campaign, validation.Value) bool { return false }
	}
	onchainSequenceRequiredFunc = f
}

// verifySequenceCoverageFunc is sequence_poc.verify_sequence_coverage:
// (covered, reasons). The default is fail-closed: it is only consulted when a
// verifier-less build reports a fork-targeted multi-step finding.
var verifySequenceCoverageFunc = func(*state.Campaign, validation.Value,
	validation.Value) (bool, []string) {
	return false, []string{"sequence coverage verifier not wired"}
}

// SetVerifySequenceCoverage wires sequence_poc.verify_sequence_coverage.
func SetVerifySequenceCoverage(f func(*state.Campaign, validation.Value,
	validation.Value) (bool, []string)) {
	if f == nil {
		f = func(*state.Campaign, validation.Value,
			validation.Value) (bool, []string) {
			return false, []string{"sequence coverage verifier not wired"}
		}
	}
	verifySequenceCoverageFunc = f
}

// execLookup is _exec_lookup: exec_id -> record, from the ledger (the source
// of truth). Records without an exec_id are skipped.
func execLookup(campaign *state.Campaign) (map[string]validation.Value, error) {
	all, err := state.AllExecs(campaign)
	if err != nil {
		return nil, err
	}
	out := map[string]validation.Value{}
	for _, r := range all {
		if id := objStr(r, "exec_id"); id != "" {
			out[id] = r
		}
	}
	return out, nil
}

// isForkLevel is `level in FORK_LEVELS`.
func isForkLevel(level string) bool {
	for _, l := range ForkLevels {
		if l == level {
			return true
		}
	}
	return false
}

// exitIsZero is `rec.get("exit_status") != 0` negated, with Python's
// None/False semantics (None != 0 is True; False == 0 is True).
func exitIsZero(rec validation.Value) bool {
	v := objAt(rec, "exit_status")
	switch v.Kind {
	case validation.Int:
		return v.Big == "" && v.I == 0
	case validation.Flt:
		return v.F == 0
	case validation.Bool:
		return !v.B
	}
	return false
}

// ForkPocEvidence is fork_poc_evidence: (evidence_item, nil) when the
// finding's mainnet fork PoC is proven, else (Null, reason). The proof stays
// read-only; the caller loads the finding.
func ForkPocEvidence(campaign *state.Campaign,
	finding validation.Value) (validation.Value, *string, error) {
	execs, err := execLookup(campaign)
	if err != nil {
		return validation.VNull(), nil, err
	}
	var evidence []validation.Value
	if finding.Kind == validation.Obj {
		evidence = listAt(finding, "evidence")
	}
	candidates := []validation.Value{}
	for _, e := range evidence {
		if e.Kind != validation.Obj {
			continue
		}
		if !isForkLevel(objStr(e, "level")) {
			continue
		}
		candidates = append(candidates, e)
	}
	if len(candidates) == 0 {
		return validation.VNull(), reasonPtr("no fork-level evidence (E5/E6) — " +
			"run the PoC on the pinned mainnet fork (webv2 exec --profile " +
			"fork-runner) and mint it (webv2 mint --type fork-test)"), nil
	}
	for _, e := range candidates {
		if objStr(e, "sandbox_profile") != ForkProfile {
			continue
		}
		rec, ok := execs[objStr(e, "artifact_id")]
		if !ok {
			continue // claimed but not in the ledger: not proven
		}
		if objStr(rec, "profile") != ForkProfile {
			continue // the ledger disagrees with the claim: not proven
		}
		if !exitIsZero(rec) {
			continue // a fork run that did not succeed proves nothing
		}
		// On-chain-shaped requirement only: a multi-tx fork PoC must cover
		// the declared sequence, but that demand applies to campaigns with a
		// fork target (deployment/chain pin).
		if onchainSequenceRequiredFunc(campaign, finding) {
			ok, _ := verifySequenceCoverageFunc(campaign, finding, rec)
			if !ok {
				continue // a single-call PoC cannot prove a multi-step exploit
			}
		}
		return e, nil, nil
	}
	if onchainSequenceRequiredFunc(campaign, finding) {
		return validation.VNull(), reasonPtr("fork-level evidence exists but no " +
			"fork-runner exec has verified sequence coverage — run a T4 " +
			"sequence PoC (webv2 sequence run); a single-call fork PoC cannot " +
			"prove this multi-step exploit"), nil
	}
	return validation.VNull(), reasonPtr("evidence claims fork-level but no " +
		"E5/E6 item traces to a SUCCEEDED fork-runner exec in the ledger — " +
		"unit-harness evidence (E4) proves semantics, not mainnet"), nil
}

// ForkPocStatus is fork_poc_status: (proven, detail) for one finding id. A
// missing finding is an error (Python's FileNotFoundError).
func ForkPocStatus(campaign *state.Campaign,
	findingID string) (bool, string, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return false, "", err
	}
	item, reason, err := ForkPocEvidence(campaign, f)
	if err != nil {
		return false, "", err
	}
	if item.Kind != validation.Null {
		return true, "fork PoC proven: " + objStr(item, "level") +
			" fork-test from " + pyStrOr(objAt(item, "artifact_id")) +
			" (fork-runner, exit 0)", nil
	}
	if reason != nil && *reason != "" {
		return false, *reason, nil
	}
	return false, "no fork PoC proven", nil
}

// ForkPocGaps is fork_poc_gaps: one missing string per CONFIRMED (or CHAIN)
// finding whose mainnet fork PoC is not proven. Vacuously empty when no such
// finding exists.
func ForkPocGaps(campaign *state.Campaign) ([]string, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	gaps := []string{}
	for _, f := range all {
		status := objStr(f, "status")
		if status != "CONFIRMED" && status != "CHAIN" {
			continue
		}
		item, reason, err := ForkPocEvidence(campaign, f)
		if err != nil {
			return nil, err
		}
		if item.Kind == validation.Null {
			text := ""
			if reason != nil {
				text = *reason
			}
			gaps = append(gaps, objStr(f, "finding_id")+": "+text)
		}
	}
	return gaps, nil
}

// reasonPtr renders an f-string reason and returns its pointer.
func reasonPtr(s string) *string { return &s }

// objAt is the dict lookup: the value, or Null (Python's .get default).
func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// listAt is `v.get(key) or []` for list-shaped fields: a non-list reads as
// empty, exactly as Python's `(evidence or [])` iteration would.
func listAt(v validation.Value, key string) []validation.Value {
	if got := objAt(v, key); got.Kind == validation.Arr {
		return got.A
	}
	return nil
}

// objStr is the dict string lookup ("" when absent or not a string).
func objStr(v validation.Value, key string) string {
	if got := objAt(v, key); got.Kind == validation.Str {
		return got.S
	}
	return ""
}

// pyStrOr renders an f-string interpolation of a JSON scalar (the
// artifact_id slot, which Python prints with str()).
func pyStrOr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
}
