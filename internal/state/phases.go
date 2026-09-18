package state

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"websec/internal/validation"
)

// Phases is PHASES: the 19 campaign phase names in exact order.
var Phases = []string{
	"SCOPE", "SNAPSHOT", "STRUCTURAL_INDEX", "PROTOCOL_INTELLIGENCE",
	"CAMPAIGN_PLANNING", "DISCOVERY", "CANDIDATE_INTEL", "HOSTILE_REVIEW",
	"REPRODUCTION", "CHAINING", "MAXIMAL_EXPLOITATION",
	"INDEPENDENT_VERIFICATION", "RISK_CALIBRATION", "MAINNET_FORK_POC",
	"BOUNTY_GATE", "REPORTING", "LEARNING", "HALTED", "COMPLETE",
}

func phaseKnown(phase string) bool {
	for _, p := range Phases {
		if p == phase {
			return true
		}
	}
	return false
}

// SetPhase is set_phase: same phase is a no-op; a transition appends a
// history entry, saves, and logs phase.transition.
func (c *Campaign) SetPhase(phase, reason string) error {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	prevRaw, hadRaw := c.rawState() // r16 unwind law
	if !phaseKnown(phase) {
		return fmt.Errorf("unknown phase %s", validation.PyReprStr(phase))
	}
	st, err := c.State()
	if err != nil {
		return err
	}
	prev := validation.ObjStr(st, "phase")
	if prev == phase {
		return nil
	}
	st.O = validation.SetOrAppend(st.O, "phase", validation.VStr(phase))
	hist := validation.ObjAt(st, "phase_history")
	hist.A = append(hist.A, validation.VObj(
		kv("at", validation.VStr(nowIso())),
		kv("from", validation.VStr(prev)),
		kv("to", validation.VStr(phase)),
		kv("reason", validation.VStr(reason)),
	))
	st.O = validation.SetOrAppend(st.O, "phase_history", hist)
	if err := c.save(st); err != nil {
		return err
	}
	data := validation.VObj(
		kv("from", validation.VStr(prev)),
		kv("reason", validation.VStr(reason)),
	)
	if _, lerr := c.Log("phase.transition", &phase, &data); lerr != nil {
		// r16: the ledger refused — UNWIND the state
		// write (PinSnapshot's r9 discipline,
		// generalized): a decision the log never
		// recorded must not live in the projection.
		if uerr := c.unwindState(prevRaw, hadRaw); uerr != nil {
			return lerr
		}
		return lerr
	}
	return nil
}

// Halt is halt: record the reason, then move to HALTED.
func (c *Campaign) Halt(reason string) error {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	prevRaw, hadRaw := c.rawState() // r16 unwind law
	st, err := c.State()
	if err != nil {
		return err
	}
	st.O = validation.SetOrAppend(st.O, "halt_reason", validation.VStr(reason))
	if err := c.save(st); err != nil {
		return err
	}
	if err := c.SetPhase("HALTED", reason); err != nil {
		// r16: SetPhase unwinds ITS save; ours (halt_reason with no
		// event) needs its own unwind — back to the pre-Halt bytes.
		if uerr := c.unwindState(prevRaw, hadRaw); uerr != nil {
			return err
		}
		return err
	}
	return nil
}

// Complete is complete: the sanctioned way to close a pass — an operator
// decision recorded with a named actor and a written reason. The
// decision is on the hash-chained log (campaign.completed) and mirrored
// in the projection (completed_by / completed_reason). The phase is a
// PROJECTION: a later stage run moves it on its own; the closure event
// stays on the log as the record of the decision.
//
// Deviation: Python's str.strip() uses the Unicode White_Space set and Go's
// strings.TrimSpace uses unicode.IsSpace; the two differ on a few control
// codepoints (U+00A0 is stripped by BOTH, which is why r38 found the ledger
// blank-line predicates disagreeing — see blankLine/BlankLine in eventlog.go,
// now the one predicate every JSONL reader uses). Operator-typed
// actor/reason is unaffected.
func (c *Campaign) Complete(actor, reason string) (validation.Value, error) {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer c.UnlockProcess()
	prevRaw, hadRaw := c.rawState() // r16 unwind law
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if actor == "" {
		return validation.VNull(), fmt.Errorf("complete requires a named actor")
	}
	if utf8.RuneCountInString(reason) < 10 {
		return validation.VNull(), fmt.Errorf(
			"complete requires a written reason (>= 10 chars): what was closed and why the pass is done")
	}
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	// setOrAppend (not append): a re-Complete must replace, not duplicate,
	// the keys — duplicate keys corrupt the projection.
	st.O = validation.SetOrAppend(st.O, "completed_by", validation.VStr(actor))
	st.O = validation.SetOrAppend(st.O, "completed_reason", validation.VStr(reason))
	if err := c.save(st); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("actor", validation.VStr(actor)),
		kv("reason", validation.VStr(reason)),
	)
	if _, lerr := c.Log("campaign.completed", &c.CampaignID, &data); lerr != nil {
		// r16: the ledger refused — UNWIND the state
		// write (PinSnapshot's r9 discipline,
		// generalized): a decision the log never
		// recorded must not live in the projection.
		if uerr := c.unwindState(prevRaw, hadRaw); uerr != nil {
			return validation.VNull(), lerr
		}
		return validation.VNull(), lerr
	}
	if err := c.SetPhase("COMPLETE", actor+": "+reason); err != nil {
		return validation.VNull(), err
	}
	return c.State()
}

// Budget is budget: state()["budget"].
func (c *Campaign) Budget() (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	return validation.ObjAt(st, "budget"), nil
}

// ConsumeDiscoverySlot is consume_discovery_slot: increment the counter.
func (c *Campaign) ConsumeDiscoverySlot() error {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	st, err := c.State()
	if err != nil {
		return err
	}
	b := validation.ObjAt(st, "budget")
	v := validation.ObjAt(b, "discovery_findings_so_far")
	b.O = validation.SetOrAppend(b.O, "discovery_findings_so_far", validation.VInt(v.I+1))
	st.O = validation.SetOrAppend(st.O, "budget", b)
	return c.save(st)
}

// SetCostCeiling is set_cost_ceiling: set (or clear, with nil) the
// operator's total-cost ceiling budget.max_total_cost_usd. The ceiling
// is a decision: actor-attributed and log-chained — the pipeline halts
// when recorded spend crosses it.
func (c *Campaign) SetCostCeiling(ceil *validation.Value, actor string) (validation.Value, error) {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer c.UnlockProcess()
	prevRaw, hadRaw := c.rawState() // r16 unwind law
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	b := validation.ObjAt(st, "budget")
	old := validation.ObjAt(b, "max_total_cost_usd")
	newV := validation.VNull()
	if ceil != nil {
		newV = *ceil
	}
	b.O = validation.SetOrAppend(b.O, "max_total_cost_usd", newV)
	st.O = validation.SetOrAppend(st.O, "budget", b)
	if err := c.save(st); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("old", old),
		kv("new", newV),
		kv("actor", validation.VStr(actor)),
	)
	if _, lerr := c.Log("budget.limit_set", nil, &data); lerr != nil {
		// r16: the ledger refused — UNWIND the state
		// write (PinSnapshot's r9 discipline,
		// generalized): a decision the log never
		// recorded must not live in the projection.
		if uerr := c.unwindState(prevRaw, hadRaw); uerr != nil {
			return validation.VNull(), lerr
		}
		return validation.VNull(), lerr
	}
	return validation.ObjAt(st, "budget"), nil
}

// SetDiscoveryBudget is set_discovery_budget: set the deterministic
// discovery ceiling. A ceiling change is a DECISION: actor-attributed
// and log-chained, same law as the cost ceiling. Positive integers only.
//
// Deviation: the Python isinstance(x, bool) rejection has no Go
// analogue (an int64 is never a bool); the < 1 check is exact.
func (c *Campaign) SetDiscoveryBudget(maxFindings int64, actor string) (validation.Value, error) {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer c.UnlockProcess()
	prevRaw, hadRaw := c.rawState() // r16 unwind law
	if maxFindings < 1 {
		return validation.VNull(), fmt.Errorf("max_discovery_findings must be a positive integer")
	}
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	b := validation.ObjAt(st, "budget")
	old := validation.ObjAt(b, "max_discovery_findings")
	b.O = validation.SetOrAppend(b.O, "max_discovery_findings", validation.VInt(maxFindings))
	st.O = validation.SetOrAppend(st.O, "budget", b)
	if err := c.save(st); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("old", old),
		kv("new", validation.VInt(maxFindings)),
		kv("actor", validation.VStr(actor)),
	)
	if _, lerr := c.Log("budget.discovery_set", nil, &data); lerr != nil {
		// r16: the ledger refused — UNWIND the state
		// write (PinSnapshot's r9 discipline,
		// generalized): a decision the log never
		// recorded must not live in the projection.
		if uerr := c.unwindState(prevRaw, hadRaw); uerr != nil {
			return validation.VNull(), lerr
		}
		return validation.VNull(), lerr
	}
	return validation.ObjAt(st, "budget"), nil
}
