package cli

// cmd_gate: `webv2 gate [<campaign> [FINDING]] [--explain CHECK]` —
//   * `gate --explain CHECK`      one failing check, explained (no campaign)
//   * `gate <campaign> FINDING`   dry-run the CONFIRMED gate on one finding:
//     EVERY live clause with its verdict, the delta since the last refused
//     attempt, and the economic NAMED DECISION when one carried the clause
//   * `gate <campaign>`           the bounty gate over CONFIRMED findings
// (cli.py cmd_gate_or_explain / cmd_gate / cmd_gate_dryrun / cmd_gate_explain
// verbatim.)
//
// The clause enumeration lives here because findings.confirmation_gate_clauses
// + clause_id + economic_clause_present are deferred to P3: the CLI rebuilds
// the clause set from the exported primitives (ConfirmationGateDetail for the
// failure strings, GateRequirements for the economic marker, the invariants
// package for the shield/invariant clauses) in Python's gate order. A test
// asserts the rebuilt failure set equals ConfirmationGateDetail exactly.

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"websec/internal/bounty"
	"websec/internal/findings"
	"websec/internal/orchestrator"
	"websec/internal/state"
	"websec/internal/validation"
)

// gateUsage is cmd_gate's own usage line (campaign is optional, so argparse
// never prints this — the handler does).
const gateUsage = "usage: webv2 gate <campaign> [FINDING] | webv2 gate --explain <CHECK>"

func runGate(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "gate", args) {
		return 0
	}

	ensureSeams()
	explain, haveExplain := "", false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--explain" && i+1 < len(args):
			explain, haveExplain = args[i+1], true
			i++
		case strings.HasPrefix(a, "--explain="):
			explain, haveExplain = strings.TrimPrefix(a, "--explain="), true
		case a == "--explain":
			return r.fail(root, argErrf("gate",
				"argument --explain: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	_ = haveExplain
	if explain != "" {
		return runGateExplain(explain, r)
	}
	if len(pos) == 0 {
		fmt.Fprintln(r.Err, gateUsage)
		return 2
	}
	if len(pos) > 2 {
		return r.withErr(root, func() error {
			return usageErrf("unrecognized arguments: %s", pos[2])
		})
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	if len(pos) == 2 {
		return runGateDryrun(c, pos[1], r)
	}
	o := orchestrator.New(c)
	results, err := o.BountyGateAll()
	if err != nil {
		// cli.py catches ORC.OrchestrationError and prints `error: {e}` with
		// exit 2 (not the generic exit-1 handler).
		var oe *orchestrator.OrchestrationError
		if errors.As(err, &oe) {
			fmt.Fprintf(r.Err, "error: %s\n", oe.Msg)
			return 2
		}
		return r.withErr(root, func() error { return err })
	}
	if len(results.A) == 0 {
		fmt.Fprintln(r.Out, "nothing to evaluate: the bounty gate runs on "+
			"CONFIRMED findings and this campaign has none yet (advance "+
			"findings through the evidence ladder with exec/repro/verify, "+
			"then gate them — `webv2 brief` shows the exact deficit per "+
			"finding)")
		return 0
	}
	for _, row := range results.A {
		fmt.Fprintf(r.Out, "%s: eligible=%s submission_ready=%s\n",
			objStr(row, "finding_id"), pyBoolText(objAt(row, "eligible")),
			pyBoolText(objAt(row, "submission_ready")))
		for _, b := range objAt(row, "blocking_reasons").A {
			fmt.Fprintf(r.Out, "  blocker: %s\n", scalarStr(b))
		}
	}
	return 0
}

// pyBoolText is Python's f"{v}" for the booleans the gate prints.
func pyBoolText(v validation.Value) string { return scalarStr(v) }

// runGateExplain is cmd_gate_explain: every check id has a stable
// explanation and the exact command that clears it.
func runGateExplain(checkID string, r *Runner) int {
	info, err := bounty.GateExplain(checkID)
	if err != nil {
		fmt.Fprintf(r.Err, "gate explain failed: %s\n", err.Error())
		return 2
	}
	fmt.Fprintf(r.Out, "check:      %s  (gate: %s)\n", objStr(info, "check"),
		objStr(info, "gate"))
	fmt.Fprintf(r.Out, "remediation: %s\n", objStr(info, "remediation"))
	return 0
}

// runGateDryrun is cmd_gate_dryrun: read-only, no status change, no write.
// Every live clause comes from findings.ConfirmationGateClauses (the single
// source the transition itself uses) — this function only renders it.
func runGateDryrun(c *state.Campaign, findingID string, r *Runner) int {
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		fmt.Fprintf(r.Err, "gate failed: %s\n", err.Error())
		return 2
	}
	clauses, err := findings.ConfirmationGateClauses(c, f)
	if err != nil {
		return r.withErr(c.Root, func() error { return err })
	}
	failures := 0
	for _, cl := range clauses {
		if !cl.OK {
			failures++
		}
	}
	status := objStr(f, "status")
	if failures > 0 {
		fmt.Fprintf(r.Out, "%s (status %s): CONFIRMED gate — %d of %d "+
			"check(s) failing:\n", findingID, status, failures, len(clauses))
	} else {
		fmt.Fprintf(r.Out, "%s (status %s): CONFIRMED gate — all checks "+
			"pass (%d clause(s))\n", findingID, status, len(clauses))
	}
	if err := printEconomicDecision(c, f, findingID, r.Out); err != nil {
		return r.withErr(c.Root, func() error { return err })
	}
	for _, cl := range clauses {
		if cl.OK {
			fmt.Fprintf(r.Out, "  \u2713 %s\n", cl.ID())
			continue
		}
		fmt.Fprintf(r.Out, "  \u2717 %s: %s\n", cl.ID(), cl.Message)
		if cl.Remediation != "" {
			fmt.Fprintf(r.Out, "    fix: %s\n", cl.Remediation)
		}
	}
	prev, err := lastGateAttempt(c, findingID)
	if err != nil {
		return r.withErr(c.Root, func() error { return err })
	}
	for _, line := range gateDeltaLines(clauses, prev) {
		fmt.Fprintln(r.Out, line)
	}
	if failures > 0 {
		return 1
	}
	return 0
}

func init() {
	register(command{ord: 56, name: "gate",
		line: "gate [campaign] [finding]           bounty gate / CONFIRMED dry-run",
		run:  runGate})
}

// --- economic decision line ----------------------------------------------

// printEconomicDecision states an accepted NAMED DECISION: the economic-class
// E7 clause can be satisfied by 'no figure is defensible', and the operator
// must see both the decision and the basis it was made against. Gated on the
// finding actually HAVING that clause (economic_clause_present).
func printEconomicDecision(c *state.Campaign, f validation.Value,
	findingID string, w io.Writer) error {
	decision := findings.UnpriceableDecision(f)
	if decision == nil || !findings.EconomicClausePresent(c, f) {
		return nil
	}
	events, err := c.Events()
	if err != nil {
		return err
	}
	data := validation.VNull()
	for _, e := range events {
		if objStr(e, "type") == "finding.unpriceable" &&
			objStr(e, "ref") == findingID {
			data = asDictCLI(objAt(e, "data"))
		}
	}
	detail := ""
	if actor := objAt(data, "actor"); pyTruthyCLI(actor) {
		detail = " (actor " + scalarStr(actor)
		if reason := objAt(data, "reason"); pyTruthyCLI(reason) {
			detail += ", reason: " + pyHead(scalarStr(reason), 100)
		}
		detail += ")"
	}
	fmt.Fprintf(w, "  economic clause: satisfied by NAMED DECISION — "+
		"UNPRICEABLE (ceiling: %s)%s\n", objStr(*decision, "ceiling"), detail)
	return nil
}

// --- delta since the last refused attempt --------------------------------

// lastGateAttempt is _last_gate_attempt: the failing check ids of the most
// recent refused CONFIRMED transition, or nil when none is on record. A
// recorded event whose check_ids is not a list yields the empty (unreadable)
// list; non-string members are dropped here exactly as _gate_delta_lines
// drops them (a hand-edited or older event must not crash the delta).
func lastGateAttempt(c *state.Campaign, findingID string) ([]string, error) {
	events, err := c.Events()
	if err != nil {
		return nil, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if objStr(e, "type") != "finding.gate_attempt" ||
			objStr(e, "ref") != findingID {
			continue
		}
		ids := objAt(asDictCLI(objAt(e, "data")), "check_ids")
		if ids.Kind != validation.Arr {
			return []string{}, nil
		}
		out := []string{}
		for _, x := range ids.A {
			if x.Kind == validation.Str && x.S != "" {
				out = append(out, x.S)
			}
		}
		return out, nil
	}
	return nil, nil
}

// gateDeltaLines is _gate_delta_lines.
func gateDeltaLines(clauses []findings.Clause, prev []string) []string {
	if prev == nil {
		return []string{"since last attempt: (none recorded)"}
	}
	if len(prev) == 0 {
		return []string{"since last attempt: (attempt unreadable)"}
	}
	order := []string{}
	for _, cl := range clauses {
		if !containsStrCLI(order, cl.ID()) {
			order = append(order, cl.ID())
		}
	}
	for _, cid := range prev {
		if !containsStrCLI(order, cid) {
			order = append(order, cid)
		}
	}
	nowFailing := map[string]bool{}
	for _, cl := range clauses {
		if !cl.OK {
			nowFailing[cl.ID()] = true
		}
	}
	prevSet := map[string]bool{}
	for _, cid := range prev {
		prevSet[cid] = true
	}
	lines := []string{}
	for _, cid := range order {
		if nowFailing[cid] && !prevSet[cid] {
			lines = append(lines, "since last attempt: "+cid+" \u2717")
		} else if !nowFailing[cid] && prevSet[cid] {
			lines = append(lines, "since last attempt: "+cid+" \u2713")
		}
	}
	if len(lines) > 0 {
		return lines
	}
	still := []string{}
	for _, cid := range order {
		if nowFailing[cid] {
			still = append(still, cid)
		}
	}
	return []string{"since last attempt: no change (" +
		strings.Join(still, ", ") + ")"}
}

// asDictCLI is findings._as_dict: the value when it is an object, else {}.
func asDictCLI(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return v
	}
	return validation.VObj()
}

// setObjFieldCLI is findings.setDeep for a single-key path: a new object with
// key set to val (the key keeps its position when it already exists). Test
// fixtures use it to edit a loaded record in place.
func setObjFieldCLI(v validation.Value, key string,
	val validation.Value) validation.Value {
	out := validation.VObj()
	replaced := false
	for _, kv := range v.O {
		if kv.K == key {
			out.O = append(out.O, validation.KV{K: key, V: val})
			replaced = true
			continue
		}
		out.O = append(out.O, kv)
	}
	if !replaced {
		out.O = append(out.O, validation.KV{K: key, V: val})
	}
	return out
}
