package cli

// cmd_terminals: `webv2 terminals <campaign>` — reachable economic terminal
// states over CONFIRMED findings from the EOA baseline (cli.py cmd_terminals
// verbatim, including the shared capital suffix).

import (
	"fmt"
	"strings"

	"websec/internal/chainengine"
	"websec/internal/validation"
)

func runTerminals(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		name, done, err := t23OneArg(args, "terminals", r)
		if err != nil || done {
			return err
		}
		c, err := t14Open(root, name)
		if err != nil {
			return err
		}
		rep, err := chainengine.TerminalReport(c, nil)
		if err != nil {
			return err
		}
		printTerminals(r, rep)
		return nil
	})
}

func printTerminals(r *Runner, rep validation.Value) {
	base := t14Join(t14List(rep, "baseline"))
	if base == "" {
		base = "(none)"
	}
	fmt.Fprintf(r.Out, "attacker baseline: %s\n", base)
	chains := t14List(rep, "terminal_chains")
	fmt.Fprintf(r.Out, "shortest path to each terminal state "+
		"(%d multi-step paths enumerated):\n", len(chains.A))
	for _, p := range t14List(rep, "shortest_by_terminal").A {
		kind := "chain"
		if len(t14List(p, "path").A) == 1 {
			kind = "direct"
		}
		capUSD := pyFloatOf(validation.ObjAt(p, "total_capital_required_usd"))
		fmt.Fprintf(r.Out, "  [%s] -> %s: %s (capital $%s%s)\n", kind,
			validation.ObjStr(p, "terminal_capability"),
			strings.Join(t14Strings(t14List(p, "path")), " -> "),
			t23Money0(capUSD), t23CapSuffix(p))
	}
	materialized := t14List(rep, "materialized_terminal_chains")
	fmt.Fprintf(r.Out, "materialized terminal chains: %d\n", len(materialized.A))
	for _, ch := range materialized.A {
		t := validation.ObjAt(ch, "terminal")
		line := fmt.Sprintf("  %s [%s] -> %s via %s (floor %s)",
			validation.ObjStr(ch, "chain_id"), validation.ObjStr(ch, "status"),
			validation.ObjStr(t, "capability"), scalarStr(validation.ObjAt(t, "via_finding")),
			validation.ObjStr(ch, "evidence_floor"))
		// B3: an unproven chain's terminal is the lead's destination, not a
		// result — say so. A proven chain renders exactly as before.
		if validation.ObjStr(ch, "provenance") == "unproven" {
			line += " — UNPROVEN (hypothesis-level)"
		}
		fmt.Fprintln(r.Out, line)
	}
}

// t23CapSuffix is cli.py _cap_suffix: the capital tail shared by terminals
// and privileged ("; net at risk $N" only when net is recorded and below cap).
func t23CapSuffix(p validation.Value) string {
	capUSD := pyFloatOf(validation.ObjAt(p, "total_capital_required_usd"))
	net := validation.ObjAt(validation.ObjAt(p, "capital_breakdown"), "net_at_risk_usd")
	if net.Kind == validation.Null {
		return ""
	}
	netUSD := pyFloatOf(net)
	if netUSD >= capUSD {
		return ""
	}
	return fmt.Sprintf("; net at risk $%s", t23Money0(netUSD))
}

func init() {
	register(command{ord: 9, name: "terminals",
		line: "terminals <campaign>                reachable economic terminal states",
		run:  runTerminals})
}
