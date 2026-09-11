package cli

// cmd_mint: `webv2 mint <campaign> <finding> --exec E --description D
// [--tier T] [--type TYPE]` — record a successful reproduction attempt AND
// mint its evidence in one call (forge-meaningfulness checked, type
// validated against the schema enum). Idempotent per exec: re-minting the
// same exec is a no-op that returns the finding unchanged.

import (
	"errors"
	"fmt"
	"strings"

	"websec/internal/findings"
	"websec/internal/reproduction"
	"websec/internal/state"
	"websec/internal/validation"
)

// mintHelp is argparse's `webv2 mint --help` output, byte-exact.
const mintHelp = `usage: webv2 mint [-h] --exec EXEC_ID --description DESCRIPTION
                  [--tier {T1,T2,T3,T4}]
                  [--type {balance-delta,differential,fork-test,foundry-test,fuzz,historical-analog,invariant-test,manual,reachability,reasoning,static-analysis,symbolic-witness,trace,unit-test}]
                  [--verify-reruns]
                  campaign finding

positional arguments:
  campaign
  finding

options:
  -h, --help            show this help message and exit
  --exec EXEC_ID
  --description DESCRIPTION
  --tier {T1,T2,T3,T4}
  --type {balance-delta,differential,fork-test,foundry-test,fuzz,historical-analog,invariant-test,manual,reachability,reasoning,static-analysis,symbolic-witness,trace,unit-test}
  --verify-reruns       re-run the PoC 3x and record the variance advisory
                        (fail-open; needs a container runtime)
`

// mintTiers is the argparse choice list for --tier (declaration order).
var mintTiers = []string{"T1", "T2", "T3", "T4"}

func runMint(root string, args []string, r *Runner) int {
	ensureSeams()
	var pos []string
	execID, description, tier, etype := "", "", "", ""
	haveExec, haveDesc, haveTier, haveType := false, false, false, false
	verifyReruns := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--exec":
			next, ok := flagValue(args, i)
			if !ok {
				return r.fail(root, argErrf("mint",
					"argument --exec: expected one argument"))
			}
			execID, haveExec = next, true
			i++
		case strings.HasPrefix(a, "--exec="):
			execID, haveExec = strings.TrimPrefix(a, "--exec="), true
		case a == "--description":
			next, ok := flagValue(args, i)
			if !ok {
				return r.fail(root, argErrf("mint",
					"argument --description: expected one argument"))
			}
			description, haveDesc = next, true
			i++
		case strings.HasPrefix(a, "--description="):
			description, haveDesc = strings.TrimPrefix(a, "--description="), true
		case a == "--tier":
			next, ok := flagValue(args, i)
			if !ok {
				return r.fail(root, argErrf("mint",
					"argument --tier: expected one argument"))
			}
			tier, haveTier = next, true
			i++
		case strings.HasPrefix(a, "--tier="):
			tier, haveTier = strings.TrimPrefix(a, "--tier="), true
		case a == "--type":
			next, ok := flagValue(args, i)
			if !ok {
				return r.fail(root, argErrf("mint",
					"argument --type: expected one argument"))
			}
			etype, haveType = next, true
			i++
		case strings.HasPrefix(a, "--type="):
			etype, haveType = strings.TrimPrefix(a, "--type="), true
		case a == "--verify-reruns":
			verifyReruns = true
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, mintHelp)
			return 0
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) > 2 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", pos[2]))
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pos) < 2 {
		missing = append(missing, "finding")
	}
	if !haveExec {
		missing = append(missing, "--exec")
	}
	if !haveDesc {
		missing = append(missing, "--description")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("mint", missing...))
	}
	if haveTier && !containsStrCLI(mintTiers, tier) {
		return r.fail(root, argErrf("mint",
			"argument --tier: invalid choice: %s (choose from %s)",
			validation.PyReprStr(tier), quotedList(mintTiers)))
	}
	if haveType && !containsStrCLI(reproduction.MintableTypes, etype) {
		return r.fail(root, argErrf("mint",
			"argument --type: invalid choice: %s (choose from %s)",
			validation.PyReprStr(etype), quotedList(sortedMintTypes())))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	if description == "" {
		fmt.Fprintln(r.Err,
			"mint requires --description (what the PoC demonstrates)")
		return 2
	}
	f, err := findings.LoadFinding(c, pos[1])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	var tierPtr, typePtr *string
	if haveTier {
		tierPtr = &tier
	}
	if haveType {
		typePtr = &etype
	}
	// Idempotency is per (exec, type) — the same exec may back a second
	// evidence item of a DIFFERENT type (feedback-triage A2: the reference
	// keyed on exec alone, so the second type silently never landed).
	effectiveType := reproduction.EffectiveEvidenceType(tierPtr, typePtr, f)
	for _, e := range objAt(f, "evidence").A {
		if objStr(e, "artifact_id") == execID && objStr(e, "type") == effectiveType {
			level, err := findings.FindingLevel(f)
			if err != nil {
				return r.withErr(root, func() error { return err })
			}
			fmt.Fprintf(r.Out, "%s: exec %s already minted as %s — idempotent "+
				"no-op (evidence level %s)\n", pos[1], execID, effectiveType, level)
			return 0
		}
	}
	// The variance gate is process-global in the library (the other mint
	// callers — ladder, sequence — never opt in); save/restore so
	// in-process test runs cannot leak the flag between commands.
	prevVerify := reproduction.VerifyReruns
	reproduction.VerifyReruns = verifyReruns
	defer func() { reproduction.VerifyReruns = prevVerify }()
	out, err := reproduction.AttemptAndMint(c, pos[1], execID, description,
		tierPtr, typePtr)
	if err != nil {
		var me *reproduction.MintError
		if errors.As(err, &me) {
			fmt.Fprintf(r.Err, "mint failed: %s\n", me.Error())
			return 2
		}
		return r.withErr(root, func() error { return err })
	}
	if notice := reproduction.TakeMintNotice(); notice != "" {
		fmt.Fprintln(r.Err, notice)
	}
	level, err := findings.FindingLevel(out)
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	label := "default"
	if haveType {
		label = etype
	}
	fmt.Fprintf(r.Out, "%s: minted %s evidence from %s — level %s\n",
		pos[1], label, execID, level)
	return 0
}

// sortedMintTypes is argparse's sorted(...) choice list for --type.
func sortedMintTypes() []string {
	out := append([]string(nil), reproduction.MintableTypes...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func init() {
	register(command{ord: 43, name: "mint",
		line: "mint <campaign> <finding> --exec E --description D  mint evidence",
		run:  runMint})
}
