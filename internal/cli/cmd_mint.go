package cli

// cmd_mint: `webv2 mint <campaign> <finding> --exec E --description D
// [--tier T] [--type TYPE] [--poc-tier {existence,maximized}]
// [--verify-reruns] [--no-hints]` — record a successful reproduction attempt
// AND mint its evidence in one call (forge-meaningfulness checked, type
// validated against the schema enum). Idempotent per exec: re-minting the
// same exec is a no-op that returns the finding unchanged.
//
// `--tier` is the T1–T4 CLAIM tier, unchanged; `--poc-tier` is the
// orthogonal v1.6 §2.2 two-tier PoC declaration that lands on the evidence
// item. Its ordering law (maximized needs an existence tier first, on a
// fork-dependent finding) is enforced in reproduction.MintReproEvidence —
// the CLI pre-check below only turns it into a clean exit-2 message.
//
// `--no-hints` (B9) suppresses the write-time hygiene note; it is documented
// in the verb's help and implemented in hints.go.

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
                  [--poc-tier {existence,maximized}]
                  [--type {balance-delta,differential,fork-test,foundry-test,fuzz,historical-analog,invariant-test,manual,reachability,reasoning,static-analysis,symbolic-witness,trace,unit-test}]
                  [--verify-reruns]
                  [--no-hints]
                  campaign finding

positional arguments:
  campaign
  finding

options:
  -h, --help            show this help message and exit
  --exec EXEC_ID
  --description DESCRIPTION
  --tier {T1,T2,T3,T4}
  --poc-tier {existence,maximized}
                        two-tier fork evidence (v1.6 2.2): existence = the
                        state break on a pinned fork at any magnitude;
                        maximized = the maximization loop's output, refused on
                        a fork-dependent finding until an existence tier is
                        minted
  --type {balance-delta,differential,fork-test,foundry-test,fuzz,historical-analog,invariant-test,manual,reachability,reasoning,static-analysis,symbolic-witness,trace,unit-test}
  --verify-reruns       re-run the PoC 3x and record the variance advisory
                        (fail-open; needs a container runtime)
  --no-hints            suppress the write-time hygiene note (the <=3 stderr
                        lines naming undispositioned surface rows / open plan
                        priorities that share the finding's affected[] anchors);
                        the environment switch WEBV2_NO_HINTS=1 does the same
                        (only the literal 1)
`

// mintTiers is the argparse choice list for --tier (declaration order).
var mintTiers = []string{"T1", "T2", "T3", "T4"}

func runMint(root string, args []string, r *Runner) int {
	ensureSeams()
	m, code := mintParseArgs(root, args, r)
	if m == nil {
		return code
	}
	c, code := mintOpenCampaign(root, m, r)
	if c == nil {
		return code
	}
	if out, done := mintIdempotentNoop(root, r, c, m); done {
		return out
	}
	if code, refused := mintPocTierRefusal(root, r, c, m); refused {
		return code
	}
	return mintExecute(root, r, c, m)
}

// mintPocTierRefusal is the CLI half of the §2.2 ordering law: the operator
// gets a named exit-2 refusal instead of the write path's generic error. It
// is a PRE-CHECK only — reproduction.MintReproEvidence enforces the same law
// for every caller (the ladder and Phase 5's maximization loop included).
// refused=false means the mint may proceed.
func mintPocTierRefusal(root string, r *Runner, c *state.Campaign,
	m *mintParsed) (int, bool) {
	if m.pocTier != "maximized" {
		return 0, false
	}
	finding, err := findings.LoadFinding(c, m.pos[1])
	if err != nil {
		return r.withErr(root, func() error { return err }), true
	}
	if err := findings.ValidatePocTierOrder(finding, "maximized"); err != nil {
		_, _ = fmt.Fprintf(r.Err, "%v\n", err)
		return 2, true
	}
	return 0, false
}

// mintParsed carries the parsed `mint` command line: the flag values, their
// presence bits, and the collected positionals.
type mintParsed struct {
	pos          []string
	execID       string
	description  string
	tier         string
	pocTier      string
	etype        string
	haveExec     bool
	haveDesc     bool
	haveTier     bool
	havePocTier  bool
	haveType     bool
	verifyReruns bool
	noHints      bool
}

// mintParseArgs scans the raw arguments with cli.py's hand-rolled loop and
// enforces the required/choice checks. A nil result means the exit code is
// already decided (help, usage or argparse error printed).
func mintParseArgs(root string, args []string, r *Runner) (*mintParsed, int) {
	m := &mintParsed{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--exec":
			next, ok := flagValue(args, i)
			if !ok {
				return nil, r.fail(root, argErrf("mint",
					"argument --exec: expected one argument"))
			}
			m.execID, m.haveExec = next, true
			i++
		case strings.HasPrefix(a, "--exec="):
			m.execID, m.haveExec = strings.TrimPrefix(a, "--exec="), true
		case a == "--description":
			next, ok := flagValue(args, i)
			if !ok {
				return nil, r.fail(root, argErrf("mint",
					"argument --description: expected one argument"))
			}
			m.description, m.haveDesc = next, true
			i++
		case strings.HasPrefix(a, "--description="):
			m.description, m.haveDesc = strings.TrimPrefix(a, "--description="), true
		case a == "--tier":
			next, ok := flagValue(args, i)
			if !ok {
				return nil, r.fail(root, argErrf("mint",
					"argument --tier: expected one argument"))
			}
			m.tier, m.haveTier = next, true
			i++
		case strings.HasPrefix(a, "--tier="):
			m.tier, m.haveTier = strings.TrimPrefix(a, "--tier="), true
		case a == "--poc-tier":
			next, ok := flagValue(args, i)
			if !ok {
				return nil, r.fail(root, argErrf("mint",
					"argument --poc-tier: expected one argument"))
			}
			m.pocTier, m.havePocTier = next, true
			i++
		case strings.HasPrefix(a, "--poc-tier="):
			m.pocTier, m.havePocTier = strings.TrimPrefix(a, "--poc-tier="), true
		case a == "--type":
			next, ok := flagValue(args, i)
			if !ok {
				return nil, r.fail(root, argErrf("mint",
					"argument --type: expected one argument"))
			}
			m.etype, m.haveType = next, true
			i++
		case strings.HasPrefix(a, "--type="):
			m.etype, m.haveType = strings.TrimPrefix(a, "--type="), true
		case a == "--verify-reruns":
			m.verifyReruns = true
		case a == "--no-hints":
			m.noHints = true
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, mintHelp)
			return nil, 0
		case strings.HasPrefix(a, "-"):
			return nil, r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			m.pos = append(m.pos, a)
		}
	}
	if len(m.pos) > 2 {
		return nil, r.fail(root, usageErrf("unrecognized arguments: %s", m.pos[2]))
	}
	if code := mintRequireArgs(root, m, r); code != 0 {
		return nil, code
	}
	if code := mintCheckChoices(root, m, r); code != 0 {
		return nil, code
	}
	return m, 0
}

// mintRequireArgs enforces mint's required positionals and flags.
func mintRequireArgs(root string, m *mintParsed, r *Runner) int {
	missing := []string{}
	if len(m.pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(m.pos) < 2 {
		missing = append(missing, "finding")
	}
	if !m.haveExec {
		missing = append(missing, "--exec")
	}
	if !m.haveDesc {
		missing = append(missing, "--description")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("mint", missing...))
	}
	return 0
}

// mintCheckChoices validates the --tier, --poc-tier and --type argparse
// choice lists.
func mintCheckChoices(root string, m *mintParsed, r *Runner) int {
	if m.haveTier && !containsStrCLI(mintTiers, m.tier) {
		return r.fail(root, argErrf("mint",
			"argument --tier: invalid choice: %s (choose from %s)",
			validation.PyReprStr(m.tier), quotedList(mintTiers)))
	}
	if m.havePocTier && !containsStrCLI(findings.PocTiers, m.pocTier) {
		return r.fail(root, argErrf("mint",
			"argument --poc-tier: invalid choice: %s (choose from %s)",
			validation.PyReprStr(m.pocTier), quotedList(findings.PocTiers)))
	}
	if m.haveType && !containsStrCLI(reproduction.MintableTypes, m.etype) {
		return r.fail(root, argErrf("mint",
			"argument --type: invalid choice: %s (choose from %s)",
			validation.PyReprStr(m.etype), quotedList(sortedMintTypes())))
	}
	return 0
}

// mintOpenCampaign opens the campaign and enforces the --description
// requirement. A nil result means the exit code is already decided.
func mintOpenCampaign(root string, m *mintParsed, r *Runner) (*state.Campaign, int) {
	c, err := state.Open(root, m.pos[0])
	if err != nil {
		return nil, r.withErr(root, func() error { return err })
	}
	if m.description == "" {
		fmt.Fprintln(r.Err,
			"mint requires --description (what the PoC demonstrates)")
		return nil, 2
	}
	return c, 0
}

// mintIdempotentNoop reports (and prints) the already-minted case: the same
// (exec, type) pair present in the finding's evidence. done=true means the
// command is finished and the returned code is final.
func mintIdempotentNoop(root string, r *Runner, c *state.Campaign,
	m *mintParsed) (int, bool) {
	f, err := findings.LoadFinding(c, m.pos[1])
	if err != nil {
		return r.withErr(root, func() error { return err }), true
	}
	var tierPtr, typePtr *string
	if m.haveTier {
		tierPtr = &m.tier
	}
	if m.haveType {
		typePtr = &m.etype
	}
	// Idempotency is per (exec, type) — the same exec may back a second
	// evidence item of a DIFFERENT type (feedback-triage A2: the reference
	// keyed on exec alone, so the second type silently never landed).
	effectiveType := reproduction.EffectiveEvidenceType(tierPtr, typePtr, f)
	for _, e := range validation.ObjAt(f, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == m.execID && validation.ObjStr(e, "type") == effectiveType {
			level, err := findings.FindingLevel(f)
			if err != nil {
				return r.withErr(root, func() error { return err }), true
			}
			fmt.Fprintf(r.Out, "%s: exec %s already minted as %s — idempotent "+
				"no-op (evidence level %s)\n", m.pos[1], m.execID, effectiveType, level)
			return 0, true
		}
	}
	return 0, false
}

// mintExecute runs the reproduction attempt and prints its outcome.
func mintExecute(root string, r *Runner, c *state.Campaign, m *mintParsed) int {
	var tierPtr, typePtr *string
	if m.haveTier {
		tierPtr = &m.tier
	}
	if m.haveType {
		typePtr = &m.etype
	}
	// The variance gate is process-global in the library (the other mint
	// callers — ladder, sequence — never opt in); save/restore so
	// in-process test runs cannot leak the flag between commands.
	prevVerify := reproduction.VerifyReruns
	reproduction.VerifyReruns = m.verifyReruns
	defer func() { reproduction.VerifyReruns = prevVerify }()
	out, err := reproduction.AttemptAndMint(c, m.pos[1], m.execID, m.description,
		tierPtr, typePtr, m.pocTier)
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
	if m.haveType {
		label = m.etype
	}
	fmt.Fprintf(r.Out, "%s: minted %s evidence from %s — level %s\n",
		m.pos[1], label, m.execID, level)
	// B9: the same capped, suppressible hygiene note ingest prints — the
	// finding's affected[] anchors are compared against the campaign's
	// surface and plan. stderr, after the success line; stdout is untouched.
	emitWriteHints(c, []validation.Value{out}, m.noHints, r.Err)
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
