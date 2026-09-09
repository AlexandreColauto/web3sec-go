package cli

// cmd_precondition: `webv2 precondition <campaign> <finding> <description>
// {--enforced | --not-enforced}` — audit a precondition against the PoC: does
// the CODE enforce it? Marking it not-enforced opens a rung; leaving it
// unaddressed fails the bounty gate (precondition-audit). cli.py
// cmd_precondition verbatim.

import (
	"fmt"
	"strings"

	"websec/internal/findings"
	"websec/internal/validation"
)

const preconditionUsage = "usage: webv2 precondition [-h] (--enforced | " +
	"--not-enforced)\n                          campaign finding description\n"

const preconditionHelp = `usage: webv2 precondition [-h] (--enforced | --not-enforced)
                          campaign finding description

positional arguments:
  campaign
  finding
  description

options:
  -h, --help      show this help message and exit
  --enforced
  --not-enforced
`

func runPrecondition(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		// argparse's mutually-exclusive group errors at parse time, BEFORE
		// the missing-positional check; the required-group error comes last.
		if err := preconditionExclusive(args); err != nil {
			return err
		}
		sp := &argSpec{prog: "precondition", usage: preconditionUsage,
			flags: []*boolOpt{{name: "--enforced"}, {name: "--not-enforced"}},
			pos: []*posOpt{{name: "campaign"}, {name: "finding"},
				{name: "description"}}}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, preconditionHelp)
			return nil
		}
		if !sp.flags[0].set && !sp.flags[1].set {
			return t14ArgparseErr(preconditionUsage, "precondition",
				"one of the arguments --enforced --not-enforced is required")
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		finding := sp.pos[1].val
		description := sp.pos[2].val
		f, err := findings.MarkPrecondition(c, finding, description,
			sp.flags[0].set)
		if err != nil {
			return err
		}
		val, ok := preconditionValue(f, description)
		if !ok {
			// Python's `next(...)` without a default raises StopIteration,
			// whose str() is empty: the generic handler prints "error: ".
			return t14ExitErr(1, "error: \n")
		}
		shown := []rune(description)
		if len(shown) > 50 {
			shown = shown[:50]
		}
		fmt.Fprintf(r.Out, "%s: precondition %s -> enforced_by_poc=%s\n",
			finding, validation.PyReprStr(string(shown)), val)
		return nil
	})
}

// preconditionExclusive is argparse's mutual-exclusion check: the SECOND of
// the two flags is the one reported as "not allowed with" the first.
func preconditionExclusive(args []string) error {
	seen := []string{}
	afterSep := false
	for _, a := range args {
		if a == "--" && !afterSep {
			afterSep = true
			continue
		}
		if afterSep {
			continue
		}
		switch a {
		case "--enforced", "--not-enforced":
			seen = append(seen, a)
		}
	}
	if len(seen) >= 2 {
		return t14ArgparseErr(preconditionUsage, "precondition",
			"argument %s: not allowed with argument %s", seen[1], seen[0])
	}
	return nil
}

// preconditionValue is cli.py's `next(...)` search: the first precondition
// whose description contains (or is contained by) the argument.
func preconditionValue(f validation.Value, description string) (string, bool) {
	for _, p := range objListAt(f, "preconditions") {
		desc := objStr(p, "description")
		if desc == "" {
			continue
		}
		if strings.Contains(desc, description) ||
			strings.Contains(description, desc) {
			v := objAt(p, "enforced_by_poc")
			if v.Kind == validation.Null {
				continue
			}
			return scalarStr(v), true
		}
	}
	return "", false
}

func init() {
	register(command{ord: 62, name: "precondition",
		line: "precondition <campaign> <finding> <description>  audit a " +
			"precondition against the code",
		run: runPrecondition})
}
