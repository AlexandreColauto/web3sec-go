package cli

// cmd_baseline: `webv2 baseline {add,list,remove} ...` — manage the baseline
// reference trees (operator-supplied, version-pinned). Port of cli.py
// cmd_baseline verbatim, including argparse's nested-subparser usage blocks,
// its help action and its error precedence.

import (
	"fmt"
	"strings"
	"websec/internal/validation"

	"websec/internal/forkdiff"
)

const (
	baselineUsage       = "usage: webv2 baseline [-h] {add,list,remove} ...\n"
	baselineAddUsage    = "usage: webv2 baseline add [-h] --path PATH [--source-url SOURCE_URL]\n                          [--license LICENSE]\n                          name\n"
	baselineListUsage   = "usage: webv2 baseline list [-h]\n"
	baselineRemoveUsage = "usage: webv2 baseline remove [-h] name\n"
)

// baselineChoices is argparse's `baseline_cmd` choice list, in order.
var baselineChoices = []string{"add", "list", "remove"}

func runBaseline(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		return baselineDispatch(args, r)
	})
}

// baselineDispatch splits the parent parser (choice + -h) from the chosen
// subparser. argparse validates the choice while parsing the parent, then
// delegates the remaining argv to the subparser; subparser errors (help,
// expected-one-argument, missing required) surface immediately, and only
// after a successful parse does parse_args report the combined
// parent+subparser "unrecognized arguments" — which therefore preempts the
// command body.
func baselineDispatch(args []string, r *Runner) error {
	var parentExtras []string
	sub, rest := "", []string(nil)
	afterSep := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !afterSep && a == "--" {
			afterSep = true
			continue
		}
		if !afterSep {
			if explicit, ok := helpToken(a); ok {
				if explicit != "" {
					return t14ArgparseErr(baselineUsage, "baseline",
						"argument -h/--help: ignored explicit argument %s",
						quoteSingle(explicit))
				}
				fmt.Fprint(r.Out, baselineHelp)
				return nil
			}
			if looksLikeOption(a) {
				parentExtras = append(parentExtras, a)
				continue
			}
		}
		sub, rest = a, args[i+1:]
		break
	}
	if sub == "" {
		return t14ArgparseErr(baselineUsage, "baseline",
			"the following arguments are required: baseline_cmd")
	}
	if !containsStr(baselineChoices, sub) {
		return t14ArgparseErr(baselineUsage, "baseline",
			"argument baseline_cmd: invalid choice: %s "+
				"(choose from 'add', 'list', 'remove')", quoteSingle(sub))
	}
	sp, helpText, exec := baselineSpec(sub)
	sp.deferExtras = true // merged with parentExtras below
	if err := sp.parse(rest); err != nil {
		return err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, helpText)
		return nil
	}
	if all := append(parentExtras, sp.extras...); len(all) > 0 {
		return t14Unrecognized(strings.Join(all, " "))
	}
	return exec(sp, r)
}

// baselineSpec is the subparser for one `baseline <sub>` choice: its spec,
// its --help block, and its command body.
func baselineSpec(sub string) (*argSpec, string, func(*argSpec, *Runner) error) {
	switch sub {
	case "add":
		sp := &argSpec{
			prog:  "baseline add",
			usage: baselineAddUsage,
			vals: []*valOpt{
				{name: "--path", required: true},
				{name: "--source-url"},
				{name: "--license"},
			},
			pos: []*posOpt{{name: "name"}},
		}
		return sp, baselineAddHelp, baselineAdd
	case "remove":
		sp := &argSpec{prog: "baseline remove", usage: baselineRemoveUsage,
			pos: []*posOpt{{name: "name"}}}
		return sp, baselineRemoveHelp, baselineRemove
	}
	sp := &argSpec{prog: "baseline list", usage: baselineListUsage}
	return sp, baselineListHelp, baselineList
}

// containsStr is a small membership test over the choice list.
func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// quoteSingle is Python's repr for a short ASCII string.
func quoteSingle(s string) string { return "'" + s + "'" }

func baselineAdd(sp *argSpec, r *Runner) error {
	name := sp.pos[0].val
	path := pyPathText(sp.vals[0].val)
	var urlPtr, licPtr *string
	if sp.vals[1].seen {
		u := sp.vals[1].val
		urlPtr = &u
	}
	if sp.vals[2].seen {
		l := sp.vals[2].val
		licPtr = &l
	}
	meta, err := forkdiff.AddBaseline(name, path, urlPtr, licPtr)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "baseline %s: sha256 %s...\n", validation.ObjStr(meta, "name"),
		first16(validation.ObjStr(meta, "fingerprint_sha256")))
	return nil
}

func baselineList(_ *argSpec, r *Runner) error {
	rows, err := forkdiff.ListBaselines()
	if err != nil {
		return err
	}
	for _, m := range rows {
		line := fmt.Sprintf("%s: sha256 %s...", validation.ObjStr(m, "name"),
			first16(validation.ObjStr(m, "fingerprint_sha256")))
		if u := validation.ObjStr(m, "source_url"); u != "" {
			line += "  " + u
		}
		fmt.Fprintln(r.Out, line)
	}
	return nil
}

func baselineRemove(sp *argSpec, r *Runner) error {
	name := sp.pos[0].val
	// r7 (critic) asked whether a remove of a never-registered name is a
	// lie; the PINNED twin argparse golden (TestP3ArgparseGolden) answers:
	// remove is IDEMPOTENT ("rm -rf" semantics), stderr stays empty.
	// Diverging would break the byte-golden, and no other reader trusts
	// the claim, so the twin's line stands — the law is recorded here
	// rather than in a behavior change.
	if err := forkdiff.RemoveBaseline(name); err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "baseline %s removed\n", name)
	return nil
}

// first16 is Python's s[:16] slice.
func first16(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func init() {
	register(command{ord: 20, name: "baseline",
		line: "baseline {add,list,remove}        manage baseline reference trees",
		run:  runBaseline})
}
