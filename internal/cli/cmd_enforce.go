package cli

// cmd_enforce: `webv2 enforce <campaign> <variable|concept> [--contract C]
// [--json]` — the enforcement-timing table for one storage variable
// (IMPROVEMENTS C1).
//
// The verb is the operator-facing half of structidx.EnforcementTable: it
// answers, for one name, where the value is written, where it is read, which
// of those sites is guarded by what, at which call-graph depth each site sits,
// and which (write, read) stage pairs no assertion covers. That is the
// deterministic backbone of the G-01 class ("the value is read here, read
// again a stage later, and nothing in the index ever writes or checks it") —
// a row, not a hypothesis the model has to stumble onto.
//
// Go-only verb (no Python twin): argparse semantics follow the house style
// (cmd_p3_args), and the output is one line per site plus the signals.

import (
	"fmt"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

const enforceUsage = "usage: webv2 enforce [-h] [--json] [--contract CONTRACT] campaign name\n"

// enforceHelp is the argparse-style help block. This verb is Go-only, so the
// prose is ours; the wrapping follows argparse's 80-column house style.
const enforceHelp = enforceUsage + `
print the enforcement-timing table for one storage variable or concept key:
every write and read site in the structural index, ordered by call-graph
depth from an entry point, each with the assertions its containing function
carries, plus the (write, read) stage pairs that no assertion about the
variable covers. A name the index knows as a storage variable is matched as
one; anything else is tokenized the way the index tokenizes expressions, so
"fee accumulator" finds the same sites as "feeAccumulator".

positional arguments:
  campaign              campaign id
  name                  storage variable name or concept key

options:
  -h, --help            show this help message and exit
  --json                emit the table as JSON
  --contract CONTRACT   restrict the table to this contract
`

func runEnforce(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return enforceCmd(root, args, r) })
}

func enforceCmd(root string, args []string, r *Runner) error {
	sp := &argSpec{
		prog:  "enforce",
		usage: enforceUsage,
		vals:  []*valOpt{{name: "--contract"}},
		flags: []*boolOpt{{name: "--json"}},
		pos:   []*posOpt{{name: "campaign"}, {name: "name"}},
	}
	if err := sp.parse(args); err != nil {
		return err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, enforceHelp)
		return nil
	}
	contract := sp.vals[0].val
	asJSON := sp.flags[0].set
	c, err := t14Open(root, sp.pos[0].val)
	if err != nil {
		return err
	}
	idx, err := structidx.LoadIndex(c)
	if err != nil {
		return err
	}
	name := sp.pos[1].val
	tbl := structidx.EnforcementTableOpts(idx, name,
		structidx.EnforcementOpts{Contract: contract})
	if contract != "" && len(objListAt(tbl, "sites")) == 0 {
		return t14ExitErr(2, "enforce: no write or read site for %s in "+
			"contract %s\n", validation.PyReprStr(name), contract)
	}
	if asJSON {
		fmt.Fprintln(r.Out, validation.DumpIndentedASCII(tbl))
		return nil
	}
	enforcePrint(r, tbl, name)
	return nil
}

// enforcePrint renders the table: the headline, one line per site, the
// signals and the stage-pair count.
func enforcePrint(r *Runner, tbl validation.Value, name string) {
	stats := objAt(tbl, "stats")
	head := fmt.Sprintf("enforce: %s — %s match, %s site(s) (%s write, %s read), ordering: %s",
		name, objStr(tbl, "match"), pyIntText(objAt(stats, "sites")),
		pyIntText(objAt(stats, "writes")), pyIntText(objAt(stats, "reads")),
		objStr(tbl, "ordering"))
	if note := objStr(tbl, "note"); note != "" {
		head += " (" + note + ")"
	}
	fmt.Fprintln(r.Out, head)
	if len(objListAt(tbl, "sites")) == 0 {
		fmt.Fprintf(r.Out, "  no site reads or writes %s (concept keys tried: %s)\n",
			name, strings.Join(t14Strings(objAt(tbl, "concept_keys")), ", "))
		return
	}
	for _, s := range objListAt(tbl, "sites") {
		depth := "-"
		if d := objAt(s, "depth"); d.Kind == validation.Int {
			depth = pyIntText(d)
		}
		entry := ""
		if b := objAt(s, "is_entry_point"); b.Kind == validation.Bool && b.B {
			entry = " entry"
		}
		fmt.Fprintf(r.Out, "  %-5s %s.%s@%s  depth %s%s  %s\n",
			objStr(s, "kind"), objStr(s, "contract"), objStr(s, "function"),
			pyIntText(objAt(s, "line")), depth, entry,
			enforceGuardText(s, name))
	}
	if sigs := objListAt(tbl, "signals"); len(sigs) > 0 {
		fmt.Fprintln(r.Out, "signals:")
		for _, s := range sigs {
			fmt.Fprintf(r.Out, "  - %s: %s\n", objStr(s, "signal"),
				objStr(s, "detail"))
		}
	}
	fmt.Fprintf(r.Out, "stages: %s (write, read) pair(s), %s with an unguarded "+
		"write, %s open on both ends\n",
		pyIntText(objAt(stats, "stage_pairs")),
		pyIntText(objAt(stats, "stage_gaps")),
		pyIntText(objAt(stats, "stage_open_gaps")))
}

// enforceGuardText describes a site's assertions relative to the queried
// variable: the ones about it (capped at two, with a count of the rest) when
// there are any, else the count of assertions about something else.
func enforceGuardText(site validation.Value, name string) string {
	about := []string{}
	others := 0
	for _, g := range objListAt(site, "guards") {
		if b := objAt(g, "about_variable"); b.Kind == validation.Bool && b.B {
			about = append(about, fmt.Sprintf("class %s %s",
				pyIntText(objAt(g, "class")), objStr(g, "text")))
			continue
		}
		others++
	}
	if len(about) == 0 {
		if others == 0 {
			return "guards: none"
		}
		return fmt.Sprintf("guards: %d, none about %s", others, name)
	}
	text := "guard " + strings.Join(about[:min(2, len(about))], "; ")
	if len(about) > 2 {
		text += fmt.Sprintf(" (+%d more)", len(about)-2)
	}
	if others > 0 {
		text += fmt.Sprintf(" (+%d other)", others)
	}
	return text
}

func init() {
	register(command{ord: 73, name: "enforce",
		line: "enforce <campaign> <var>         write/read stage table for one variable",
		run:  runEnforce})
}
