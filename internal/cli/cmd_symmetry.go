package cli

// cmd_symmetry: `webv2 symmetry <campaign> [--family F] [--json]` — the
// primitive matrix (IMPROVEMENTS C2).
//
// The operator-facing half of probes.PrimitiveMatrix: for every inheritance
// family in the structural index, which custody primitive each member performs
// for each (direction, asset), and — the point of the verb — where siblings
// disagree. Two divergence kinds are rendered: member-disagreement (siblings
// using different primitives for the same direction and asset) and
// funding-mismatch (a forward path that mints or burns while a recovery path
// moves the asset out of a balance the member never held: the G-02 shape).
//
// Go-only verb (no Python twin): argparse semantics follow the house style
// (cmd_p3_args); the output is one block per family with its cells and the
// questions its divergences raise.

import (
	"fmt"
	"strings"

	"websec/internal/probes"
	"websec/internal/structidx"
	"websec/internal/validation"
)

const symmetryUsage = "usage: webv2 symmetry [-h] [--json] [--family FAMILY] campaign\n"

const symmetryHelp = symmetryUsage + `
print the custody-primitive matrix of a campaign's structural index: for each
inheritance family, the (direction, asset) cell every member implements, and
the divergences between members. Two kinds are reported:
  member-disagreement  siblings use different primitives for one (direction,
                       asset) — which of them is the custody model?
  funding-mismatch     a forward path mints/burns while a recovery path moves
                       the asset out of a balance the member never held — who
                       funds the difference?
A family with no disagreement prints its cells and no question: the matrix is
an obligation to look, never a claim.

positional arguments:
  campaign              campaign id

options:
  -h, --help            show this help message and exit
  --json                emit the matrix as JSON
  --family FAMILY       restrict the output to one family
`

func runSymmetry(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return symmetryCmd(root, args, r) })
}

func symmetryCmd(root string, args []string, r *Runner) error {
	sp := &argSpec{
		prog:  "symmetry",
		usage: symmetryUsage,
		vals:  []*valOpt{{name: "--family"}},
		flags: []*boolOpt{{name: "--json"}},
		pos:   []*posOpt{{name: "campaign"}},
	}
	if err := sp.parse(args); err != nil {
		return err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, symmetryHelp)
		return nil
	}
	family := sp.vals[0].val
	asJSON := sp.flags[0].set
	c, err := t14Open(root, sp.pos[0].val)
	if err != nil {
		return err
	}
	idx, err := structidx.LoadIndex(c)
	if err != nil {
		return err
	}
	matrix := probes.PrimitiveMatrix(idx)
	if family != "" {
		kept := []validation.Value{}
		for _, f := range objListAt(matrix, "families") {
			if validation.ObjStr(f, "name") == family {
				kept = append(kept, f)
			}
		}
		if len(kept) == 0 {
			return t14ExitErr(2, "symmetry: no inheritance family named %s in "+
				"the structural index\n", validation.PyReprStr(family))
		}
		matrix = filterSymmetryFamilies(matrix, kept)
	}
	if asJSON {
		fmt.Fprintln(r.Out, validation.DumpIndentedASCII(matrix))
		return nil
	}
	symmetryPrint(r, matrix)
	return nil
}

// filterSymmetryFamilies narrows a matrix to a family subset, keeping the
// stats block honest about what is shown.
func filterSymmetryFamilies(matrix validation.Value, kept []validation.Value) validation.Value {
	divs := []validation.Value{}
	for _, f := range kept {
		divs = append(divs, objListAt(f, "divergences")...)
	}
	stats := validation.ObjAt(matrix, "stats")
	return validation.VObj(
		validation.KV{K: "families", V: validation.VArr(kept...)},
		validation.KV{K: "divergences", V: validation.VArr(divs...)},
		validation.KV{K: "stats", V: validation.VObj(
			validation.KV{K: "families", V: validation.VInt(1)},
			validation.KV{K: "members", V: validation.ObjAt(stats, "members")},
			validation.KV{K: "sites", V: validation.ObjAt(stats, "sites")},
			validation.KV{K: "cells", V: validation.ObjAt(stats, "cells")},
			validation.KV{K: "divergences", V: validation.VInt(int64(len(divs)))},
			validation.KV{K: "filtered", V: validation.VBool(true)},
		)})
}

// symmetryPrint renders the matrix: one block per family, cells grouped by
// direction, then the divergences as questions.
func symmetryPrint(r *Runner, matrix validation.Value) {
	stats := validation.ObjAt(matrix, "stats")
	fmt.Fprintf(r.Out, "symmetry: %s famil%s, %s member(s), %s cell(s), "+
		"%s divergence(s)\n",
		pyIntText(validation.ObjAt(stats, "families")),
		pluralSuffix(pyIntText(validation.ObjAt(stats, "families")), "y", "ies"),
		pyIntText(validation.ObjAt(stats, "members")),
		pyIntText(validation.ObjAt(stats, "cells")),
		pyIntText(validation.ObjAt(stats, "divergences")))
	fams := objListAt(matrix, "families")
	if len(fams) == 0 {
		fmt.Fprintln(r.Out, "  no inheritance family carries a custody primitive "+
			"in this index")
		return
	}
	for _, f := range fams {
		fmt.Fprintf(r.Out, "  %s (%s)\n", validation.ObjStr(f, "name"),
			strings.Join(t14Strings(validation.ObjAt(f, "members")), ", "))
		byDirection := map[string][]string{}
		order := []string{}
		for _, c := range objListAt(f, "cells") {
			d := validation.ObjStr(c, "direction")
			if _, seen := byDirection[d]; !seen {
				order = append(order, d)
			}
			byDirection[d] = append(byDirection[d], fmt.Sprintf("%s %s %s.%s@%s",
				validation.ObjStr(c, "asset"), validation.ObjStr(c, "primitive"), validation.ObjStr(c, "contract"),
				validation.ObjStr(c, "function"), pyIntText(validation.ObjAt(c, "line"))))
		}
		for _, d := range order {
			fmt.Fprintf(r.Out, "    %-10s %s\n", d+":",
				strings.Join(byDirection[d], "; "))
		}
		divs := objListAt(f, "divergences")
		if len(divs) == 0 {
			continue
		}
		for _, d := range divs {
			fmt.Fprintf(r.Out, "    ! %s: %s\n", validation.ObjStr(d, "kind"),
				validation.ObjStr(d, "question"))
		}
	}
}

// pluralSuffix is the naive plural used by the headline counts.
func pluralSuffix(n, one, many string) string {
	if n == "1" {
		return one
	}
	return many
}

func init() {
	register(command{ord: 74, name: "symmetry",
		line: "symmetry <campaign>             family custody-primitive matrix",
		run:  runSymmetry})
}
