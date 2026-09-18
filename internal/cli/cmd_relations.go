package cli

// cmd_relations: `webv2 relations <campaign> [--rebuild]` — the research
// memory graph: stored typed edges, grouped by kind (cli.py cmd_relations
// verbatim). --rebuild re-derives the deterministic edges first and says how
// many were new.

import (
	"fmt"

	"websec/internal/relations"
	"websec/internal/validation"
)

const relationsUsage = "usage: webv2 relations [-h] [--rebuild] campaign\n"

// relationsHelp is argparse's `webv2 relations --help` output, byte-exact.
const relationsHelp = `usage: webv2 relations [-h] [--rebuild] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
  --rebuild   re-derive deterministic edges first
`

func runRelations(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{
			prog:  "relations",
			usage: relationsUsage,
			flags: []*boolOpt{{name: "--rebuild"}},
			pos:   []*posOpt{{name: "campaign"}},
		}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, relationsHelp)
			return nil
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		if sp.flags[0].set {
			n, err := relations.MintAllDeterministic(c)
			if err != nil {
				return err
			}
			fmt.Fprintf(r.Out, "re-derived deterministic edges: %d new\n", n)
		}
		v, err := relations.GraphView(c)
		if err != nil {
			return err
		}
		fmt.Fprintf(r.Out, "edges: %s\n", pyIntText(validation.ObjAt(v, "edge_count")))
		byKind := validation.ObjAt(v, "by_kind")
		policies := validation.ObjAt(v, "policies")
		for _, entry := range byKind.O {
			kind := entry.K
			edges := entry.V.A
			fmt.Fprintf(r.Out, "  %s (%s): %d\n", kind,
				validation.ObjStr(policies, kind), len(edges))
			for _, e := range edges {
				sup := ""
				if support := validation.ObjAt(e, "support"); support.Kind != validation.Null {
					sup = firstNonEmpty(validation.ObjStr(support, "chain_id"),
						validation.ObjStr(support, "evidence_id"),
						validation.ObjStr(support, "pin"),
						validation.ObjStr(support, "memory_id"),
						validation.ObjStr(support, "commit"), "attested")
				}
				who := ""
				if actor := validation.ObjAt(e, "actor"); actor.Kind == validation.Str &&
					actor.S != "" {
					who = " [actor " + actor.S + "]"
				}
				if sup == "" {
					sup = "n/a"
				}
				fmt.Fprintf(r.Out, "    %s -> %s  (anchor: %s)%s\n",
					validation.ObjStr(validation.ObjAt(e, "src"), "id"),
					validation.ObjStr(validation.ObjAt(e, "dst"), "id"), sup, who)
			}
		}
		return nil
	})
}

// firstNonEmpty is Python's `a or b or ... or fallback`.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func init() {
	register(command{ord: 13, name: "relations",
		line: "relations <campaign> [--rebuild]  research memory graph (typed edges)",
		run:  runRelations})
}
