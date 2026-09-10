package cli

// cmd_artifact_reconcile: `webv2 artifact-reconcile <campaign> [--dry]` —
// re-hash every registered artifact against its file and refresh the rows whose
// file changed (D3). The audit's artifacts section re-hashes every row, so a
// file rewritten by anything other than the tool (a hand-edited report, an
// external exporter) keeps the whole audit red until the registry is brought
// back in line; this is the operator's escape hatch, and `--dry` shows the
// damage without touching state.
//
// Naming: the D3 design sketch called this `artifacts reconcile`; it landed as
// a flat sibling of artifact-register/artifact-list, because every other verb
// in this CLI is flat and a subcommand layer for one verb would be the odd one.
// The singular `artifact-*` prefix matches the two existing verbs.

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

const artifactReconcileUsage = "usage: webv2 artifact-reconcile [-h] [--dry] " +
	"campaign\n"

const artifactReconcileHelp = artifactReconcileUsage + `
re-hash every registered artifact against its file. A row whose file changed
since registration is refreshed; a row whose file is gone is reported; an
unchanged row is left alone. The audit re-hashes every row, so a file rewritten
by anything other than the tool (a hand-edited report, an external exporter)
keeps the whole audit red until this brings the registry back in line.

positional arguments:
  campaign              campaign id

options:
  -h, --help            show this help message and exit
  --dry                 report what would be refreshed, change nothing
`

func runArtifactReconcile(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return artifactReconcileCmd(root, args, r) })
}

func artifactReconcileCmd(root string, args []string, r *Runner) error {
	sp := &argSpec{
		prog:  "artifact-reconcile",
		usage: artifactReconcileUsage,
		flags: []*boolOpt{{name: "--dry"}},
		pos:   []*posOpt{{name: "campaign"}},
	}
	if err := sp.parse(args); err != nil {
		return err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, artifactReconcileHelp)
		return nil
	}
	c, err := state.Open(root, sp.pos[0].val)
	if err != nil {
		return err
	}
	dry := sp.flags[0].set
	res, err := c.ReconcileArtifacts(dry)
	if err != nil {
		return err
	}
	verb := "refreshed"
	if dry {
		verb = "would refresh"
	}
	ids := objAt(res, "refreshed").A
	checked := objAt(res, "checked").I
	unchanged := objAt(res, "unchanged").I
	missing := objAt(res, "missing").A
	fmt.Fprintf(r.Out, "artifact reconcile: %d checked, %d %s, %d unchanged, "+
		"%d missing\n", checked, len(ids), verb, unchanged, len(missing))
	for _, id := range ids {
		fmt.Fprintf(r.Out, "  %s\n", idText(id))
	}
	for _, m := range missing {
		fmt.Fprintf(r.Out, "  missing %s  %s\n", objStr(m, "artifact_id"),
			objStr(m, "path"))
	}
	return nil
}

// idText is the bare string of a value the registry already knows is an id.
func idText(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.DumpIndented(v)
}

func init() {
	register(command{ord: 75, name: "artifact-reconcile",
		line: "artifact-reconcile <campaign> [--dry]  re-hash registered " +
			"artifacts",
		run: runArtifactReconcile})
}
