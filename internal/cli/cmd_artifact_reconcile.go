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
//
// T3: the report also names invariant-status drift between the protocol model
// and the ledger registry (the gate's source of truth). Reported, never
// written — see invariants.ModelStatusDrift.

import (
	"fmt"
	"path/filepath"

	"websec/internal/invariants"
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
A protocol model that claims a verification status the ledger registry does not
hold is reported as drift (invariant INV-1: model.json says X, ledger says Y —
ledger governs); the model file is never rewritten.

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
	// T3: name model.json↔ledger invariant-status drift. The gate reads the
	// ledger registry, which records the model's claimed status as DATA and
	// keeps UNVERIFIED until verify/contradict moves it with a log-anchored
	// verdict — so a cheap agent writing CONTRADICTED into the model changes
	// nothing the gate reads. Read-only on purpose: the ledger governs and the
	// model file has one writer (`webv2 model`), so this only says so.
	drift, err := invariants.ModelStatusDrift(c, reconcileModel(c))
	if err != nil {
		return err
	}
	for _, d := range drift {
		fmt.Fprintf(r.Out, "invariant %s: model.json says %s, ledger says %s "+
			"— ledger governs\n", d.InvariantID, d.ModelStatus, d.LedgerStatus)
	}
	return nil
}

// reconcileModel is the protocol model on disk, or Null when there is none or
// it cannot be read: with no model file the reconcile report is byte-for-byte
// what it was before the drift check existed.
func reconcileModel(c *state.Campaign) validation.Value {
	p := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if !t29FileExists(p) {
		return validation.VNull()
	}
	m, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull()
	}
	return m
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
