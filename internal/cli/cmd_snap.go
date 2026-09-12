package cli

// cmd_snap: `webv2 snap <campaign> <target> [--deployment F] [--chain F]
// [--exclude GLOB...]` — pin a source snapshot (cli.py cmd_snap
// verbatim, P0 flags only).

import (
	"fmt"
	"io"
	"os"
	"strings"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func runSnap(root string, args []string, stdout io.Writer) error {
	if helpRequested(stdout, "snap", args) {
		return nil
	}

	var pos []string
	var deployment, chain string
	var excludes []string
	dryRun := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--dry-run":
			dryRun = true
		case a == "--deployment" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			deployment = args[i+1]
			i++
		case strings.HasPrefix(a, "--deployment="):
			deployment = strings.TrimPrefix(a, "--deployment=")
		case a == "--chain" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			chain = args[i+1]
			i++
		case strings.HasPrefix(a, "--chain="):
			chain = strings.TrimPrefix(a, "--chain=")
		case a == "--exclude" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			excludes = append(excludes, args[i+1])
			i++
		case strings.HasPrefix(a, "--exclude="):
			excludes = append(excludes, strings.TrimPrefix(a, "--exclude="))
		case strings.HasPrefix(a, "-"):
			return usageErrf("unrecognized arguments: %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 2 {
		return usageErrf("snap requires <campaign> <target> arguments")
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	var extra []string
	for _, spec := range excludes {
		for _, s := range strings.Split(spec, ",") {
			if s = strings.TrimSpace(s); s != "" {
				extra = append(extra, s)
			}
		}
	}
	// M2: dry-run stages, prunes and hashes exactly like the pin and
	// reports the preview — recording nothing (no snapshot dir, no
	// manifest, no events).
	if dryRun {
		return snapDryRun(stdout, pos[1], extra, deployment, chain)
	}
	snap, err := snapshot.PinSourceSnapshot(c, pos[1], nil, extra)
	if err != nil {
		return err
	}
	src := objAt(snap, "source")
	fmt.Fprintf(stdout, "pinned %s (%s, %d files)\n",
		objStr(snap, "snapshot_id"), objStr(src, "ladder"), objInt(src, "file_count"))
	if cfg := objAt(snap, "config"); cfg.Kind == validation.Obj && len(cfg.O) > 0 {
		fmt.Fprintf(stdout, "  toolchain: %s — solc %s (detected from the pinned tree)\n",
			objStr(cfg, "build_system"), objStr(cfg, "compiler"))
	}
	if excl := objAt(src, "excluded"); excl.Kind == validation.Arr && len(excl.A) > 0 {
		var names []string
		for _, e := range excl.A {
			if e.Kind == validation.Str {
				names = append(names, e.S)
			}
		}
		fmt.Fprintf(stdout, "  EXCLUDED from the pin (bulk defaults + --exclude): %s — the pin does NOT cover these; "+
			"re-pin without the prune if any of them is in scope\n", strings.Join(names, ", "))
	}
	if deployment != "" {
		snap, err = attachDeployment(c, snap, deployment)
		if err != nil {
			return err
		}
		dep := objAt(snap, "deployment")
		n := 0
		if contracts := objAt(dep, "contracts"); contracts.Kind == validation.Arr {
			n = len(contracts.A)
		}
		fmt.Fprintf(stdout, "  deployment: %s (%d contracts)\n", objStr(dep, "network"), n)
	}
	if chain != "" {
		snap, err = attachChain(c, snap, chain)
		if err != nil {
			return err
		}
		ch := objAt(snap, "chain")
		fmt.Fprintf(stdout, "  chain: %s @ %s\n", scalarStr(objAt(ch, "chain_id")), scalarStr(objAt(ch, "fork_block")))
	}
	// M5: untracked files inside the pinned tree. Covered by copytree
	// pins, silently dropped by the git-clean worktree — either way the
	// operator names what the pin did with them.
	if total, names := untrackedSummary(snapshot.UntrackedInTarget(pos[1], extra)); total > 0 {
		covered := "covered by this pin but not in git"
		if objStr(objAt(snap, "source"), "ladder") == "git-clean" {
			covered = "NOT covered by this git-clean pin (the worktree " +
				"pins the commit, not the workdir)"
		}
		fmt.Fprintf(stdout, "  WARNING: %d untracked file(s) in the target: "+
			"%s — %s; re-pin after cleanup if any is litter (or evidence "+
			"you meant to keep)\n", total, names, covered)
	}
	return nil
}

// snapDryRun renders the M2 preview: ladder, would-be id, prune set,
// matched paths, and untracked entries — with nothing recorded.
// Deployment/chain attaches are post-pin steps; the dry run names them
// as skipped rather than silently ignoring the flags.
func snapDryRun(w io.Writer, target string, extra []string, deployment, chain string) error {
	p, err := snapshot.DryRunPin(target, extra)
	if err != nil {
		return err
	}
	hash := p.ContentHash
	if len(hash) > 12 {
		hash = hash[:12]
	}
	fmt.Fprintf(w, "dry-run: %s — nothing recorded\n", p.Target)
	fmt.Fprintf(w, "  ladder: %s, would-be snapshot: %s (%d files, content %s)\n",
		p.Ladder, p.SnapshotID, p.FileCount, hash)
	fmt.Fprintf(w, "  prune names (%d): %s\n", len(p.PruneNames),
		strings.Join(p.PruneNames, ", "))
	// The path dump carries the package's console cap (consoleRowCap, see
	// cmd_probes.go): a monorepo can match hundreds of prune names, and one
	// line of hundreds of paths is unreadable. A small dump keeps the compact
	// one-line form; past the cap it becomes one path per row plus the
	// pointer to the complete table.
	switch {
	case len(p.PrunedPaths) == 0:
		fmt.Fprintf(w, "  pruned paths (0): none matched in target\n")
	case len(p.PrunedPaths) <= consoleRowCap:
		fmt.Fprintf(w, "  pruned paths (%d): %s\n", len(p.PrunedPaths),
			strings.Join(p.PrunedPaths, ", "))
	default:
		fmt.Fprintf(w, "  pruned paths (%d):\n", len(p.PrunedPaths))
		for _, path := range p.PrunedPaths[:consoleRowCap] {
			fmt.Fprintf(w, "    %s\n", path)
		}
		fmt.Fprintf(w, "  … +%d more rows — use --json for the full table\n",
			len(p.PrunedPaths)-consoleRowCap)
	}
	if total, names := untrackedSummary(p.Untracked, p.UntrackedMore); total > 0 {
		covered := "would be covered by this pin but are not in git"
		if p.Ladder == "git-clean" {
			covered = "would NOT be covered by this git-clean pin " +
				"(the worktree pins the commit, not the workdir)"
		}
		fmt.Fprintf(w, "  untracked (%d): %s — %s\n", total, names, covered)
	} else {
		fmt.Fprintf(w, "  untracked: none\n")
	}
	if skipped := skippedAttaches(deployment, chain); skipped != "" {
		fmt.Fprintf(w, "  skipped in dry-run (post-pin attaches): %s\n", skipped)
	}
	return nil
}

// skippedAttaches names the attach flags a dry run does not perform.
func skippedAttaches(deployment, chain string) string {
	out := []string{}
	if deployment != "" {
		out = append(out, "--deployment")
	}
	if chain != "" {
		out = append(out, "--chain")
	}
	return strings.Join(out, ", ")
}

// untrackedSummary renders the capped untracked list with its true total.
func untrackedSummary(listed []string, more int) (int, string) {
	total := len(listed) + more
	names := strings.Join(listed, ", ")
	if more > 0 {
		names += fmt.Sprintf(" (+%d more)", more)
	}
	return total, names
}

func attachDeployment(c *state.Campaign, snap validation.Value, path string) (validation.Value, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return validation.VNull(), err
	}
	dep, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.VNull(), err
	}
	return snapshot.AttachDeploymentPin(c, objStr(snap, "snapshot_id"), dep)
}

func attachChain(c *state.Campaign, snap validation.Value, path string) (validation.Value, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return validation.VNull(), err
	}
	ch, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.VNull(), err
	}
	return snapshot.AttachChainPin(c, objStr(snap, "snapshot_id"), ch)
}

func init() {
	register(command{ord: 48, name: "snap",
		line: `snap <campaign> <target> [--deployment F] [--chain F] [--exclude GLOB] [--dry-run]
                        pin a source snapshot`,
		run: func(root string, args []string, r *Runner) int {
			return r.withErr(root, func() error { return runSnap(root, args, r.Out) })
		}})
}
