package cli

// cmd_snap: `webv2 snap <campaign> <target> [--deployment F] [--chain F]
// [--exclude NAME...]` — pin a source snapshot (cli.py cmd_snap
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

// excludedInlineCap bounds the exclusion SUMMARY a pin/re-pin prints: past
// this many pruned paths the console names the exact count and the first
// excludedInlineCap paths and leaves the rest to the record object. At or
// under the cap the list is printed whole (Task 8).
const excludedInlineCap = 10

// snapCmd carries one runSnap invocation's parsed arguments and staged
// snapshot; the extracted stages below are its methods, called by the
// orchestrator in the original body's order.
type snapCmd struct {
	root       string
	stdout     io.Writer
	pos        []string
	deployment string
	chain      string
	excludes   []string
	dryRun     bool
	asJSON     bool
	extra      []string
	c          *state.Campaign
	snap       validation.Value
}

func runSnap(root string, args []string, stdout io.Writer) error {
	if helpRequested(stdout, "snap", args) {
		return nil
	}
	sc := &snapCmd{root: root, stdout: stdout}
	if err := sc.snapParseArgs(args); err != nil {
		return err
	}
	if err := sc.snapOpenCampaign(); err != nil {
		return err
	}
	sc.snapSplitExcludes()
	// M2: dry-run stages, prunes and hashes exactly like the pin and
	// reports the preview — recording nothing (no snapshot dir, no
	// manifest, no events).
	if sc.dryRun {
		return snapDryRun(stdout, sc.pos[1], sc.extra, sc.deployment, sc.chain, sc.asJSON)
	}
	if err := sc.snapRefuseEmptyPin(); err != nil {
		return err
	}
	if err := sc.snapPinTarget(); err != nil {
		return err
	}
	if err := sc.snapRefuseZeroFiles(); err != nil {
		return err
	}
	sc.snapPrintPinned()
	sc.snapPrintSymlinkNote()
	sc.snapPrintToolchain()
	sc.snapPrintExcluded()
	if err := sc.snapAttachDeploymentFlag(); err != nil {
		return err
	}
	if err := sc.snapAttachChainFlag(); err != nil {
		return err
	}
	sc.snapPrintUntracked()
	return nil
}

func (sc *snapCmd) snapParseArgs(args []string) error {
	var pos []string
	var deployment, chain string
	var excludes []string
	dryRun := false
	asJSON := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--dry-run":
			dryRun = true
		case a == "--json":
			asJSON = true
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
	// --json is the machine-readable dry-run table (see snapDryRun);
	// a mutating pin keeps its human summary, so the flag refuses there
	// rather than being silently ignored.
	if asJSON && !dryRun {
		return usageErrf("--json applies to snap --dry-run only")
	}
	sc.pos, sc.deployment, sc.chain = pos, deployment, chain
	sc.excludes = excludes
	sc.dryRun, sc.asJSON = dryRun, asJSON
	return nil
}

func (sc *snapCmd) snapOpenCampaign() error {
	c, err := state.Open(sc.root, sc.pos[0])
	if err != nil {
		return err
	}
	sc.c = c
	return nil
}

func (sc *snapCmd) snapSplitExcludes() {
	var extra []string
	for _, spec := range sc.excludes {
		for _, s := range strings.Split(spec, ",") {
			if s = strings.TrimSpace(s); s != "" {
				extra = append(extra, s)
			}
		}
	}
	sc.extra = extra
}

// snapRefuseEmptyPin is the R3 pre-scan refusal: a pin that provably pins
// zero files is refused before anything is staged or recorded.
func (sc *snapCmd) snapRefuseEmptyPin() error {
	// R3 (critic): the zero-file refusal must PRECEDE the pin — a refused
	// operation may not leave snapshot dirs, events, or an active_snapshot
	// projection behind. The pre-scan is a conservative lower bound on the
	// on-disk tree (exact on the no-vcs/git-dirty copytree ladder; a
	// git-clean pin stages from tracked files and may legitimately hold
	// more than the working tree shows, so a matching tracked file cannot
	// be disproved here — the post-pin check below stays as the backstop
	// and prints the honest "refused after staging" line instead of a
	// silent success if the lower bound was wrong).
	if pre, perr := snapshot.PinWillBeEmpty(sc.pos[1], sc.extra); perr == nil && pre {
		return fmt.Errorf("target pins 0 files — empty tree or every entry " +
			"matched --exclude (excludes are exact base names, not globs); " +
			"nothing was recorded")
	}
	return nil
}

// snapPinTarget stages the pin and echoes the --exclude patterns that
// matched nothing (the R2 rail against silently pinning nothing-pruned).
func (sc *snapCmd) snapPinTarget() error {
	snap, err := snapshot.PinSourceSnapshot(sc.c, sc.pos[1], nil, sc.extra)
	if err != nil {
		return err
	}
	sc.snap = snap
	// R2 (critic): --exclude matches EXACT base names (the ported
	// ignore-pattern law), so a glob-looking or typo'd pattern can silently
	// pin nothing-pruned. Echo what matched; name what matched nothing.
	if len(sc.extra) > 0 {
		matched := snapshot.MatchedExcludes(sc.pos[1], sc.extra)
		var silent []string
		for _, x := range sc.extra {
			if !matched[x] {
				silent = append(silent, x)
			}
		}
		if len(silent) > 0 {
			fmt.Fprintf(sc.stdout, "note: --exclude matched nothing: %s "+
				"(patterns are exact file/dir BASE names, not globs)\n",
				strings.Join(silent, ", "))
		}
	}
	return nil
}

// snapRefuseZeroFiles is the R2-2 post-pin backstop: a pin that captured
// zero files is refused with the residue disclosed.
func (sc *snapCmd) snapRefuseZeroFiles() error {
	src := validation.ObjAt(sc.snap, "source")
	// R2-2 (critic): a pin that captures zero files proves nothing about
	// any target — empty tree or over-broad excludes. Python stored the
	// empty snapshot; this CLI refuses it (divergence is a refusal, never
	// a silent success).
	if objInt(src, "file_count") == 0 {
		// The lower bound missed it (git-clean ladder staging from tracked
		// files that the walk could not see): fail CLOSED, and say so —
		// the residue is disclosed, never hidden behind a usage error.
		return fmt.Errorf("target pinned 0 files — empty tree or every " +
			"entry matched --exclude; the snapshot was staged and recorded, " +
			"delete it with `webv2 doctor` review before re-pinning")
	}
	return nil
}

// snapPrintPinned is the one-line pin summary.
func (sc *snapCmd) snapPrintPinned() {
	src := validation.ObjAt(sc.snap, "source")
	fmt.Fprintf(sc.stdout, "pinned %s (%s, %d files)\n",
		validation.ObjStr(sc.snap, "snapshot_id"), validation.ObjStr(src, "ladder"), objInt(src, "file_count"))
}

// snapPrintSymlinkNote names every escaping link the pin took as a link.
func (sc *snapCmd) snapPrintSymlinkNote() {
	src := validation.ObjAt(sc.snap, "source")
	if root := validation.ObjStr(src, "root"); root != "" {
		if links, err := snapshot.PinnedSymlinks(root); err == nil && len(links) > 0 {
			// r14/r15: custody is a claim, so the pin says exactly what
			// it does NOT take — every escaping link by name (a bare
			// count hid which file to materialize; note also that a
			// RELATIVE target resolves differently once the copy lives
			// under snapshots/<id>/).
			word := "entries"
			if len(links) == 1 {
				word = "entry"
			}
			shown := links
			if len(shown) > 5 {
				shown = append(append([]string{}, shown[:5]...),
					fmt.Sprintf("… and %d more", len(links)-5))
			}
			fmt.Fprintf(sc.stdout, "  note: %d pinned %s symlinked (copied "+
				"as links, hashed as links — outside bytes are NOT in "+
				"custody; relative targets resolve from the store): "+
				"%s\n  materialize (cp -rL) first if the pin must stand "+
				"alone\n", len(links), word, strings.Join(shown, ", "))
		}
	}
}

// snapPrintToolchain names the build system and compiler detected from the
// pinned tree.
func (sc *snapCmd) snapPrintToolchain() {
	if cfg := validation.ObjAt(sc.snap, "config"); cfg.Kind == validation.Obj && len(cfg.O) > 0 {
		fmt.Fprintf(sc.stdout, "  toolchain: %s — solc %s (detected from the pinned tree)\n",
			validation.ObjStr(cfg, "build_system"), validation.ObjStr(cfg, "compiler"))
	}
}

// snapPrintExcluded renders the prune list under the console cap (Task 8).
func (sc *snapCmd) snapPrintExcluded() {
	src := validation.ObjAt(sc.snap, "source")
	if excl := validation.ObjAt(src, "excluded"); excl.Kind == validation.Arr && len(excl.A) > 0 {
		var names []string
		for _, e := range excl.A {
			if e.Kind == validation.Str {
				names = append(names, e.S)
			}
		}
		// Task 8: the prune list is SCOPE, not a console dump — a monorepo
		// re-pin can match hundreds of paths, and one line holding all of
		// them is unreadable. Past excludedInlineCap the console prints the
		// exact count and the first cap paths, and points at the record;
		// the complete list stays in the record object (snapshot.json
		// source.excluded, mirrored by the snapshot.excluded event). At or
		// under the cap nothing is hidden: every path is named inline.
		if len(names) > excludedInlineCap {
			fmt.Fprintf(sc.stdout, "  EXCLUDED from the pin (bulk defaults + "+
				"--exclude): %d paths excluded (first %d): %s (+%d more — "+
				"the full list is in the record's source.excluded) — the "+
				"pin does NOT cover these; re-pin without the prune if any "+
				"of them is in scope\n", len(names), excludedInlineCap,
				strings.Join(names[:excludedInlineCap], ", "),
				len(names)-excludedInlineCap)
		} else {
			fmt.Fprintf(sc.stdout, "  EXCLUDED from the pin (bulk defaults + "+
				"--exclude): %s — the pin does NOT cover these; re-pin "+
				"without the prune if any of them is in scope\n",
				strings.Join(names, ", "))
		}
	}
}

// snapAttachDeploymentFlag attaches the --deployment file and prints its
// summary line.
func (sc *snapCmd) snapAttachDeploymentFlag() error {
	if sc.deployment != "" {
		snap, err := attachDeployment(sc.c, sc.snap, sc.deployment)
		if err != nil {
			return err
		}
		sc.snap = snap
		dep := validation.ObjAt(snap, "deployment")
		n := 0
		if contracts := validation.ObjAt(dep, "contracts"); contracts.Kind == validation.Arr {
			n = len(contracts.A)
		}
		fmt.Fprintf(sc.stdout, "  deployment: %s (%d contracts)\n", validation.ObjStr(dep, "network"), n)
	}
	return nil
}

// snapAttachChainFlag attaches the --chain file and prints its summary line.
func (sc *snapCmd) snapAttachChainFlag() error {
	if sc.chain != "" {
		snap, err := attachChain(sc.c, sc.snap, sc.chain)
		if err != nil {
			return err
		}
		sc.snap = snap
		ch := validation.ObjAt(snap, "chain")
		fmt.Fprintf(sc.stdout, "  chain: %s @ %s\n", scalarStr(validation.ObjAt(ch, "chain_id")), scalarStr(validation.ObjAt(ch, "fork_block")))
	}
	return nil
}

// snapPrintUntracked is the M5 disclosure: untracked files inside the
// pinned tree, covered or not by the pin's ladder.
func (sc *snapCmd) snapPrintUntracked() {
	// M5: untracked files inside the pinned tree. Covered by copytree
	// pins, silently dropped by the git-clean worktree — either way the
	// operator names what the pin did with them.
	if total, names := untrackedSummary(snapshot.UntrackedInTarget(sc.pos[1], sc.extra)); total > 0 {
		covered := "covered by this pin but not in git"
		if validation.ObjStr(validation.ObjAt(sc.snap, "source"), "ladder") == "git-clean" {
			covered = "NOT covered by this git-clean pin (the worktree " +
				"pins the commit, not the workdir)"
		}
		fmt.Fprintf(sc.stdout, "  WARNING: %d untracked file(s) in the target: "+
			"%s — %s; re-pin after cleanup if any is litter (or evidence "+
			"you meant to keep)\n", total, names, covered)
	}
}

// snapDryRun renders the M2 preview: ladder, would-be id, prune set,
// matched paths, and untracked entries — with nothing recorded.
// Deployment/chain attaches are post-pin steps; the dry run names them
// as skipped rather than silently ignoring the flags. With --json the
// same preview is emitted as one machine-readable JSON object (the full
// pruned-paths table, no console cap) and nothing else.
func snapDryRun(w io.Writer, target string, extra []string, deployment, chain string, asJSON bool) error {
	p, err := snapshot.DryRunPin(target, extra)
	if err != nil {
		return err
	}
	if asJSON {
		skipped := []string{}
		if deployment != "" {
			skipped = append(skipped, "--deployment")
		}
		if chain != "" {
			skipped = append(skipped, "--chain")
		}
		t14PrintJSON(w, validation.VObj(
			validation.KV{K: "dry_run", V: validation.VBool(true)},
			validation.KV{K: "target", V: validation.VStr(p.Target)},
			validation.KV{K: "ladder", V: validation.VStr(p.Ladder)},
			validation.KV{K: "snapshot_id", V: validation.VStr(p.SnapshotID)},
			validation.KV{K: "file_count", V: validation.VInt(int64(p.FileCount))},
			validation.KV{K: "content_hash", V: validation.VStr(p.ContentHash)},
			validation.KV{K: "prune_names", V: strListValue(p.PruneNames)},
			validation.KV{K: "pruned_paths", V: strListValue(p.PrunedPaths)},
			validation.KV{K: "untracked", V: strListValue(p.Untracked)},
			validation.KV{K: "untracked_more", V: validation.VInt(int64(p.UntrackedMore))},
			validation.KV{K: "skipped_attaches", V: strListValue(skipped)}))
		return nil
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
	return snapshot.AttachDeploymentPin(c, validation.ObjStr(snap, "snapshot_id"), dep)
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
	return snapshot.AttachChainPin(c, validation.ObjStr(snap, "snapshot_id"), ch)
}

func init() {
	register(command{ord: 48, name: "snap",
		line: `snap <campaign> <target> [--deployment F] [--chain F] [--exclude NAME] [--dry-run]
                        pin a source snapshot`,
		run: func(root string, args []string, r *Runner) int {
			return r.withErr(root, func() error { return runSnap(root, args, r.Out) })
		}})
}
