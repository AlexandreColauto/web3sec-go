package cli

// cmd_artifact_register: `webv2 artifact-register <campaign> <path>
// [--kind K] [--note N]` — register an artifact by path (cli.py
// cmd_artifact_register's argument handling and its own exit-2 error line).
//
// DEVIATION (r34 F3, 2026-09-15): the write goes through
// state.RegisterOrRefresh instead of the append primitive, so the RUNBOOK's
// hard rule "a path holds one registry row" holds for this verb too (see the
// comment at the call site). A path that is NOT registered keeps the
// reference bytes: the same id line and the same immutability notice, both
// pinned by cmd_artifact_register_test.go.
//
// DEVIATION (r35 F1, 2026-09-16): a same-path ghost whose row id a live
// citation still names is KEPT, not pruned (the RUNBOOK's one-row law is
// about the shape that law was written for; the cited shape is the evidence
// audit section 11 re-derives, and the log is append-only so retiring it is
// permanent). The verb's STDOUT first line is unchanged —
// "<ID>: kind=K path=P" — and the kept-row disclosure rides stderr, the
// documented convention for warnings. A kept ghost means the path now holds
// two rows, and the verb says so.

import (
	"fmt"
	"os"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// artifactRegisterRefreshReason is the reason the re-registration logs on the
// artifact.refreshed event: register_or_refresh's own default (the reference
// Python's "re-registered (content may have changed)"), so a path that is
// already registered refreshes through the SAME event shape report.go and
// the verify flows write.
const artifactRegisterRefreshReason = "re-registered (content may have changed)"

// artifactRowWasRefreshed reports whether the row this verb just returned was
// REFRESHED instead of minted. refreshArtifact is the only writer of
// refresh_count (RegisterArtifact never sets the key), and a positive count
// on the row this call produced therefore means the re-registration took the
// refresh/migrate path the RUNBOOK's one-row-per-path law requires — which is
// also the only shape whose success line must NOT promise immutability.
func artifactRowWasRefreshed(row validation.Value) bool {
	rc := validation.ObjAt(row, "refresh_count")
	return rc.Kind == validation.Int && rc.I > 0
}

// artifactRegisterParse parses the flag loop and the positional count,
// returning the positionals plus the --kind/--note values.
func artifactRegisterParse(args []string) ([]string, string, string, error) {
	var pos []string
	kind, note := "other", ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--kind" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			kind = args[i+1]
			i++
		case strings.HasPrefix(a, "--kind="):
			kind = strings.TrimPrefix(a, "--kind=")
		case a == "--kind":
			return nil, "", "", argErrf("artifact-register",
				"argument --kind: expected one argument")
		case a == "--note" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			note = args[i+1]
			i++
		case strings.HasPrefix(a, "--note="):
			note = strings.TrimPrefix(a, "--note=")
		case a == "--note":
			return nil, "", "", argErrf("artifact-register",
				"argument --note: expected one argument")
		case strings.HasPrefix(a, "-"):
			return nil, "", "", usageErrf("unrecognized arguments: %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 2 {
		missing := []string{}
		if len(pos) < 1 {
			missing = append(missing, "campaign")
		}
		if len(pos) < 2 {
			missing = append(missing, "path")
		}
		return nil, "", "", requiredErrf("artifact-register", missing...)
	}
	return pos, kind, note, nil
}

// artifactRegisterReport prints the id line, the kept-ghost warnings and the
// mint-vs-refresh note, and returns the verb's exit code.
func artifactRegisterReport(c *state.Campaign, r *Runner, aid, kind, path string,
	kept []state.KeptGhost) int {
	fmt.Fprintf(r.Out, "%s: kind=%s path=%s\n", aid, kind, path)
	// The kept-row report rides stderr, the documented convention for
	// warnings (artifact-prune's cite warning is the sibling) — the stdout
	// shape above is the RUNBOOK's contract and stays byte-identical.
	if len(kept) > 0 {
		rows := make([]string, 0, len(kept)+1)
		rows = append(rows, aid)
		for _, g := range kept {
			fmt.Fprintf(r.Err, "WARNING: registry row %s (kind=%s) at %s was "+
				"NOT retired — %s\n", g.ArtifactID, g.Kind, path, g.Citation)
			rows = append(rows, g.ArtifactID)
		}
		fmt.Fprintf(r.Err, "WARNING: %s now holds %d registry rows (%s): "+
			"the kept row(s) are the evidence the citation above still names, "+
			"so a re-registration may not retire them — audit section 11 "+
			"re-derives them by id\n", path, len(rows), strings.Join(rows, ", "))
	}
	// The id line is unchanged for both shapes (the id is the row's, and on
	// the refresh path it is the row that was ALREADY there). What follows
	// depends on which happened, because the historical notice is only true
	// of a mint: a refreshed row WAS revised in place, and the previous bytes
	// stay on the log as artifact.refreshed rather than in a second row.
	// The fresh-register bytes are the ones the RUNBOOK and
	// cmd_artifact_register_test.go pin, and they are untouched.
	if row, rerr := c.Artifact(aid); rerr == nil &&
		artifactRowWasRefreshed(row) {
		fmt.Fprintln(r.Out, "note: re-registered — this path already held "+
			"a registry row, so it was refreshed in place (a path holds "+
			"one registry row); the previous bytes stay on the log as "+
			"artifact.refreshed")
		return 0
	}
	// The artifact id is immutable (Task 7d): the store copied the bytes, so
	// overwriting the file at `path` afterwards does not revise the artifact.
	// Say so once, at the moment the operator learns the id — the alternative
	// is finding out when the recorded hash no longer matches the file.
	fmt.Fprintln(r.Out, "note: registered artifacts are immutable — to revise, "+
		"register a new artifact (the old one stays for provenance)")
	return 0
}

func runArtifactRegister(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "artifact-register", args) {
		return 0
	}

	ensureSeams()
	pos, kind, note, err := artifactRegisterParse(args)
	if err != nil {
		return r.fail(root, err)
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	path := pos[1]
	if _, statErr := os.Stat(path); statErr != nil {
		fmt.Fprintf(r.Err, "artifact register failed: no such file: %s\n", path)
		return 2
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	// r34 F3: RegisterOrRefresh, not RegisterArtifact. The RUNBOOK's hard rule
	// for the operator (assets/runbook/RUNBOOK.md:1652-1660) makes this verb
	// the sanctioned re-registration path and states the law it must honour:
	// "A path holds one registry row: re-registering it under a different
	// --kind migrates that row (the refresh event records kind_migrated:
	// old→new) and prunes any ghost rows at the same path." The append
	// primitive this used to call minted a SECOND row for a registered path
	// (an OTH- row plus a REP- row for one file — the D3 supersession defect
	// state.RegisterOrRefresh exists to close), and no artifact.refreshed
	// event was ever written. RegisterArtifact stays the append primitive for
	// the callers that mean to mint a row (RegisterOrRefresh's own
	// path-not-registered branch); this verb is not one of them.
	//
	// r35 F1: RegisterOrRefreshKeptGhosts, not RegisterOrRefresh, because the
	// ghost half of that law is CITE-CHECKED (state.ArtifactCitedByLiveBinds)
	// and the operator is owed the report: a same-path row whose id a live
	// citation still names — a harness_scaffold event's ref is the one that
	// burns section 11's rung FOREVER, since the log is append-only and the id
	// is uuid-random — is kept, and this verb says which rows it kept and
	// why. An UNCITED ghost is still pruned (one row per path for the shape
	// the RUNBOOK law was written for).
	aid, kept, err := c.RegisterOrRefreshKeptGhosts(kind, path, note, snap,
		artifactRegisterRefreshReason)
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	return artifactRegisterReport(c, r, aid, kind, path, kept)
}

func init() {
	register(command{ord: 23, name: "artifact-register",
		line: "artifact-register <campaign> <path>  register an artifact",
		run:  runArtifactRegister})
}
