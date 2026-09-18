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
//
// B2 (feedback-triage-morph-r2, 2026-09-17): three hygiene fixes, all in this
// file. (1) --kind is validated EARLY, against the campaign_state schema
// document's own artifact-row enum (SchemaEnumValues, internal/validation/
// schema_enum.go) — a wrong kind used to parse here as a free string and die
// LATE as a raw schema wall (exit 1, the whole 32-value enum dumped at
// artifacts/1/kind); it is now the house argparse refusal, exit 2, with the
// allowed values in schema document order. (2) An EMPTY file is refused at
// this verb — right after the os.Stat below — because an empty artifact is a
// row with no evidence behind it; the two state-layer twins
// (internal/state/artifacts.go:50 RegisterArtifact,
// internal/state/artifacts_register.go:84 RegisterOrRefreshKeptGhosts) stay
// existence-only ON PURPOSE: they also serve `--exec` auto-registration and
// the harness-scaffold minters. There is deliberately NO --allow-empty
// bypass: a real placeholder is `printf '{}' > f.json` away, and a flag
// pressed reflexively defeats the check it bypasses. (3) The help block
// (artifactRegisterHelp below) advertises [--kind K] [--note N] — the
// registry line used to hide a flag that exists.

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// artifactRegisterKindPath is the campaign_state schema path whose enum is the
// registry's closed kind set: `artifacts[]` is the items schema of the
// `artifacts` array and `kind` its enum member
// (assets/schema/campaign_state.schema.json, artifacts[].kind). The CLI must
// not carry its own copy of that list — the schema document is the registry's
// contract, and a kind added to it must become registrable with no code edit.
const artifactRegisterKindPath = "artifacts[]/kind"

// artifactRegisterKinds reads the artifact-row kind enum, in schema document
// order (the order the refusal text below lists the values in). A missing
// enum is a hard error, not an empty allow-list: if the schema ever moves the
// property, "every kind is invalid" would be the worst possible way to find
// out.
func artifactRegisterKinds() ([]string, error) {
	vals, ok, err := validation.SchemaEnumValues("campaign_state",
		artifactRegisterKindPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("campaign_state schema: no artifact kind enum "+
			"at %s", artifactRegisterKindPath)
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, validation.LegendValue(v))
	}
	return out, nil
}

// artifactRegisterHelp is `webv2 artifact-register --help`: argparse's block
// shape (usage, positionals, options) like the sibling artifact-prune help,
// with the kind list's home named so the operator can read the full enum
// without a failing register. Printed by helpRequested through
// verbHelpBlocks (internal/cli/cli.go); the usage line stays byte-identical
// to argparseUsageBlocks["artifact-register"], which is what a usage ERROR
// renders.
const artifactRegisterHelp = `usage: webv2 artifact-register [-h] [--kind KIND] [--note NOTE] campaign path

positional arguments:
  campaign     the campaign whose registry the row joins
  path         the file to register; it must exist and hold at least one byte

options:
  -h, --help   show this help message and exit
  --kind KIND  the artifact row's kind (default: other). Common kinds: recon,
               protocol-model, plan, hypothesis, finding, poc, trace, coverage,
               report, harness, detector, sequence-poc, disclosure, other. The
               full list is the artifact-row kind enum in the campaign_state
               schema: ` + "`webv2 schema campaign_state`" + ` (artifacts[]/kind).
  --note NOTE  free-form note recorded on the artifact row
`

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
//
// B2: --kind is validated HERE, after the loop and before the positional
// count — argparse checks an option's choices while it consumes the option,
// so an invalid --kind outranks "the following arguments are required", and
// (the point of the fix) it refuses before state.Open: no campaign is opened,
// no row is written, exit 2 with the fix list. The allowed values are read
// from the campaign_state schema document on every call, never a Go literal.
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
	kinds, err := artifactRegisterKinds()
	if err != nil {
		return nil, "", "", err
	}
	if !slices.Contains(kinds, kind) {
		// The refusal names the schema's own values in document order: the
		// operator gets the fix list WITH the refusal instead of the late raw
		// schema wall (exit 1, the whole enum dumped at artifacts/1/kind).
		return nil, "", "", argErrf("artifact-register",
			"argument --kind: invalid kind %s; choose from: %s",
			quoteSingle(kind), strings.Join(kinds, ", "))
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
	fi, statErr := os.Stat(path)
	if statErr != nil {
		fmt.Fprintf(r.Err, "artifact register failed: no such file: %s\n", path)
		return 2
	}
	// B2: an EMPTY file is refused, here at the verb — the authoritative
	// place — right after the existence check and BEFORE anything is written
	// (the campaign was opened read-only above; no row, no event). A row is a
	// citation the audit re-hashes, so a zero-byte artifact is a citation to
	// nothing; `/dev/null` is the spelling that made this visible (it exists,
	// so the existence check passed and a row was minted). NO --allow-empty
	// bypass: an operator who really wants a placeholder writes `{}` into the
	// file, and a flag pressed reflexively defeats the check it bypasses.
	// The state-layer twins stay existence-only on purpose (artifacts.go:50,
	// artifacts_register.go:84): `--exec` auto-registration and the
	// harness-scaffold minters register files the CLI never sees.
	if fi.Size() == 0 {
		fmt.Fprintf(r.Err, "artifact register failed: empty artifact: %s\n",
			path)
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
		line: "artifact-register <campaign> <path> [--kind K] [--note N]  " +
			"register an artifact",
		run: runArtifactRegister})
}
