package cli

// cmd_artifact_prune: `webv2 artifact-prune <artifact_id> --reason REASON
// [--json]` — retire one registry row through state.Campaign.PruneArtifact,
// the same primitive the bind path uses (cmd_verify_autoprove.go). The row
// leaves the working projection; the artifact.registered/artifact.pruned
// events stay on the log as the trail, and --reason is what the ledger
// records as WHY the row retired.
//
// ID-ADDRESSED on purpose: no `<campaign>` positional. Artifact ids are
// minted per campaign and the operator's documented tool is
// `artifact prune <id>` (docs/MINIPROVER_INTEGRATION.md §10, the paragraph
// that discloses the store's knowingly unbounded growth), so the ROW says
// which campaign under --root to touch. An id no campaign holds is the
// exit-2 usage error naming that id; an id two campaigns hold (reachable
// only by a hand-edited pair of registries) refuses rather than guessing.
//
// CITE WARNING, never a gate. The bind's cite-guard refuses to prune a row
// a live harness_run event cites — but that is the BIND's discipline, not
// the operator's: this verb reuses the same guard and its predicate
// (artifactCitedByLiveBinds) to SCAN, names on stderr the artifact and
// every invariant whose blessing cites the row's sha256, says on that same
// line that the evidence is being removed and that audit section 11 will
// now report that rung unbacked (UNBACKED) — and then prunes anyway. The
// burn that follows is the honest cost of an explicit operator act, so
// there is deliberately no --force flag to make it look conditional.
//
// Success prints the retired row in artifact-register's line shape
// (`{id}: kind={kind} path={path}`); --json prints the row as object with
// the recorded reason appended, indent-2 ASCII like the sibling --json
// verbs (cmd_execs, cmd_audit).

import (
	"fmt"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

const artifactPruneUsage = "usage: webv2 artifact-prune [-h] --reason REASON " +
	"[--json] artifact_id\n"

const artifactPruneHelp = `usage: webv2 artifact-prune [-h] --reason REASON [--json] artifact_id

positional arguments:
  artifact_id      the registry row to retire

options:
  -h, --help       show this help message and exit
  --reason REASON  why the row retires (recorded on the artifact.pruned
                   event)
  --json           print the retired row as indent-2 JSON
`

func runArtifactPrune(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return artifactPruneCmd(root, args, r)
	})
}

func artifactPruneCmd(root string, args []string, r *Runner) error {
	sp := &argSpec{
		prog:  "artifact-prune",
		usage: artifactPruneUsage,
		vals:  []*valOpt{{name: "--reason", required: true}},
		flags: []*boolOpt{{name: "--json"}},
		pos:   []*posOpt{{name: "artifact_id"}},
	}
	if err := sp.parse(args); err != nil {
		return err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, artifactPruneHelp)
		return nil
	}
	artID, reason := sp.pos[0].val, sp.vals[0].val
	if artID == "" {
		return t14ArgparseErr(artifactPruneUsage, "artifact-prune",
			"artifact_id must not be empty")
	}
	if strings.TrimSpace(reason) == "" {
		return t14ArgparseErr(artifactPruneUsage, "artifact-prune",
			"--reason must not be empty — the artifact.pruned event records "+
				"why the row retired")
	}
	c, row, err := pruneLookup(root, artID)
	if err != nil {
		return err
	}
	if c == nil {
		return t14ExitErr(2, "artifact prune failed: unknown artifact %s",
			validation.PyReprStr(artID))
	}
	// The citation the bind's cite-guard protects: does a harness_run event
	// still name this row's digest? Same predicate, same decision function
	// the bind path calls — the verb must not hold a second opinion about
	// what "cited" means.
	dig := objStr(row, "sha256")
	cited, err := artifactCitedByLiveBinds(c, dig)
	if err != nil {
		return err
	}
	if cited {
		ids, aerr := pruneCitedInvariants(c, dig)
		if aerr != nil {
			return aerr
		}
		subject := "an invariant the citing event does not name"
		if len(ids) > 0 {
			subject = strings.Join(ids, ", ")
		}
		fmt.Fprintf(r.Err, "WARNING: artifact %s holds the report bytes a "+
			"harness_run event cites for %s — pruning removes the "+
			"blessing's evidence; audit section 11 will now report that "+
			"rung unbacked (UNBACKED)\n", artID, subject)
	}
	rec, err := c.PruneArtifact(artID, reason)
	if err != nil {
		return err
	}
	if sp.flags[0].set {
		kvs := append([]validation.KV{}, rec.O...)
		kvs = validation.SetOrAppend(kvs, "reason", validation.VStr(reason))
		fmt.Fprintln(r.Out, validation.DumpIndentedASCII(validation.VObj(kvs...)))
		return nil
	}
	fmt.Fprintf(r.Out, "%s: kind=%s path=%s\n", objStr(rec, "artifact_id"),
		objStr(rec, "kind"), objStr(rec, "path"))
	return nil
}

// pruneLookup finds the campaign under root that holds artID, and its row.
// A nil campaign with a nil error means no campaign holds the id (the
// caller renders the exit-2 unknown-artifact refusal). Two campaigns
// holding one id is impossible by minting (random ids) and possible only
// by a hand-edited registry: named and refused, never guessed.
func pruneLookup(root, artID string) (*state.Campaign, validation.Value, error) {
	var found *state.Campaign
	var row validation.Value
	foundIn := ""
	for _, cid := range state.ListCampaigns(root) {
		c, err := state.Open(root, cid)
		if err != nil {
			return nil, validation.VNull(), err
		}
		st, err := c.State()
		if err != nil {
			return nil, validation.VNull(), err
		}
		for _, a := range objAt(st, "artifacts").A {
			if objStr(a, "artifact_id") != artID {
				continue
			}
			if found != nil {
				if foundIn == cid {
					return nil, validation.VNull(), t14ExitErr(2,
						"artifact prune failed: %s is registered "+
							"twice in campaign %s — the registry was "+
							"hand-edited; retire the row that owns "+
							"the bytes", artID, cid)
				}
				return nil, validation.VNull(), t14ExitErr(2,
					"artifact prune failed: %s is registered in two "+
						"campaigns (%s, %s) — retire the row in the "+
						"campaign that owns it", artID, foundIn, cid)
			}
			found, row, foundIn = c, a, cid
		}
	}
	return found, row, nil
}

// pruneCitedInvariants lists the invariants whose harness_run events pin
// dig, in event order and deduplicated. It is the naming half of the
// cite-guard: artifactCitedByLiveBinds decides "cited" with the identical
// predicate (type == harness_run && data.report_sha256 == dig) and this
// collects the ids the warning must name.
func pruneCitedInvariants(c *state.Campaign, dig string) ([]string, error) {
	if dig == "" {
		return nil, nil
	}
	events, err := c.Events()
	if err != nil {
		return nil, err
	}
	var ids []string
	seen := map[string]bool{}
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		d := objAt(ev, "data")
		if objStr(d, "report_sha256") != dig {
			continue
		}
		iid := objStr(d, "invariant")
		if iid == "" || seen[iid] {
			continue
		}
		seen[iid] = true
		ids = append(ids, iid)
	}
	return ids, nil
}

func init() {
	register(command{ord: 83, name: "artifact-prune",
		line: "artifact-prune <artifact_id> --reason R  retire a registry " +
			"row (the log keeps the trail)",
		run: runArtifactPrune})
}
