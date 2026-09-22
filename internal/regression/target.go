package regression

import (
	"fmt"
	"path/filepath"
	"regexp"

	"websec/internal/state"
	"websec/internal/validation"
)

// TargetKinds is §3a's closed vocabulary of target provenances.
var TargetKinds = []string{"scabench", "fresh", "control", "diagnosed"}

// TargetShapes is §3a's composition constraint as one closed vocabulary: the
// four ScaBench target shapes plus the two named rows (the diagnosed campaign,
// retained but relabeled training data, and the already-exploited control).
var TargetShapes = []string{
	"vault-erc4626", "lending-liquidation", "bridge-messaging",
	"non-rollup-l2-or-oracle", "diagnosed-campaign", "already-exploited",
}

// sha40Re is the only pin shape §3a accepts: a concrete commit, never a ref.
var sha40Re = regexp.MustCompile(`^[0-9a-f]{40}$`)

// TargetSpec is one target's identity at registration time. RecordID is the
// dataset's PROJECT id (selection and hold-out are per project); CodebaseID is
// the dataset's codebase id for the tree actually pinned, because the commit
// lives on the codebase — one project (Starknet Perpetual) carries two.
type TargetSpec struct {
	Kind       string
	Program    string
	RecordID   string
	CodebaseID string
	Repo       string
	Shape      string
	CommitHint string
}

// checkTargetSpec is AddTarget's refusals. An empty commit hint IS a legal
// value: the dataset emits it for two codebases (Initia Move_b36d06, Starknet
// Perpetual_main), so refusing it outright would make two of the 32 codebases
// unrepresentable (see *The dataset, as it actually is*).
func checkTargetSpec(spec TargetSpec) error {
	if !contains(TargetKinds, spec.Kind) {
		return fmt.Errorf("unknown target kind %q (known: %v)", spec.Kind, TargetKinds)
	}
	if !contains(TargetShapes, spec.Shape) {
		return fmt.Errorf("unknown target shape %q (known: %v)", spec.Shape, TargetShapes)
	}
	if spec.Program == "" {
		return fmt.Errorf("a target must name its program")
	}
	// The dataset's commit field is a HINT, and for two codebases the hint is
	// the empty string — a real value the producer emitted, not a missing row.
	// The row's provenance is still required, and Task 5's pin rule demands a
	// mirror for an `unknown` hint exactly as it does for `main`.
	if spec.Kind == "scabench" && spec.CommitHint == "" &&
		(spec.RecordID == "" || spec.Repo == "") {
		return fmt.Errorf("a scabench target with an empty dataset commit field must still name its --record-id and --repo: the dataset's commit field is empty for Initia Move_b36d06 and Starknet Perpetual_main, and an empty hint is a value to record, not a licence to skip the row")
	}
	return nil
}

// targetDoc builds one target record document.
func targetDoc(c *state.Campaign, spec TargetSpec, tid string) validation.Value {
	doc := validation.VObj(
		kv("target_id", validation.VStr(tid)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("kind", validation.VStr(spec.Kind)),
		kv("program", validation.VStr(spec.Program)),
		kv("shape", validation.VStr(spec.Shape)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("schema_version", validation.VInt(1)),
	)
	doc.O = withOptional(doc.O,
		optionalStr{"record_id", spec.RecordID},
		optionalStr{"codebase_id", spec.CodebaseID},
		optionalStr{"repo", spec.Repo},
		optionalStr{"commit_hint", spec.CommitHint},
	)
	return doc
}

// AddTarget records one target. It refuses an unknown kind or shape, an empty
// program, and (for a ScaBench target) an empty commit hint that is not backed
// by a named record and repo — a target whose dataset row was not read is not
// a target.
func AddTarget(c *state.Campaign, spec TargetSpec) (validation.Value, error) {
	if err := checkTargetSpec(spec); err != nil {
		return validation.VNull(), err
	}
	tid := state.NewID("T", 12)
	doc := targetDoc(c, spec, tid)
	data := validation.VObj(
		kv("target_id", validation.VStr(tid)),
		kv("kind", validation.VStr(spec.Kind)),
		kv("program", validation.VStr(spec.Program)),
		kv("shape", validation.VStr(spec.Shape)),
	)
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.target.added", &tid, data)
}

// PinSpec is one pin attempt: the concrete SHA the checkout landed on, the
// snapshot that recorded that checkout, and who resolved it.
type PinSpec struct {
	TargetID    string
	ResolvedSHA string
	SnapshotID  string
	ResolvedBy  string
}

// requireTarget reports a missing target as a refusal naming the campaign.
func requireTarget(c *state.Campaign, id string) error {
	ok, err := targetExists(c, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no target %s in campaign %s", id, c.CampaignID)
	}
	return nil
}

// targetExists reports whether a target record is present in this campaign.
func targetExists(c *state.Campaign, id string) (bool, error) {
	_, ok, err := readRecord(targetPath(c, id))
	if err != nil {
		return false, err
	}
	return ok, nil
}

// checkPin is PinTarget's §3a source-pinning rule, the two refusals that need
// the campaign:
//
//   - the SHA must be a concrete 40-hex commit — "ScaBench's commit field is a
//     hint, not a pin";
//   - the named snapshot must exist in this campaign and its
//     source.git_commit must EQUAL the resolved SHA, which is what makes
//     "every snapshot carries a resolved SHA" a checked fact rather than a
//     claim about the operator's shell history.
func checkPin(c *state.Campaign, spec PinSpec) error {
	if !sha40Re.MatchString(spec.ResolvedSHA) {
		return fmt.Errorf("resolved SHA %q is not a 40-hex commit — a ref (\"main\", \"v1.2.3\", a short hash) is a hint, not a pin; resolve it against the local mirror first", spec.ResolvedSHA)
	}
	snap, ok, err := readSnapshot(c, spec.SnapshotID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no snapshot %s in campaign %s", spec.SnapshotID, c.CampaignID)
	}
	commit := validation.ObjStr(validation.ObjAt(snap, "source"), "git_commit")
	if commit != spec.ResolvedSHA {
		return fmt.Errorf("snapshot %s records source.git_commit %q, not the resolved SHA %q — pin the checkout you actually resolved, not a different tree", spec.SnapshotID, commit, spec.ResolvedSHA)
	}
	return nil
}

// PinTarget binds a target to a resolved commit and to the snapshot that
// recorded it.
func PinTarget(c *state.Campaign, spec PinSpec) (validation.Value, error) {
	target, ok, err := Target(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			spec.TargetID, c.CampaignID)
	}
	if err := checkPin(c, spec); err != nil {
		return validation.VNull(), err
	}
	tid := spec.TargetID
	doc := copyTargetWith(target, spec)
	data := validation.VObj(
		kv("target_id", validation.VStr(tid)),
		kv("resolved_sha", validation.VStr(spec.ResolvedSHA)),
		kv("snapshot_id", validation.VStr(spec.SnapshotID)),
		kv("resolved_by", validation.VStr(spec.ResolvedBy)),
	)
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.target.pinned", &tid, data)
}

// copyTargetWith returns the target document with the pin keys set or
// appended, preserving every existing key's position (the ordered-JSON
// discipline: a rewrite must not reorder a record).
func copyTargetWith(target validation.Value, spec PinSpec) validation.Value {
	out := validation.VObj()
	out.O = append(out.O, target.O...)
	out.O = validation.SetOrAppend(out.O, "resolved_sha", validation.VStr(spec.ResolvedSHA))
	out.O = validation.SetOrAppend(out.O, "snapshot_id", validation.VStr(spec.SnapshotID))
	if spec.ResolvedBy != "" {
		out.O = validation.SetOrAppend(out.O, "resolved_by", validation.VStr(spec.ResolvedBy))
	}
	return out
}

// readSnapshot reads campaigns/<cid>/snapshots/<id>/snapshot.json, the
// immutable store internal/state/campaign_snapshot.go:277 points at.
func readSnapshot(c *state.Campaign, id string) (validation.Value, bool, error) {
	if id == "" {
		return validation.VNull(), false, nil
	}
	return readRecord(filepath.Join(c.Dir, "snapshots", id, "snapshot.json"))
}

// LoadTargets is every target record in the campaign, in file order.
func LoadTargets(c *state.Campaign) ([]validation.Value, error) {
	return loadRecords(TargetsDir(c), "T-")
}

// Target is one target record by id.
func Target(c *state.Campaign, id string) (validation.Value, bool, error) {
	return readRecord(targetPath(c, id))
}
