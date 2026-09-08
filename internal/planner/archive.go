package planner

// ---- superseded-plan archive (B1/D1) --------------------------------------
//
// The plan is the campaign's CONTRACT. Regeneration is a decision, so the
// outgoing plan is never truncated: it is copied byte-for-byte to a
// monotonically numbered path, registered as its own artifact kind and logged.
// An archive is IMMUTABLE by construction — the next rebuild only ever writes
// a higher number, so no rebuild can destroy the record of a prior contract.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"websec/internal/state"
	"websec/internal/validation"
)

// SupersededDirname and SupersededPrefix are SUPERSEDED_DIRNAME /
// SUPERSEDED_PREFIX.
const (
	SupersededDirname = "superseded"
	SupersededPrefix  = "campaign_plan"
)

// ArchiveOpts is archive_plan's keyword-only tail (Python: path=None,
// reason="plan superseded by an explicit rebuild"). An empty Path is None.
type ArchiveOpts struct {
	Path   string
	Reason string
}

// SupersededPaths is superseded_paths: every archived plan, in version order
// (lexical == numeric: the version is zero-padded).
func SupersededPaths(campaign *state.Campaign) []string {
	d := filepath.Join(campaign.ArtifactsDir, SupersededDirname)
	info, err := os.Stat(d)
	if err != nil || !info.IsDir() {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(d,
		SupersededPrefix+".[0-9]*.json"))
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}

// nextSupersededVersion is _next_superseded_version: one past the highest
// existing version — monotonic even if an operator deletes a middle archive,
// so a later rebuild can never reuse a number.
func nextSupersededVersion(campaign *state.Campaign) int {
	n := 0
	for _, p := range SupersededPaths(campaign) {
		// campaign_plan.<version>.json
		stem := filepath.Base(p)
		stem = stem[len(SupersededPrefix)+1 : len(stem)-len(".json")]
		if v, err := strconv.Atoi(stem); err == nil && v > n {
			n = v
		}
	}
	return n + 1
}

// ArchivePlan is archive_plan: archive the outgoing plan BEFORE a rebuild
// overwrites it.
//
// Copies the file byte-for-byte to
// artifacts/superseded/campaign_plan.<NNNN>.json (zero-padded, monotonic,
// never overwritten), registers it as kind plan.superseded and logs one
// plan.superseded event carrying the archive path, the priority count, the
// sha256 of the superseded content and the reason. Fail-loud: archiving a plan
// that is not there raises instead of writing an empty record.
func ArchivePlan(campaign *state.Campaign, opts ArchiveOpts) (string, error) {
	reason := opts.Reason
	if reason == "" {
		reason = "plan superseded by an explicit rebuild"
	}
	src := opts.Path
	if src == "" {
		src = filepath.Join(campaign.ArtifactsDir, "campaign_plan.json")
	}
	if _, err := os.Stat(src); err != nil {
		return "", errValue("nothing to archive: no plan at " + src)
	}
	plan, err := validation.ReadJson(src)
	if err != nil {
		return "", err
	}
	destDir := filepath.Join(campaign.ArtifactsDir, SupersededDirname)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	version := nextSupersededVersion(campaign)
	dest := filepath.Join(destDir,
		SupersededPrefix+"."+pad4(version)+".json")
	if _, err := os.Stat(dest); err == nil {
		// belt and braces: never overwrite an archive
		return "", errValue("superseded plan already exists: " + dest)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dest, raw, 0o644); err != nil { // byte-identical
		return "", err
	}
	priorities := len(listOf(plan, "priorities"))
	note := "superseded campaign plan " + pad4(version) + " (" +
		itoa(priorities) + " priorities)"
	aid, err := campaign.RegisterOrRefresh("plan.superseded", dest, note, nil,
		reason)
	if err != nil {
		return "", err
	}
	sha, err := validation.Sha256File(dest)
	if err != nil {
		return "", err
	}
	data := validation.VObj(
		kv("path", validation.VStr(dest)),
		kv("source_path", validation.VStr(src)),
		kv("version", validation.VStr(pad4(version))),
		kv("priorities", validation.VInt(int64(priorities))),
		kv("sha256_of_superseded", validation.VStr(sha)),
		kv("reason", validation.VStr(reason)),
	)
	if _, err := campaign.Log("plan.superseded", &aid, &data); err != nil {
		return "", err
	}
	return dest, nil
}

// pad4 is Python's f"{n:04d}".
func pad4(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}
