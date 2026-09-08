package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"websec/internal/validation"
)

// pyTruthy is CPython truthiness over a Value: null/False/0/""/[]/{} are
// false, everything else true. Used by the `if note` / `executor or ...`
// guards in set_stage.
func pyTruthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		if v.Big != "" {
			return v.Big != "0"
		}
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

// first3Upper is kind[:3].upper() (a short kind slices to its whole length).
func first3Upper(s string) string {
	rs := []rune(s)
	if len(rs) > 3 {
		rs = rs[:3]
	}
	return strings.ToUpper(string(rs))
}

// resolvePath is Path.resolve() for an existing path: absolute with
// symlinks expanded (strict=False is moot — callers only resolve paths
// they just stat'ed).
func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}

// --- stage ledger ----------------------------------------------------------

// StageStatus is stage_status: state()["stages"].get(stage,
// {"status": "pending"}).
func (c *Campaign) StageStatus(stage string) (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	if e := objAt(objAt(st, "stages"), stage); e.Kind != validation.Null {
		return e, nil
	}
	return validation.VObj(kv("status", validation.VStr("pending"))), nil
}

// SetStage is set_stage: the per-stage execution ledger. The entry defaults
// to {"status":"pending","attempts":0,"last_run_at":None,"note":"",
// "executor":None} (exact key order). attempts increments only for
// "needs-model"/"done"/"failed"; note overwrites only when truthy;
// executor only when a non-empty value is passed. No event is logged.
//
// Deviation: Python's optional note/executor parameters are passed
// explicitly — VNull()/nil for the defaults. Python's `executor or ...`
// also treats "" as "keep the old value"; the port matches.
func (c *Campaign) SetStage(stage, status string, note validation.Value, executor *string) error {
	st, err := c.State()
	if err != nil {
		return err
	}
	stages := objAt(st, "stages")
	entry := objAt(stages, stage)
	if entry.Kind == validation.Null {
		entry = validation.VObj(
			kv("status", validation.VStr("pending")),
			kv("attempts", validation.VInt(0)),
			kv("last_run_at", validation.VNull()),
			kv("note", validation.VStr("")),
			kv("executor", validation.VNull()),
		)
	}
	entry.O = setOrAppend(entry.O, "status", validation.VStr(status))
	attempts := int64(0)
	if a := objAt(entry, "attempts"); a.Kind == validation.Int {
		if n, err := strconv.ParseInt(validation.IntText(a), 10, 64); err == nil {
			attempts = n
		}
	}
	if status == "needs-model" || status == "done" || status == "failed" {
		attempts++
	}
	entry.O = setOrAppend(entry.O, "attempts", validation.VInt(attempts))
	entry.O = setOrAppend(entry.O, "last_run_at", validation.VStr(nowIso()))
	if pyTruthy(note) {
		entry.O = setOrAppend(entry.O, "note", validation.VStr(capNote(note)))
	}
	if executor != nil && *executor != "" {
		entry.O = setOrAppend(entry.O, "executor", validation.VStr(*executor))
	}
	stages.O = setOrAppend(stages.O, stage, entry)
	st.O = setOrAppend(st.O, "stages", stages)
	return c.save(st)
}

// --- artifacts -------------------------------------------------------------

// RegisterArtifact is register_artifact: hash the file, mint
// kind-prefix + 8-hex id, store the path relative to the (resolved) root
// when the file is inside it, else absolute, and log artifact.registered
// with the ORIGINAL path argument.
func (c *Campaign) RegisterArtifact(kind, path, note string, snapshotID *string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		// p.exists() is False on ANY stat failure -> FileNotFoundError(p)
		// whose str() is the path itself.
		return "", fmt.Errorf("%s", path)
	}
	id := strings.Replace(newId("ART", 8), "ART-", first3Upper(kind)+"-", 1)
	resolved := resolvePath(path)
	rootResolved := resolvePath(c.Root)
	stored := resolved
	// is_relative_to: Rel never yields a leading ".." component for a
	// true descendant; check the COMPONENT, not the prefix, so a file
	// named "..hidden" inside the root still stores as relative.
	if rel, err := filepath.Rel(rootResolved, resolved); err == nil &&
		rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		stored = rel
	}
	sha, err := validation.Sha256File(path)
	if err != nil {
		return "", err
	}
	snap := validation.VNull()
	if snapshotID != nil {
		snap = validation.VStr(*snapshotID)
	}
	rec := validation.VObj(
		kv("artifact_id", validation.VStr(id)),
		kv("kind", validation.VStr(kind)),
		kv("path", validation.VStr(stored)),
		kv("registered_at", validation.VStr(nowIso())),
		kv("sha256", validation.VStr(sha)),
		kv("snapshot_id", snap),
		kv("note", validation.VStr(note)),
	)
	st, err := c.State()
	if err != nil {
		return "", err
	}
	arts := objAt(st, "artifacts")
	arts.A = append(arts.A, rec)
	st.O = setOrAppend(st.O, "artifacts", arts)
	if err := c.save(st); err != nil {
		return "", err
	}
	data := validation.VObj(
		kv("kind", validation.VStr(kind)),
		kv("path", validation.VStr(path)),
	)
	if _, err := c.Log("artifact.registered", &id, &data); err != nil {
		return "", err
	}
	return id, nil
}

// Artifact is artifact: the registry row for id, or the KeyError the
// Python raises (repr quoting included).
func (c *Campaign) Artifact(artifactID string) (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	for _, a := range objAt(st, "artifacts").A {
		if objStr(a, "artifact_id") == artifactID {
			return a, nil
		}
	}
	return validation.VNull(), fmt.Errorf("unknown artifact %s",
		validation.PyReprStr(artifactID))
}

// resolveArtifactPath is _resolve_artifact_path: stored absolute paths
// stay as-is, relative ones are joined under the campaign root (NO
// symlink resolution — the callers add it where Python adds .resolve()).
func (c *Campaign) resolveArtifactPath(a validation.Value) string {
	p := objStr(a, "path")
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Root, p)
}

// PruneArtifact is prune_artifact: retire a row whose content can no
// longer be verified. The row is removed from the working projection; the
// original artifact.registered event stays on the log as the audit trail.
func (c *Campaign) PruneArtifact(artifactID, reason string) (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	arts := objAt(st, "artifacts")
	idx := -1
	for i, a := range arts.A {
		if objStr(a, "artifact_id") == artifactID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return validation.VNull(), fmt.Errorf("unknown artifact %s",
			validation.PyReprStr(artifactID))
	}
	rec := arts.A[idx]
	arts.A = append(arts.A[:idx], arts.A[idx+1:]...)
	st.O = setOrAppend(st.O, "artifacts", arts)
	if err := c.save(st); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("kind", objAt(rec, "kind")),
		kv("path", objAt(rec, "path")),
		kv("reason", validation.VStr(reason)),
	)
	if _, err := c.Log("artifact.pruned", &artifactID, &data); err != nil {
		return validation.VNull(), err
	}
	return rec, nil
}

// RefreshArtifact is refresh_artifact: the sanctioned re-hash of a LIVING
// artifact that mutated after registration. The file check comes BEFORE
// the reason check (as in Python).
//
// Deviation: Python's default actor="operator" has no Go analogue for an
// omitted argument; an empty actor string is treated as the default.
func (c *Campaign) RefreshArtifact(artifactID, reason, actor string) (validation.Value, error) {
	if actor == "" {
		actor = "operator"
	}
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	arts := objAt(st, "artifacts")
	idx := -1
	for i, a := range arts.A {
		if objStr(a, "artifact_id") == artifactID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return validation.VNull(), fmt.Errorf("unknown artifact %s",
			validation.PyReprStr(artifactID))
	}
	a := arts.A[idx]
	p := c.resolveArtifactPath(a)
	if _, err := os.Stat(p); err != nil {
		return validation.VNull(),
			fmt.Errorf("artifact file missing, cannot refresh: %s", p)
	}
	if reason == "" || strings.TrimSpace(reason) == "" {
		return validation.VNull(),
			fmt.Errorf("refresh_artifact requires a written reason")
	}
	old := objAt(a, "sha256")
	sha, err := validation.Sha256File(p)
	if err != nil {
		return validation.VNull(), err
	}
	count := int64(0)
	if rc := objAt(a, "refresh_count"); rc.Kind == validation.Int {
		if n, err := strconv.ParseInt(validation.IntText(rc), 10, 64); err == nil {
			count = n
		}
	}
	a.O = setOrAppend(a.O, "sha256", validation.VStr(sha))
	a.O = setOrAppend(a.O, "refreshed_at", validation.VStr(nowIso()))
	a.O = setOrAppend(a.O, "refresh_reason", validation.VStr(reason))
	a.O = setOrAppend(a.O, "refresh_count", validation.VInt(count+1))
	arts.A[idx] = a
	st.O = setOrAppend(st.O, "artifacts", arts)
	if err := c.save(st); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("kind", objAt(a, "kind")),
		kv("actor", validation.VStr(actor)),
		kv("reason", validation.VStr(reason)),
		kv("old_sha256", old),
		kv("new_sha256", validation.VStr(sha)),
		kv("refresh_count", validation.VInt(count+1)),
	)
	if _, err := c.Log("artifact.refreshed", &artifactID, &data); err != nil {
		return validation.VNull(), err
	}
	return a, nil
}

// RegisterOrRefresh is register_or_refresh: register path — or, when an
// artifact is already registered at the same (resolved) path, REFRESH it
// instead of minting a ghost row. A differing kind (with a non-empty kind)
// mints a new row. "latest" is max by registered_at (first max wins ties,
// as in Python). The caller passes the reason explicitly (Python's default
// is "re-registered (content may have changed)").
func (c *Campaign) RegisterOrRefresh(kind, path, note string, snapshotID *string, reason string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("%s", path)
	}
	resolved := resolvePath(path)
	st, err := c.State()
	if err != nil {
		return "", err
	}
	var same []validation.Value
	for _, a := range objAt(st, "artifacts").A {
		if resolvePath(c.resolveArtifactPath(a)) == resolved {
			same = append(same, a)
		}
	}
	if len(same) > 0 {
		latest := same[0]
		for _, a := range same[1:] {
			if objStr(a, "registered_at") > objStr(latest, "registered_at") {
				latest = a
			}
		}
		if kind != "" && objStr(latest, "kind") != kind {
			return c.RegisterArtifact(kind, path, note, snapshotID)
		}
		if _, err := c.RefreshArtifact(objStr(latest, "artifact_id"), reason, "operator"); err != nil {
			return "", err
		}
		return objStr(latest, "artifact_id"), nil
	}
	return c.RegisterArtifact(kind, path, note, snapshotID)
}
