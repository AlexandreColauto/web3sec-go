package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"websec/internal/validation"
)

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

// --- artifacts -------------------------------------------------------------

// RegisterArtifact is register_artifact: hash the file, mint
// kind-prefix + 8-hex id, store the path relative to the (resolved) root
// when the file is inside it, else absolute, and log artifact.registered
// with the ORIGINAL path argument.
func (c *Campaign) RegisterArtifact(kind, path, note string, snapshotID *string) (string, error) {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return "", err
	}
	defer c.UnlockProcess()
	prevRaw, hadRaw := c.rawState() // r16 unwind law
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
	arts := validation.ObjAt(st, "artifacts")
	arts.A = append(arts.A, rec)
	st.O = validation.SetOrAppend(st.O, "artifacts", arts)
	if err := c.save(st); err != nil {
		return "", err
	}
	data := validation.VObj(
		kv("kind", validation.VStr(kind)),
		kv("path", validation.VStr(path)),
	)
	if _, lerr := c.Log("artifact.registered", &id, &data); lerr != nil {
		// r16: ledger refused — UNWIND (see phases.go
		// for the law; a state change with no event is
		// the projection lie every audit direction hunts).
		if uerr := c.unwindState(prevRaw, hadRaw); uerr != nil {
			return "", lerr
		}
		return "", lerr
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
	for _, a := range validation.ObjAt(st, "artifacts").A {
		if validation.ObjStr(a, "artifact_id") == artifactID {
			return a, nil
		}
	}
	// B6a: the typed refusal, not a bare fmt.Errorf — the message is
	// unchanged (see UnknownArtifactError), the type is what lets the CLI
	// heal-pointer tell this reason from every other verify failure.
	return validation.VNull(), &UnknownArtifactError{ID: artifactID}
}

// resolveArtifactPath is _resolve_artifact_path: stored absolute paths
// stay as-is, relative ones are joined under the campaign root (NO
// symlink resolution — the callers add it where Python adds .resolve()).
func (c *Campaign) resolveArtifactPath(a validation.Value) string {
	p := validation.ObjStr(a, "path")
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Root, p)
}

// ResolveArtifactPath exports resolveArtifactPath for readers outside this
// package (the invariants relevance gate reads the cited artifact's bytes).
func (c *Campaign) ResolveArtifactPath(a validation.Value) string {
	return c.resolveArtifactPath(a)
}

// PruneArtifact is prune_artifact: retire a row whose content can no
// longer be verified. The row is removed from the working projection; the
// original artifact.registered event stays on the log as the audit trail.
func (c *Campaign) PruneArtifact(artifactID, reason string) (validation.Value, error) {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer c.UnlockProcess()
	prevRaw, hadRaw := c.rawState() // r16 unwind law
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	arts := validation.ObjAt(st, "artifacts")
	idx := -1
	for i, a := range arts.A {
		if validation.ObjStr(a, "artifact_id") == artifactID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return validation.VNull(), &UnknownArtifactError{ID: artifactID}
	}
	rec := arts.A[idx]
	arts.A = append(arts.A[:idx], arts.A[idx+1:]...)
	st.O = validation.SetOrAppend(st.O, "artifacts", arts)
	if err := c.save(st); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("kind", validation.ObjAt(rec, "kind")),
		kv("path", validation.ObjAt(rec, "path")),
		kv("reason", validation.VStr(reason)),
	)
	if _, lerr := c.Log("artifact.pruned", &artifactID, &data); lerr != nil {
		// r16: ledger refused — UNWIND (see phases.go
		// for the law; a state change with no event is
		// the projection lie every audit direction hunts).
		if uerr := c.unwindState(prevRaw, hadRaw); uerr != nil {
			return validation.VNull(), lerr
		}
		return validation.VNull(), lerr
	}
	return rec, nil
}
