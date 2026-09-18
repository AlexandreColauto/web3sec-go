// artifacts_refresh.go: refresh_artifact — the sanctioned re-hash of a
// living artifact, with its optional kind migration and the save-then-log
// unwind.
package state

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"websec/internal/validation"
)

// RefreshArtifact is refresh_artifact: the sanctioned re-hash of a LIVING
// artifact that mutated after registration. The file check comes BEFORE
// the reason check (as in Python).
//
// Deviation: Python's default actor="operator" has no Go analogue for an
// omitted argument; an empty actor string is treated as the default.
func (c *Campaign) RefreshArtifact(artifactID, reason, actor string) (validation.Value, error) {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer c.UnlockProcess()
	return c.refreshArtifact(artifactID, reason, actor, "")
}

// refreshArtifact is RefreshArtifact plus an optional kind migration: when
// newKind is non-empty and differs from the row's kind, the row's kind is
// rewritten and the refresh event carries kind_migrated (D3 — a path that was
// first registered with a default kind and later re-registered as its real kind
// is ONE artifact that changed label, not two artifacts). A caller passing ""
// gets byte-identical behaviour to the reference.
func (c *Campaign) refreshArtifact(artifactID, reason, actor, newKind string) (validation.Value, error) {
	if actor == "" {
		actor = "operator"
	}
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	r := &refreshArtCtx{c: c, artifactID: artifactID, reason: reason,
		actor: actor, newKind: newKind, st: st}
	if err := r.findRow(); err != nil {
		return validation.VNull(), err
	}
	if err := r.checkFile(); err != nil {
		return validation.VNull(), err
	}
	if err := r.checkReason(); err != nil {
		return validation.VNull(), err
	}
	if err := r.applyRow(); err != nil {
		return validation.VNull(), err
	}
	return r.saveAndLog()
}

// refreshArtCtx carries the shared refreshArtifact context across its
// section helpers (row lookup, file/reason checks, row rewrite, save +
// event with unwind).
type refreshArtCtx struct {
	c          *Campaign
	artifactID string
	reason     string
	actor      string
	newKind    string
	st         validation.Value
	arts       validation.Value
	idx        int
	a          validation.Value
	p          string
	old        validation.Value
	sha        string
	count      int64
	migrated   string
}

// refreshArtFindRow locates the registry row for the id, refusing an
// unknown artifact exactly as the reference does.
func (r *refreshArtCtx) findRow() error {
	arts := validation.ObjAt(r.st, "artifacts")
	r.arts = arts
	idx := -1
	for i, a := range arts.A {
		if validation.ObjStr(a, "artifact_id") == r.artifactID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("unknown artifact %s",
			validation.PyReprStr(r.artifactID))
	}
	r.idx = idx
	r.a = arts.A[idx]
	return nil
}

// refreshArtCheckFile resolves the row's path and refuses a refresh whose
// file no longer exists.
func (r *refreshArtCtx) checkFile() error {
	p := r.c.resolveArtifactPath(r.a)
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("artifact file missing, cannot refresh: %s", p)
	}
	r.p = p
	return nil
}

// refreshArtCheckReason refuses an empty reason (the file check comes
// BEFORE the reason check, as in Python).
func (r *refreshArtCtx) checkReason() error {
	if r.reason == "" || strings.TrimSpace(r.reason) == "" {
		return fmt.Errorf("refresh_artifact requires a written reason")
	}
	return nil
}

// refreshArtApplyRow rewrites the row: optional kind migration, fresh
// sha256, refreshed_at, refresh_reason and the bumped refresh_count.
func (r *refreshArtCtx) applyRow() error {
	// r12 NOTE (critic issue 6, REFUSED): a hash-equal refresh does log
	// an event and bump refresh_count — deliberately. Two ported twin
	// pins demand it: TestRefreshArtifact ("second refresh increments to
	// 2" over identical bytes) and TestInvariantVerifyExecRerunRefreshes
	// TheSameArtifact (a re-verification is a REAL act whose provenance
	// must land even when output bytes coincide). The cost — report →
	// re-index → prove says "regenerate" — is honest: something DID
	// happen after report.generated. A content-no-op refresh would trade
	// recorded provenance for convenience, so the flip stays.
	r.old = validation.ObjAt(r.a, "sha256")
	oldKind := validation.ObjStr(r.a, "kind")
	r.migrated = ""
	if r.newKind != "" && oldKind != r.newKind {
		r.migrated = oldKind + "→" + r.newKind
		r.a.O = validation.SetOrAppend(r.a.O, "kind", validation.VStr(r.newKind))
	}
	sha, err := validation.Sha256File(r.p)
	if err != nil {
		return err
	}
	r.sha = sha
	count := int64(0)
	if rc := validation.ObjAt(r.a, "refresh_count"); rc.Kind == validation.Int {
		if n, err := strconv.ParseInt(validation.IntText(rc), 10, 64); err == nil {
			count = n
		}
	}
	r.count = count
	r.a.O = validation.SetOrAppend(r.a.O, "sha256", validation.VStr(sha))
	r.a.O = validation.SetOrAppend(r.a.O, "refreshed_at", validation.VStr(nowIso()))
	r.a.O = validation.SetOrAppend(r.a.O, "refresh_reason", validation.VStr(r.reason))
	r.a.O = validation.SetOrAppend(r.a.O, "refresh_count", validation.VInt(count+1))
	r.arts.A[r.idx] = r.a
	r.st.O = validation.SetOrAppend(r.st.O, "artifacts", r.arts)
	return nil
}

// refreshArtSaveAndLog saves the projection and logs artifact.refreshed,
// unwinding the state when the ledger refuses the event.
func (r *refreshArtCtx) saveAndLog() (validation.Value, error) {
	// r17: capture disk bytes BEFORE this save — under the caller's lock
	// they are the last CONSISTENT state (refresh is only reached while
	// a locked method runs; the disk has not been touched since its
	// load).
	prevRaw, hadRaw := r.c.rawState()
	if err := r.c.save(r.st); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("kind", validation.ObjAt(r.a, "kind")),
		kv("actor", validation.VStr(r.actor)),
		kv("reason", validation.VStr(r.reason)),
		kv("old_sha256", r.old),
		kv("new_sha256", validation.VStr(r.sha)),
		kv("refresh_count", validation.VInt(r.count+1)),
	)
	if r.migrated != "" {
		data.O = validation.SetOrAppend(data.O, "kind_migrated",
			validation.VStr(r.migrated))
	}
	if _, err := r.c.Log("artifact.refreshed", &r.artifactID, &data); err != nil {
		// r17 P1: the refresh half-landed SILENTLY — projection shows
		// the new sha + count, the log has no artifact.refreshed, and
		// audit stays green because the only refreshed check runs
		// log->state. UNWIND, like every other save-then-log site
		// (the r16 headline said "every": prune/register got it,
		// refresh had been skipped by the converter).
		if uerr := r.c.unwindState(prevRaw, hadRaw); uerr != nil {
			return validation.VNull(), err
		}
		return validation.VNull(), err
	}
	return r.a, nil
}
