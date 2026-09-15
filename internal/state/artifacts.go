package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
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
	entry.O = validation.SetOrAppend(entry.O, "status", validation.VStr(status))
	attempts := int64(0)
	if a := objAt(entry, "attempts"); a.Kind == validation.Int {
		if n, err := strconv.ParseInt(validation.IntText(a), 10, 64); err == nil {
			attempts = n
		}
	}
	if status == "needs-model" || status == "done" || status == "failed" {
		attempts++
	}
	entry.O = validation.SetOrAppend(entry.O, "attempts", validation.VInt(attempts))
	entry.O = validation.SetOrAppend(entry.O, "last_run_at", validation.VStr(nowIso()))
	if validation.PyTruthy(note) {
		entry.O = validation.SetOrAppend(entry.O, "note", validation.VStr(capNote(note)))
	}
	if executor != nil && *executor != "" {
		entry.O = validation.SetOrAppend(entry.O, "executor", validation.VStr(*executor))
	}
	stages.O = validation.SetOrAppend(stages.O, stage, entry)
	st.O = validation.SetOrAppend(st.O, "stages", stages)
	return c.save(st)
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
	arts := objAt(st, "artifacts")
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
	st.O = validation.SetOrAppend(st.O, "artifacts", arts)
	if err := c.save(st); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("kind", objAt(rec, "kind")),
		kv("path", objAt(rec, "path")),
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
	// r12 NOTE (critic issue 6, REFUSED): a hash-equal refresh does log
	// an event and bump refresh_count — deliberately. Two ported twin
	// pins demand it: TestRefreshArtifact ("second refresh increments to
	// 2" over identical bytes) and TestInvariantVerifyExecRerunRefreshes
	// TheSameArtifact (a re-verification is a REAL act whose provenance
	// must land even when output bytes coincide). The cost — report →
	// re-index → prove says "regenerate" — is honest: something DID
	// happen after report.generated. A content-no-op refresh would trade
	// recorded provenance for convenience, so the flip stays.
	old := objAt(a, "sha256")
	oldKind := objStr(a, "kind")
	migrated := ""
	if newKind != "" && oldKind != newKind {
		migrated = oldKind + "→" + newKind
		a.O = validation.SetOrAppend(a.O, "kind", validation.VStr(newKind))
	}
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
	a.O = validation.SetOrAppend(a.O, "sha256", validation.VStr(sha))
	a.O = validation.SetOrAppend(a.O, "refreshed_at", validation.VStr(nowIso()))
	a.O = validation.SetOrAppend(a.O, "refresh_reason", validation.VStr(reason))
	a.O = validation.SetOrAppend(a.O, "refresh_count", validation.VInt(count+1))
	arts.A[idx] = a
	st.O = validation.SetOrAppend(st.O, "artifacts", arts)
	// r17: capture disk bytes BEFORE this save — under the caller's lock
	// they are the last CONSISTENT state (refresh is only reached while
	// a locked method runs; the disk has not been touched since its
	// load).
	prevRaw, hadRaw := c.rawState()
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
	if migrated != "" {
		data.O = validation.SetOrAppend(data.O, "kind_migrated",
			validation.VStr(migrated))
	}
	if _, err := c.Log("artifact.refreshed", &artifactID, &data); err != nil {
		// r17 P1: the refresh half-landed SILENTLY — projection shows
		// the new sha + count, the log has no artifact.refreshed, and
		// audit stays green because the only refreshed check runs
		// log->state. UNWIND, like every other save-then-log site
		// (the r16 headline said "every": prune/register got it,
		// refresh had been skipped by the converter).
		if uerr := c.unwindState(prevRaw, hadRaw); uerr != nil {
			return validation.VNull(), err
		}
		return validation.VNull(), err
	}
	return a, nil
}

// KeptGhost is one same-path registry row a re-registration did NOT retire
// because the campaign's own data still cites it (r35 F1; the decision is
// ArtifactCitedByLiveBinds, the ONE cite predicate). The caller reports it;
// the row stays registered.
type KeptGhost struct {
	ArtifactID string
	Kind       string
	Citation   string
}

// RegisterOrRefresh is register_or_refresh: register path — or, when an
// artifact is already registered at the same (resolved) path, REFRESH it
// instead of minting a ghost row. "latest" is max by registered_at (first max
// wins ties, as in Python). The caller passes the reason explicitly (Python's
// default is "re-registered (content may have changed)").
//
// DEVIATION (D3, 2026-09-10): a differing kind no longer mints a new row — it
// MIGRATES the row's kind and refreshes it, and any other row at the same
// resolved path (a ghost) is pruned with an artifact.pruned event. The
// reference behaviour was self-defeating for regenerated files: `report.md`
// was first registered by `artifact-register` (default kind "other") and later
// by report.generate() as kind "report", so every regeneration minted one more
// row, only the newest row's hash was ever refreshed, and the audit's
// re-hash-every-row check went red permanently — a state no sequence of
// commands could leave (pruning/refreshing instead logged events, which the
// report-freshness proof reads as "something happened after report.generated").
// One row per resolved path, always re-hashed on refresh, is what makes the
// registry auditable again.
//
// r35 F1 — THE PRUNE IS CITE-CHECKED, and the r34 justification for an
// unconditional one was FALSE. r34 pruned every ghost because "every ghost
// resolves to the SAME file as the row that replaces it, so the copy would be
// an unverifiable duplicate with no provenance value". Same bytes is not the
// same citation: the evidence that a live bind names is the ROW ID.
// harnessScaffoldArtifactBytes resolves the latest harness_scaffold event's
// ref with c.Artifact(ref) (audit/sections/invariantverification.go:549/587,
// cli/cmd_verify_harness.go:641), so retiring the row a scaffold event refs
// turns section 11's rung UNBACKED — permanently, because the log is
// append-only and the id is uuid-random: re-running `verify --scaffold` says
// "unchanged" (no second event) and re-binding refuses ("the scaffold artifact
// HAR-… is not registered"). The audit re-derives the id-cited row through the
// same code path the bind wrote it with, so no re-registration may retire it.
// An UNCITED ghost is still pruned: the RUNBOOK's one-row-per-path law is about
// the shape that law was written for.
//
// When a ghost is cited, the path temporarily holds TWO rows — the refreshed
// one plus the cited one — and that is the honest state, not a leak: the cited
// row cannot be retired by a re-registration (its id is what the evidence
// names), and the refreshed row is what the registry must re-hash. The two
// resolve to the same file, so the audit's re-hash-every-row check and the
// bind's sha arm both stay satisfied; the moment the citation retires (the
// evidence retires with it), the row is prunable again.
func (c *Campaign) RegisterOrRefresh(kind, path, note string, snapshotID *string, reason string) (string, error) {
	id, _, err := c.RegisterOrRefreshKeptGhosts(kind, path, note, snapshotID,
		reason)
	return id, err
}

// RegisterOrRefreshKeptGhosts is RegisterOrRefresh plus the r35 F1 report:
// the same-path rows it left registered because the campaign's own evidence
// still cites them, each with the citation's reason. Only the verb that must
// tell the operator what it did calls this (cli.cmd_artifact_register).
func (c *Campaign) RegisterOrRefreshKeptGhosts(kind, path, note string,
	snapshotID *string, reason string) (string, []KeptGhost, error) {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return "", nil, err
	}
	defer c.UnlockProcess()
	if _, err := os.Stat(path); err != nil {
		return "", nil, fmt.Errorf("%s", path)
	}
	resolved := resolvePath(path)
	st, err := c.State()
	if err != nil {
		return "", nil, err
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
		latestID := objStr(latest, "artifact_id")
		migrate := kind
		if kind == "" || objStr(latest, "kind") == kind {
			migrate = ""
		}
		// Prune the ghosts first so a failure mid-way leaves the projection
		// with one row per path, never zero.
		var kept []KeptGhost
		for _, a := range same {
			id := objStr(a, "artifact_id")
			if id == latestID {
				continue
			}
			// r35 F1: the ONE cite predicate decides, for the SAME reason
			// the bind's guard and the operator verb ask it — a ghost whose
			// row id a live harness_scaffold ref / verified_by link /
			// finding citation still names IS the evidence section 11
			// re-derives from, and no re-registration may retire it.
			cited, why, cerr := ArtifactCitedByLiveBinds(c, id)
			if cerr != nil {
				// A cite check that cannot READ the campaign's own citation
				// sources is not a clearance to destroy: keep the row and
				// say why it survived, rather than prune on an unknown.
				kept = append(kept, KeptGhost{ArtifactID: id,
					Kind: objStr(a, "kind"),
					Citation: "the citation check could not read the " +
						"campaign's evidence (" + cerr.Error() + ")"})
				continue
			}
			if cited {
				kept = append(kept, KeptGhost{ArtifactID: id,
					Kind: objStr(a, "kind"), Citation: why})
				continue
			}
			label := kind
			if label == "" {
				label = "the requested kind"
			}
			if _, err := c.PruneArtifact(id,
				"superseded: same path re-registered as kind "+label); err != nil {
				return "", nil, err
			}
		}
		if _, err := c.refreshArtifact(latestID, reason, "operator",
			migrate); err != nil {
			return "", nil, err
		}
		return latestID, kept, nil
	}
	id, err := c.RegisterArtifact(kind, path, note, snapshotID)
	if err != nil {
		return "", nil, err
	}
	return id, nil, nil
}

// --- the ONE cite predicate ------------------------------------------------
//
// r35 F1: a live bind's evidence names a registry ROW in two shapes, and the
// r34 ghost-prune saw only the first:
//
//   - by CONTENT: the row's sha256 is what a live harness_run event pins as
//     its report bytes, or what an exec record that event names hashes as the
//     bytes the run took in (input_hashes) or produced (artifact_hashes);
//   - by IDENTITY: the row's artifact_id is named outright, where byte
//     equality cannot look — a harness_scaffold event's `ref` (the scaffold a
//     live bind re-reads: audit/sections/invariantverification.go:544 and 582,
//     cli/cmd_verify_harness.go:627), an invariant.verified / linked_test /
//     contradicted event's payload, the invariants registry's `verified_by` /
//     `tests` / `contradiction` fields (invariants/guard.go:109 and 124,
//     invariants/invariants.go:503, 689, 721), and a finding's evidence /
//     repro-attempt `artifact_id` (risk/risk.go:786 — E7 must cite a
//     registered artifact — findings/assumptions.go:158).
//
// Byte equality cannot see the second shape at all, which is how retiring a
// same-path ghost turned section 11's rung UNBACKED FOREVER: the log is
// append-only and the ids are uuid-random, so an id the evidence still names
// can never be minted again (re-running `verify --scaffold` prints "unchanged"
// and writes no second event; re-binding refuses "the scaffold artifact … is
// not registered").
//
// Every arm is answered from the campaign's OWN sources: the event log
// (Campaign.Events), the invariants registry (artifacts/invariant_links.json),
// the findings store (findings/F-*.json) and the exec ledger (AllExecs). An
// arm whose source cannot be READ returns an error, never a silent false — a
// check that cannot read its sources is not a clearance to destroy, so the
// callers report the unreadable source instead of pruning on it.

// ArtifactCitedByLiveBinds is the ONE cite predicate: does any live evidence
// in this campaign still name the registry row id? `why` names the exact
// citation that holds it ("harness_scaffold event 12 refs this row as INV-1's
// minicertora scaffold"), because the caller prints it; it is "" when the row
// is uncited. An id no registry row carries is uncited by definition — the
// row is already gone, so there is nothing left for the evidence to name.
func ArtifactCitedByLiveBinds(c *Campaign, id string) (bool, string, error) {
	if c == nil || id == "" {
		return false, "", nil
	}
	st, err := c.State()
	if err != nil {
		return false, "", err
	}
	row := validation.VNull()
	for _, a := range objAt(st, "artifacts").A {
		if objStr(a, "artifact_id") == id {
			row = a
			break
		}
	}
	if row.Kind != validation.Obj {
		return false, "", nil
	}
	events, err := c.Events()
	if err != nil {
		return false, "", err
	}
	// Every arm is consulted and EVERY citation is reported: a row can be
	// named both by its bytes and by its id (a scaffold row is), and the
	// operator reading the warning is entitled to the whole reason — an
	// early return on the first hit hid the id-citation that makes the row
	// unretirable (r35 F1).
	var whys []string
	cited, why, err := artifactShaCitedRow(c, events, objStr(row, "sha256"))
	if err != nil {
		return false, "", err
	}
	if cited {
		whys = append(whys, why)
	}
	cited, why, err = artifactIDCitedByEvents(events, id)
	if err != nil {
		return false, "", err
	}
	if cited {
		whys = append(whys, why)
	}
	cited, why, err = artifactIDCitedByRegistry(c, id)
	if err != nil {
		return false, "", err
	}
	if cited {
		whys = append(whys, why)
	}
	if len(whys) == 0 {
		return false, "", nil
	}
	return true, strings.Join(whys, "; "), nil
}

// artifactShaCitedRow is the CONTENT half of the predicate: the two arms the
// cli's cite-guard and prune warning used (r25/r28/N1), moved here so the
// decision has one home.
func artifactShaCitedRow(c *Campaign, events []validation.Value,
	dig string) (bool, string, error) {
	if dig == "" {
		return false, "", nil
	}
	pins, err := ArtifactCitedExecIDs(events, c, dig)
	if err != nil {
		return false, "", err
	}
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		d := objAt(ev, "data")
		if !ArtifactEventCitesDig(d, dig, pins) {
			continue
		}
		iid := objStr(d, "invariant")
		if iid == "" {
			iid = "an invariant the event does not name"
		}
		if objStr(d, "report_sha256") == dig {
			return true, fmt.Sprintf("harness_run event %s for %s pins this "+
				"row's sha256 as its report bytes", eventSeq(ev), iid), nil
		}
		return true, fmt.Sprintf("harness_run event %s for %s names exec %s, "+
			"whose record pins this row's sha256 as the bytes the run took in",
			eventSeq(ev), iid, objStr(d, "exec")), nil
	}
	return false, "", nil
}

// artifactIDCitedByEvents is the IDENTITY half's log arm: the events that
// name a registry row id as evidence.
//
// artifact.registered / artifact.refreshed / artifact.pruned are deliberately
// NOT arms: their `ref` is the row's OWN id (a registration names the row it
// mints, a prune names the row it retires), so reading them as citations
// would make every row unprunable and the cite predicate vacuous.
func artifactIDCitedByEvents(events []validation.Value, id string) (bool,
	string, error) {
	for _, ev := range events {
		d := objAt(ev, "data")
		switch objStr(ev, "type") {
		case "harness_scaffold":
			if objStr(ev, "ref") != id || !scaffoldRefIsLive(events, d) {
				continue
			}
			label, kind := objStr(d, "artifact_id"), objStr(d, "kind")
			if label == "" {
				label = "an unnamed scaffold"
			}
			if kind == "" {
				kind = "unstated-kind"
			}
			return true, fmt.Sprintf("harness_scaffold event %s refs this row "+
				"as %s's %s scaffold, which the live harness_run bind for %s "+
				"re-reads", eventSeq(ev), label, kind,
				objStr(d, "invariant")), nil
		case "invariant.verified":
			if objStr(d, "artifact") == id {
				return true, fmt.Sprintf("invariant.verified event %s binds "+
					"this row to %s as its CHECKED_AGAINST_CODE artifact",
					eventSeq(ev), objStr(ev, "ref")), nil
			}
		case "invariant.linked_test":
			if objStr(d, "artifact") == id {
				return true, fmt.Sprintf("invariant.linked_test event %s "+
					"registers this row as a test artifact of %s",
					eventSeq(ev), objStr(ev, "ref")), nil
			}
		case "invariant.contradicted":
			if objStr(d, "evidence") == id {
				return true, fmt.Sprintf("invariant.contradicted event %s "+
					"names this row as %s's contradiction anchor",
					eventSeq(ev), objStr(ev, "ref")), nil
			}
		case "finding.impact_quantified":
			if objStr(d, "artifact_id") == id {
				return true, fmt.Sprintf("finding.impact_quantified event %s "+
					"names this row as the artifact quantifying %s",
					eventSeq(ev), objStr(ev, "ref")), nil
			}
		}
	}
	return false, "", nil
}

// scaffoldRefIsLive: a harness_scaffold event's `ref` is a LIVE citation only
// when a harness_run bind exists that re-reads that scaffold. The readers
// (audit/sections/invariantverification.go's harnessScaffoldArtifactBytes,
// cli.harnessScaffoldBytes) resolve HARNESS-<invariant>-<kind> off the latest
// harness_scaffold event, and the audit asks them ONLY while re-deriving an
// invariant's landed harness slot (InvariantVerification calls
// harnessEvidenceRecheck under harnessRunLine's `ok` arm), so a scaffold no
// bind re-reads is not evidence any reader consults. The gate is the bind's
// own identity: a harness_run event for the same invariant and — when the
// event states one — the same kind (a report-kind bind re-reads the report
// row, never a scaffold).
//
// Pinned by TestR35CiteScaffoldRefNeedsALiveBind (state) and, on the verb
// side, by cmd_artifact_prune_test.go's TestR28ExecCitationNeedsALiveEvent:
// a scaffold event alone must not make a row unretirable.
func scaffoldRefIsLive(events []validation.Value, scaffold validation.Value) bool {
	iid := objStr(scaffold, "invariant")
	if iid == "" {
		return false
	}
	kind := objStr(scaffold, "kind")
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		d := objAt(ev, "data")
		if objStr(d, "invariant") != iid {
			continue
		}
		if evKind := objStr(d, "kind"); evKind == "" || kind == "" ||
			evKind == kind {
			return true
		}
	}
	return false
}

// artifactIDCitedByRegistry is the IDENTITY half's store arm: the two
// id-keyed stores that are not the event log.
func artifactIDCitedByRegistry(c *Campaign, id string) (bool, string, error) {
	links, err := citationLinks(c)
	if err != nil {
		return false, "", err
	}
	for _, entry := range objAt(links, "invariants").O {
		iid, e := entry.K, entry.V
		if e.Kind != validation.Obj {
			continue
		}
		if objStr(e, "verified_by") == id {
			return true, fmt.Sprintf("%s links this row as its verified_by "+
				"artifact (CHECKED_AGAINST_CODE)", iid), nil
		}
		if objStr(e, "contradiction") == id {
			return true, fmt.Sprintf("%s names this row as its "+
				"contradiction anchor", iid), nil
		}
		if arrHasStr(objAt(e, "tests"), id) {
			return true, fmt.Sprintf("%s lists this row among its test "+
				"artifacts", iid), nil
		}
	}
	findings, err := citationFindings(c)
	if err != nil {
		return false, "", err
	}
	for _, f := range findings {
		fid := objStr(f, "finding_id")
		for _, item := range objAt(f, "evidence").A {
			if objStr(item, "artifact_id") != id {
				continue
			}
			what := objStr(item, "evidence_id")
			if what == "" {
				what = "an unnamed item"
			}
			return true, fmt.Sprintf("finding %s evidence %s names this row "+
				"as its artifact_id", fid, what), nil
		}
		attempts := objAt(objAt(objAt(f, "verification"), "reproduction"),
			"attempts")
		for _, a := range attempts.A {
			if objStr(a, "artifact_id") != id {
				continue
			}
			what := objStr(a, "attempt_id")
			if what == "" {
				what = "an unnamed attempt"
			}
			return true, fmt.Sprintf("finding %s reproduction attempt %s "+
				"names this row as its artifact_id", fid, what), nil
		}
	}
	return false, "", nil
}

// citationLinks reads the invariants registry STRAIGHT OFF DISK. The citation
// fields are stored verbatim, and the package's own reader
// (invariants.LoadLinks) runs the legacy migration — which REWRITES the
// registry and logs invariant.migrated. A read-only predicate must not mutate
// the campaign it is asked about. A missing file is the empty registry; an
// unreadable one is an error the caller must not read as "uncited".
func citationLinks(c *Campaign) (validation.Value, error) {
	p := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	raw, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return validation.VNull(), nil
	}
	if err != nil {
		return validation.VNull(), fmt.Errorf("the invariants registry %s "+
			"cannot be read: %v", p, err)
	}
	links, perr := validation.ParseOrdered(raw)
	if perr != nil {
		return validation.VNull(), fmt.Errorf("the invariants registry %s "+
			"does not parse (%v) — its citations cannot be checked", p, perr)
	}
	return links, nil
}

// citationFindings reads the findings store (findings/F-*.json, the layout
// findings.storage uses). A missing store is no findings; a store that cannot
// be listed or a file that cannot be read is an error, never "no citations".
func citationFindings(c *Campaign) ([]validation.Value, error) {
	if _, err := os.ReadDir(c.FindingsDir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("the findings store %s cannot be listed: %v",
			c.FindingsDir, err)
	}
	var out []validation.Value
	for _, p := range validation.ListPrefixed(c.FindingsDir, "F-", ".json") {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("the finding %s cannot be read: %v", p, err)
		}
		f, perr := validation.ParseOrdered(raw)
		if perr != nil {
			return nil, fmt.Errorf("the finding %s does not parse (%v) — its "+
				"citations cannot be checked", p, perr)
		}
		out = append(out, f)
	}
	return out, nil
}

// arrHasStr is membership for a string array read off disk (a non-array or a
// non-string element contributes nothing).
func arrHasStr(v validation.Value, want string) bool {
	for _, e := range v.A {
		if e.Kind == validation.Str && e.S == want {
			return true
		}
	}
	return false
}

// eventSeq renders an event's seq for citation messages ("?" when a
// hand-written line carries none).
func eventSeq(ev validation.Value) string {
	if s := objAt(ev, "seq"); s.Kind == validation.Int {
		return strconv.FormatInt(s.I, 10)
	}
	return "?"
}

// ArtifactEventCitesDig is THE per-event cite predicate, one home for every
// caller (the bind's cite-guard, the ghost-prune, the prune verb's warning). A
// live harness_run event cites dig when EITHER
//
//   - its own data.report_sha256 IS dig — the report-bound rungs (miniprover
//     autoprove, minicertora report binds), whose event names the exact bytes
//     it mapped; OR
//   - it names an exec (data.exec) whose recorded exec pins dig in
//     input_hashes / artifact_hashes — the EXEC rungs, whose evidence is the
//     scaffold file the sandbox hashed as the run's input (N1: the scaffold
//     artifact row was prunable with an EMPTY stderr, because the scan saw
//     only report_sha256, while the usage line and the RUNBOOK both promise
//     the warning whenever a live bind cites the row).
func ArtifactEventCitesDig(d validation.Value, dig string,
	citedExecs map[string]bool) bool {
	if dig == "" {
		return false
	}
	if objStr(d, "report_sha256") == dig {
		return true
	}
	id := objStr(d, "exec")
	return id != "" && citedExecs[id]
}

// ArtifactCitedExecIDs is the second CONTENT arm's resolution: the exec ids
// that a live harness_run event names AND whose exec record pins dig. It is a
// local re-read of the harness bind's hash reader (cli.harnessRecordedHashes,
// owned elsewhere): the same two maps, the same "non-empty string VALUE is a
// hash" rule — re-read here so the prune verb agrees with the bind instead of
// holding a second opinion about what the bind recorded.
//
// "Live" is the same notion the report arm already used: every harness_run
// event on the append-only ledger (nothing removes one; a superseded bind is
// still a bind the audit re-derives). Reading an extra event as cited burns
// nothing — it only makes the warning more conservative.
func ArtifactCitedExecIDs(events []validation.Value, c *Campaign,
	dig string) (map[string]bool, error) {
	if dig == "" {
		return nil, nil
	}
	named := map[string]bool{}
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		if id := objStr(objAt(ev, "data"), "exec"); id != "" {
			named[id] = true
		}
	}
	if len(named) == 0 {
		return nil, nil
	}
	execs, err := AllExecs(c)
	if err != nil {
		return nil, err
	}
	pins := map[string]bool{}
	for _, rec := range execs {
		id := objStr(rec, "exec_id")
		if named[id] && artifactExecPins(rec, dig) {
			pins[id] = true
		}
	}
	return pins, nil
}

// artifactExecPins: does one exec record pin dig among the bytes the run took
// in (input_hashes) or produced (artifact_hashes)? The record maps a file NAME
// to a sha256 STRING; only non-empty strings are hashes, so a
// null/absent/scalar map contributes nothing (same filter as the bind's
// reader).
func artifactExecPins(rec validation.Value, dig string) bool {
	if dig == "" {
		return false
	}
	for _, key := range []string{"input_hashes", "artifact_hashes"} {
		m := objAt(rec, key)
		if m.Kind != validation.Obj {
			continue
		}
		for _, kv := range m.O {
			if kv.V.Kind == validation.Str && kv.V.S == dig {
				return true
			}
		}
	}
	return false
}

// ReconcileArtifacts re-hashes every registered row against its file: a row
// whose file changed since registration is refreshed (reason "reconcile after
// external rewrite"), a row whose file is gone is reported as missing, and an
// unchanged row is left alone. dry=true reports without writing or logging
// anything. This is the operator's escape hatch for a batch of rewrites made by
// something other than the tool (D3).
//
// The result is {checked, refreshed, unchanged, missing, dry} where refreshed
// is the list of artifact ids (refreshed, or would-be-refreshed when dry) and
// missing is a list of {artifact_id, path}.
func (c *Campaign) ReconcileArtifacts(dry bool) (validation.Value, error) {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer c.UnlockProcess()
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	rows := append([]validation.Value{}, objAt(st, "artifacts").A...)
	refreshed := []validation.Value{}
	missing := []validation.Value{}
	unchanged := int64(0)
	for _, a := range rows {
		id := objStr(a, "artifact_id")
		p := c.resolveArtifactPath(a)
		if _, err := os.Stat(p); err != nil {
			missing = append(missing, validation.VObj(
				kv("artifact_id", validation.VStr(id)),
				kv("path", validation.VStr(p))))
			continue
		}
		stored := objAt(a, "sha256")
		if stored.Kind != validation.Str || stored.S == "" {
			// Registered without a hash: nothing to compare, and refreshing it
			// here would invent a baseline from whatever is on disk now.
			// Reported as unchanged, and since 2026-09-10 the audit really does
			// flag it (it used to skip the row and still report ok) — the
			// operator's fix is an explicit `webv2 artifact-reconcile
			// <campaign>`, which re-hashes the row against the bytes on disk.
			unchanged++
			continue
		}
		actual, err := validation.Sha256File(p)
		if err != nil {
			return validation.VNull(), err
		}
		if actual == stored.S {
			unchanged++
			continue
		}
		if !dry {
			if _, err := c.RefreshArtifact(id,
				"reconcile after external rewrite", "operator"); err != nil {
				return validation.VNull(), err
			}
		}
		refreshed = append(refreshed, validation.VStr(id))
	}
	return validation.VObj(
		kv("checked", validation.VInt(int64(len(rows)))),
		kv("refreshed", validation.VArr(refreshed...)),
		kv("unchanged", validation.VInt(unchanged)),
		kv("missing", validation.VArr(missing...)),
		kv("dry", validation.VBool(dry)),
	), nil
}

// ArtifactBytes resolves a registry row, re-hashes the file behind it,
// and returns the bytes ONLY when they still match the row's pinned
// sha256 — callers that re-derive evidence must not be able to read a
// substituted path while trusting the row (r25 F2 audit re-derivation).
// A row whose file moved returns a mismatch error naming both shas.
func (c *Campaign) ArtifactBytes(row validation.Value) ([]byte, error) {
	p := c.resolveArtifactPath(row)
	stored := objStr(row, "sha256")
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if stored == "" {
		return nil, fmt.Errorf("%s", "registry row carries no sha to "+
			"check the bytes against")
	}
	if got := validation.Sha256Hex(raw); got != stored {
		return nil, fmt.Errorf("registry row pins %s but %s now hashes "+
			"to %s", stored, p, got)
	}
	return raw, nil
}

// ResolveArtifactPathFor exposes resolveArtifactPath's resolution for
// one path string (r25 F4 cite-guard: bind-time callers must find the
// row that OWNS a path, which is exactly the resolver's question).
func ResolveArtifactPathFor(c *Campaign, p string) string {
	if p == "" {
		return ""
	}
	row := validation.VObj(
		validation.KV{K: "path", V: validation.VStr(p)},
	)
	return c.resolveArtifactPath(row)
}
