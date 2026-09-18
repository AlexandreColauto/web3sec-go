// artifacts_register.go: register_or_refresh — one row per resolved path:
// refresh-instead-of-mint, the cite-checked ghost prune (and its kept-ghost
// report), plus the bytes-unchanged short-circuit for regeneration verbs.
package state

import (
	"fmt"
	"os"
	"websec/internal/validation"
)

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
	for _, a := range validation.ObjAt(st, "artifacts").A {
		if resolvePath(c.resolveArtifactPath(a)) == resolved {
			same = append(same, a)
		}
	}
	if len(same) > 0 {
		latest := same[0]
		for _, a := range same[1:] {
			if validation.ObjStr(a, "registered_at") > validation.ObjStr(latest, "registered_at") {
				latest = a
			}
		}
		latestID := validation.ObjStr(latest, "artifact_id")
		migrate := kind
		if kind == "" || validation.ObjStr(latest, "kind") == kind {
			migrate = ""
		}
		// Prune the ghosts first so a failure mid-way leaves the projection
		// with one row per path, never zero.
		var kept []KeptGhost
		for _, a := range same {
			id := validation.ObjStr(a, "artifact_id")
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
					Kind: validation.ObjStr(a, "kind"),
					Citation: "the citation check could not read the " +
						"campaign's evidence (" + cerr.Error() + ")"})
				continue
			}
			if cited {
				kept = append(kept, KeptGhost{ArtifactID: id,
					Kind: validation.ObjStr(a, "kind"), Citation: why})
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

// RegisterOrRefreshIfChanged is RegisterOrRefresh for a command that
// REGENERATES an artifact: when the registry already pins exactly the bytes on
// disk at this (resolved) path — same sha256, same kind — the call does
// nothing at all: no row write, no artifact.refreshed event. Anything else
// takes the RegisterOrRefresh path (mint the row, migrate the kind, refresh),
// so an unchanged regeneration cannot manufacture a refresh event for bytes
// nobody changed.
//
// It is deliberately NOT the behaviour of RegisterOrRefresh itself: the
// explicit operator verbs (RefreshArtifact, artifact-register) keep logging a
// hash-equal refresh, because re-registering or re-hashing IS an act whose
// provenance must land (r12 note on refreshArtifact). A rebuild command is the
// other case — the act is conditional on the bytes moving.
//
// refreshed reports whether the registry was actually touched. The caller is
// expected to hold the campaign lock across the write and this call (the
// lock is re-entrant, counted), so the bytes and the row that pins them are
// one window.
func (c *Campaign) RegisterOrRefreshIfChanged(kind, path, note string,
	snapshotID *string, reason string) (id string, refreshed bool, err error) {
	if err := c.LockProcess(); err != nil {
		return "", false, err
	}
	defer c.UnlockProcess()
	currentID, current, err := c.artifactRowCurrent(kind, path)
	if err != nil {
		return "", false, err
	}
	if current {
		return currentID, false, nil
	}
	got, _, err := c.RegisterOrRefreshKeptGhosts(kind, path, note, snapshotID,
		reason)
	if err != nil {
		return "", false, err
	}
	return got, true, nil
}

// artifactRowCurrent reports whether the registry already pins the bytes on
// disk at path, and returns the id of the row RegisterOrRefresh would have
// refreshed (the latest at the resolved path — the same selection, tie-break
// included, that RegisterOrRefreshKeptGhosts makes). A requested kind that
// differs from the row's is NOT current: the D3 kind migration is a real
// change and must still land.
func (c *Campaign) artifactRowCurrent(kind, path string) (string, bool, error) {
	resolved := resolvePath(path)
	st, err := c.State()
	if err != nil {
		return "", false, err
	}
	latest := validation.VNull()
	for _, a := range validation.ObjAt(st, "artifacts").A {
		if resolvePath(c.resolveArtifactPath(a)) != resolved {
			continue
		}
		if latest.Kind != validation.Obj ||
			validation.ObjStr(a, "registered_at") > validation.ObjStr(latest, "registered_at") {
			latest = a
		}
	}
	if latest.Kind != validation.Obj {
		return "", false, nil
	}
	if kind != "" && validation.ObjStr(latest, "kind") != kind {
		return validation.ObjStr(latest, "artifact_id"), false, nil
	}
	sha, err := validation.Sha256File(path)
	if err != nil {
		return validation.ObjStr(latest, "artifact_id"), false, nil
	}
	return validation.ObjStr(latest, "artifact_id"),
		sha != "" && validation.ObjStr(latest, "sha256") == sha, nil
}
