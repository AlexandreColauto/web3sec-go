// artifacts_reconcile.go: the operator's batch re-hash
// (ReconcileArtifacts), the sha-pinned byte reader, and the path resolver
// export.
package state

import (
	"fmt"
	"os"
	"websec/internal/validation"
)

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
	rows := append([]validation.Value{}, validation.ObjAt(st, "artifacts").A...)
	refreshed := []validation.Value{}
	missing := []validation.Value{}
	unchanged := int64(0)
	for _, a := range rows {
		id := validation.ObjStr(a, "artifact_id")
		p := c.resolveArtifactPath(a)
		if _, err := os.Stat(p); err != nil {
			missing = append(missing, validation.VObj(
				kv("artifact_id", validation.VStr(id)),
				kv("path", validation.VStr(p))))
			continue
		}
		stored := validation.ObjAt(a, "sha256")
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
	stored := validation.ObjStr(row, "sha256")
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
