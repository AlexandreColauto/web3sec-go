// Package sharedmem is a 1:1 port of webv2/shared_memory.py: the
// cross-campaign store of DERIVED knowledge (capability signatures of
// CONFIRMED findings/CHAINs plus human-approved memory rows), in two tiers
// (root + user-global), with a hash-chained manifest, a sanctioned
// scope-change operation, a derived advisory recall, and a verifier.
//
// I6 adds one inbound-only artifact: an operator-supplied disclosure bundle
// (see disclosure.go). Its CONTENTS never enter shared memory — the bundle is
// a campaign-local file, and the publish record carries only
// disclosure_sha256 and disclosure_embargo_until. Shared memory is a
// cross-campaign surface; free-text impact narratives do not belong on it.
// The embargo is recorded, never enforced.
package sharedmem

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/validation"
)

// StoreDirname is _STORE_DIRNAME.
const StoreDirname = "shared-memory"

const (
	sigsName     = "signatures.json"
	memName      = "memory.json"
	manifestName = "manifest.json"
)

// PublishableStatuses is _PUBLISHABLE_STATUSES.
var PublishableStatuses = []string{"CONFIRMED", "CHAIN"}

// ApprovedMemory is _APPROVED_MEMORY.
var ApprovedMemory = []string{"human-approved", "promoted"}

// Scopes is _SCOPES.
var Scopes = []string{"program", "global"}

// ---- store locations + IO --------------------------------------------------

// StoreDir is store_dir: the ROOT-tier store (shared by every campaign
// under this root).
func StoreDir(root string) string {
	return filepath.Join(root, StoreDirname)
}

// GlobalStoreDir is global_store_dir: the USER-GLOBAL tier.
// $WEBV2_GLOBAL_MEMORY_DIR overrides the location.
func GlobalStoreDir() string {
	if override := os.Getenv("WEBV2_GLOBAL_MEMORY_DIR"); override != "" {
		if strings.HasPrefix(override, "~") {
			home, err := os.UserHomeDir()
			if err == nil {
				override = filepath.Join(home, strings.TrimPrefix(override, "~"))
			}
		}
		return override
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".webv2", StoreDirname)
	}
	return filepath.Join(home, ".webv2", StoreDirname)
}

// StoreDirs is store_dirs: every store a campaign under `root` reads from,
// in precedence order (root tier first), deduped by resolved path.
func StoreDirs(root string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, d := range []string{StoreDir(root), GlobalStoreDir()} {
		key := resolvePath(d)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out
}

func resolvePath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	return p
}

func sigsPath(store string) string     { return filepath.Join(store, sigsName) }
func memPath(store string) string      { return filepath.Join(store, memName) }
func manifestPath(store string) string { return filepath.Join(store, manifestName) }

// loadList is _load_list.
func loadList(path string) ([]validation.Value, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	data, err := validation.ReadJson(path)
	if err != nil {
		return nil, err
	}
	if data.Kind != validation.Arr {
		return nil, fmt.Errorf("%s must be a list", filepath.Base(path))
	}
	return data.A, nil
}

func tierSignatures(store string) ([]validation.Value, error) {
	return loadList(sigsPath(store))
}

func tierMemory(store string) ([]validation.Value, error) {
	return loadList(memPath(store))
}

func tierManifest(store string) ([]validation.Value, error) {
	return loadList(manifestPath(store))
}
