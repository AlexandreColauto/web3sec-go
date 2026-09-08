// Snapshot manifest: the self-describing, self-anchoring summary of a
// snapshot (refresh_manifest + manifest_hash + the lockfile Merkle input).
//
// Ports web3sec-final/src/webv2/snapshot.py::refresh_manifest and
// ::manifest_hash. Promoted here from pin.go (which carried a pin-time
// subset); pin.go now calls RefreshManifest.
package snapshot

import (
	"crypto/sha256"
	"runtime"
	"sort"

	"websec/internal/validation"
)

// ManifestHash is manifest_hash: the digest over the manifest's own fields
// (without manifest_hash) — editing the manifest after the fact breaks it.
func ManifestHash(fields validation.Value) string {
	return validation.Sha256Hex([]byte(Canonical(fields)))
}

// MerkleRootOfVisibleLockfiles is the manifest's dependency_lock_hash input:
// the Merkle root over the file leaves of the pinned files whose NAME is a
// known dependency lockfile, in pinned order. Null-adjacent: returns the
// empty-tree digest when no lockfile is present (the caller keeps null).
func MerkleRootOfVisibleLockfiles(snapDir string) (string, error) {
	locks, err := LockfileLeaves(snapDir)
	if err != nil {
		return "", err
	}
	return MerkleRoot(locks), nil
}

// environmentHash is the manifest's environment_hash: a digest over the
// toolchain that produced the pin.
//
// KNOWN DIVERGENCE (forced by Go, recorded for the gate report): Python
// hashes {"python": sys.version, "platform": platform.platform()}; Go has
// no Python version, so this port hashes {"go": runtime.Version(),
// "platform": GOOS/GOARCH}. Cross-twin parity normalizes environment_hash
// (and the manifest_hash covering it); every other manifest field is
// byte-identical across twins.
func environmentHash() string {
	return validation.Sha256Hex([]byte(Canonical(validation.VObj(
		validation.KV{K: "go", V: validation.VStr(runtime.Version())},
		validation.KV{K: "platform", V: validation.VStr(runtime.GOOS + "/" + runtime.GOARCH)},
	))))
}

// deploymentLeaves mirrors the deployment branch of refresh_manifest: one
// sha256(canonical({address, bytecode_hash, implementation_address,
// proxy_admin})) leaf per contract, contracts sorted by (address or "").
func deploymentLeaves(dep validation.Value) [][]byte {
	contracts := sget(dep, "contracts")
	if contracts.Kind != validation.Arr || len(contracts.A) == 0 {
		return nil
	}
	sorted := make([]validation.Value, len(contracts.A))
	copy(sorted, contracts.A)
	sort.SliceStable(sorted, func(i, j int) bool {
		return contractAddr(sorted[i]) < contractAddr(sorted[j])
	})
	leaves := make([][]byte, len(sorted))
	for i, c := range sorted {
		sum := sha256.Sum256([]byte(Canonical(validation.VObj(
			validation.KV{K: "address", V: sget(c, "address")},
			validation.KV{K: "bytecode_hash", V: sget(c, "bytecode_hash")},
			validation.KV{K: "implementation_address", V: sget(c, "implementation_address")},
			validation.KV{K: "proxy_admin", V: sget(c, "proxy_admin")},
		))))
		leaf := make([]byte, 32)
		copy(leaf, sum[:])
		leaves[i] = leaf
	}
	return leaves
}

func contractAddr(c validation.Value) string {
	if a := sget(c, "address"); a.Kind == validation.Str {
		return a.S
	}
	return "" // Python: c.get("address") or ""
}

// RefreshManifest is refresh_manifest: (re)compute the snapshot's
// self-describing manifest and install it as snap["manifest"] (dict
// assignment: replaced in place when present, appended otherwise). Called
// at pin time and after every deployment/chain attach, so the manifest
// always describes the snapshot exactly as it stands on disk. Key order is
// the Python dict-literal order, contractual for the on-disk dump.
func RefreshManifest(snap validation.Value, snapDir string) (validation.Value, error) {
	files, err := pinnedFiles(snapDir)
	if err != nil {
		return validation.VNull(), err
	}
	leaves := make([][]byte, len(files))
	for i, f := range files {
		leaf, err := FileLeaf(f.abs, snapDir)
		if err != nil {
			return validation.VNull(), err
		}
		leaves[i] = leaf
	}
	manifest := validation.VObj(
		validation.KV{K: "source_merkle_root", V: validation.VStr(MerkleRoot(leaves))},
		validation.KV{K: "deployment_merkle_root", V: validation.VNull()},
		validation.KV{K: "chain_fingerprint", V: validation.VNull()},
		validation.KV{K: "toolchain_fingerprint", V: validation.VNull()},
		validation.KV{K: "dependency_lock_hash", V: validation.VNull()},
		validation.KV{K: "environment_hash", V: validation.VStr(environmentHash())},
	)

	if locks, err := LockfileLeaves(snapDir); err == nil && len(locks) > 0 {
		manifest.O = setOrAppendObj(manifest.O, "dependency_lock_hash",
			validation.VStr(MerkleRoot(locks)))
	}
	if cfg := sget(snap, "config"); cfg.Kind == validation.Obj && len(cfg.O) > 0 {
		manifest.O = setOrAppendObj(manifest.O, "toolchain_fingerprint",
			validation.VStr(validation.Sha256Hex([]byte(Canonical(cfg)))))
	}
	if dep := sget(snap, "deployment"); dep.Kind == validation.Obj && len(dep.O) > 0 {
		if leaves := deploymentLeaves(dep); len(leaves) > 0 {
			manifest.O = setOrAppendObj(manifest.O, "deployment_merkle_root",
				validation.VStr(MerkleRoot(leaves)))
		}
	}
	if ch := sget(snap, "chain"); ch.Kind == validation.Obj && len(ch.O) > 0 {
		manifest.O = setOrAppendObj(manifest.O, "chain_fingerprint",
			validation.VStr(validation.Sha256Hex([]byte(Canonical(validation.VObj(
				validation.KV{K: "network", V: sget(ch, "network")},
				validation.KV{K: "chain_id", V: sget(ch, "chain_id")},
				validation.KV{K: "fork_block", V: sget(ch, "fork_block")},
				validation.KV{K: "fork_block_hash", V: sget(ch, "fork_block_hash")},
			))))))
	}

	manifest.O = append(manifest.O,
		validation.KV{K: "manifest_hash", V: validation.VStr(ManifestHash(manifest))})
	snap.O = setOrAppendObj(snap.O, "manifest", manifest)
	return snap, nil
}
