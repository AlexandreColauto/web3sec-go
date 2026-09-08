// Port of the Task 12 manifest behaviors: refresh_manifest self-anchoring,
// source/lock/toolchain/deployment/chain fingerprints, and the Python
// LOCKFILE_NAMES set (10 names, in order).
package snapshot

import (
	"path/filepath"
	"regexp"
	"testing"

	"websec/internal/validation"
)

var hex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

func manifestOf(t *testing.T, snap validation.Value) validation.Value {
	t.Helper()
	for _, kv := range snap.O {
		if kv.K == "manifest" {
			return kv.V
		}
	}
	t.Fatal("snapshot has no manifest")
	return validation.VNull()
}

func manifestKeys(m validation.Value) []string {
	out := make([]string, len(m.O))
	for i, kv := range m.O {
		out[i] = kv.K
	}
	return out
}

func TestLockfileNamesMatchPython(t *testing.T) {
	want := []string{
		"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"Cargo.lock", "go.sum", "uv.lock", "poetry.lock",
		"Pipfile.lock", "requirements.txt", "Foundry.lock",
	}
	if len(LockfileNames) != len(want) {
		t.Fatalf("LockfileNames len = %d, want %d", len(LockfileNames), len(want))
	}
	for i := range want {
		if LockfileNames[i] != want[i] {
			t.Fatalf("LockfileNames[%d] = %q, want %q", i, LockfileNames[i], want[i])
		}
	}
}

func TestManifestHashSelfAnchors(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-manifesthash1")
	snap := mustPin(t, c, target, nil, nil)
	m := manifestOf(t, snap)

	var fields []validation.KV
	for _, kv := range m.O {
		if kv.K != "manifest_hash" {
			fields = append(fields, validation.KV{K: kv.K, V: kv.V})
		}
	}
	if got := ManifestHash(validation.VObj(fields...)); got != strField(t, m, "manifest_hash") {
		t.Fatalf("ManifestHash(fields) = %q, want manifest_hash %q", got, strField(t, m, "manifest_hash"))
	}
	if !hex64Re.MatchString(strField(t, m, "manifest_hash")) {
		t.Fatalf("manifest_hash %q is not 64-hex", strField(t, m, "manifest_hash"))
	}
}

func TestManifestKeyOrder(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-manifestorder1")
	snap := mustPin(t, c, target, nil, nil)
	got := manifestKeys(manifestOf(t, snap))
	want := []string{"source_merkle_root", "deployment_merkle_root",
		"chain_fingerprint", "toolchain_fingerprint", "dependency_lock_hash",
		"environment_hash", "manifest_hash"}
	if len(got) != len(want) {
		t.Fatalf("manifest keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("manifest keys = %v, want %v", got, want)
		}
	}
}

func TestManifestSourceRootMatches(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-manifestsrc1")
	snap := mustPin(t, c, target, nil, nil)
	m := manifestOf(t, snap)
	dir := strField(t, objField(t, snap, "source"), "root")
	want, err := SourceMerkleRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strField(t, m, "source_merkle_root"); got != want {
		t.Fatalf("source_merkle_root = %q, want %q", got, want)
	}
	_ = root
}

func TestManifestLockfilesAbsentThenPresent(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-manifestlock1")
	snap := mustPin(t, c, target, nil, nil)
	m := manifestOf(t, snap)
	for _, kv := range m.O {
		if kv.K == "dependency_lock_hash" && kv.V.Kind != validation.Null {
			t.Fatalf("dependency_lock_hash without lockfiles = %v, want null", kv.V)
		}
	}
	writeFiles(t, target, map[string]string{"package-lock.json": `{"name":"x"}`})
	snap2 := mustPin(t, c, target, nil, nil)
	m2 := manifestOf(t, snap2)
	dir2 := strField(t, objField(t, snap2, "source"), "root")
	want, err := MerkleRootOfVisibleLockfiles(dir2)
	if err != nil {
		t.Fatal(err)
	}
	if got := strField(t, m2, "dependency_lock_hash"); got != want || !hex64Re.MatchString(got) {
		t.Fatalf("dependency_lock_hash = %q, want %q", got, want)
	}
}

func TestManifestToolchainFingerprint(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-manifesttool1")
	plain := manifestOf(t, mustPin(t, c, target, nil, nil))
	for _, kv := range plain.O {
		if kv.K == "toolchain_fingerprint" && kv.V.Kind != validation.Null {
			t.Fatalf("toolchain_fingerprint without foundry.toml = %v, want null", kv.V)
		}
	}
	writeFiles(t, target, map[string]string{"foundry.toml": "[profile.default]\nsol = \"0.8.24\"\n"})
	foundry := manifestOf(t, mustPin(t, c, target, nil, nil))
	if got := strField(t, foundry, "toolchain_fingerprint"); !hex64Re.MatchString(got) {
		t.Fatalf("toolchain_fingerprint = %q, want 64-hex", got)
	}
}

func TestManifestAttachRefreshesRoots(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-manifestattach1")
	snap := mustPin(t, c, target, nil, nil)
	before := strField(t, manifestOf(t, snap), "manifest_hash")

	dep := validation.VObj(
		validation.KV{K: "network", V: validation.VStr("ethereum-mainnet")},
		validation.KV{K: "chain_id", V: validation.VInt(1)},
		validation.KV{K: "contracts", V: validation.VArr(validation.VObj(
			validation.KV{K: "name", V: validation.VStr("Vault")},
			validation.KV{K: "address", V: validation.VStr("0xabababababababababababababababababababab")},
			validation.KV{K: "source_match", V: validation.VStr("verified")},
		))},
	)
	snap2, err := AttachDeploymentPin(c, strField(t, snap, "snapshot_id"), dep)
	if err != nil {
		t.Fatal(err)
	}
	m2 := manifestOf(t, snap2)
	if got := strField(t, m2, "deployment_merkle_root"); !hex64Re.MatchString(got) {
		t.Fatalf("deployment_merkle_root = %q, want 64-hex", got)
	}
	if got := strField(t, m2, "manifest_hash"); got == before {
		t.Fatal("manifest_hash unchanged after deployment attach")
	}
	chain := validation.VObj(
		validation.KV{K: "network", V: validation.VStr("ethereum-mainnet")},
		validation.KV{K: "chain_id", V: validation.VInt(1)},
		validation.KV{K: "fork_block", V: validation.VInt(23456789)},
	)
	snap3, err := AttachChainPin(c, strField(t, snap, "snapshot_id"), chain)
	if err != nil {
		t.Fatal(err)
	}
	m3 := manifestOf(t, snap3)
	if got := strField(t, m3, "chain_fingerprint"); !hex64Re.MatchString(got) {
		t.Fatalf("chain_fingerprint = %q, want 64-hex", got)
	}
	// The on-disk snapshot validates after every attach.
	onDisk, err := validation.ReadJson(filepath.Join(
		strField(t, objField(t, snap3, "source"), "root"), "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(onDisk, "snapshot", 1); err != nil {
		t.Fatalf("on-disk snapshot after attach fails schema: %v", err)
	}
}
