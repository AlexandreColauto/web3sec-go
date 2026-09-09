package snapshot

// T35 testmap re-triage:
// tests/test_design_upgrades.py::test_manifest_is_self_describing_and_self_consistent.
// The manifest names every digest, carries the in-tree lockfile hash and the
// configured toolchain, leaves the unattached pins null, and both digests
// recompute from disk.

import (
	"testing"

	"websec/internal/validation"
)

func TestManifestIsSelfDescribingAndSelfConsistent(t *testing.T) {
	root, target := pinTarget(t)
	writeFiles(t, target, map[string]string{
		"requirements.txt": "web3==7.0.0\n",
	})
	c := pinCampaign(t, root, "C-manifestself1")
	cfg := validation.VObj(validation.KV{K: "compiler",
		V: validation.VStr("solc 0.8.28")})
	snap := mustPin(t, c, target, &cfg, nil)
	m := manifestOf(t, snap)

	want := []string{"source_merkle_root", "deployment_merkle_root",
		"chain_fingerprint", "toolchain_fingerprint", "dependency_lock_hash",
		"environment_hash", "manifest_hash"}
	for _, key := range want {
		found := false
		for _, kv := range m.O {
			if kv.K == key {
				found = true
			}
		}
		if !found {
			t.Fatalf("manifest lacks %s: %v", key, manifestKeys(m))
		}
	}
	// requirements.txt is in-tree and config was provided
	for _, key := range []string{"dependency_lock_hash", "toolchain_fingerprint"} {
		if got := objField(t, m, key); got.Kind != validation.Str || !hex64Re.MatchString(got.S) {
			t.Errorf("%s = %v, want a 64-hex digest", key, got)
		}
	}
	// no deployment/chain pin attached yet
	for _, key := range []string{"deployment_merkle_root", "chain_fingerprint"} {
		if got := objField(t, m, key); got.Kind != validation.Null {
			t.Errorf("%s = %v, want null", key, got)
		}
	}
	srcDir := strField(t, objField(t, snap, "source"), "root")
	wantRoot, err := SourceMerkleRoot(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strField(t, m, "source_merkle_root"); got != wantRoot {
		t.Errorf("source_merkle_root = %q, want %q", got, wantRoot)
	}
	var fields []validation.KV
	for _, kv := range m.O {
		if kv.K != "manifest_hash" {
			fields = append(fields, validation.KV{K: kv.K, V: kv.V})
		}
	}
	if got := ManifestHash(validation.VObj(fields...)); got != strField(t, m, "manifest_hash") {
		t.Errorf("ManifestHash(fields) = %q, want %q", got,
			strField(t, m, "manifest_hash"))
	}
}
