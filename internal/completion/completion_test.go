// Port of tests/test_completion_proof.py — the protocol-model completion
// proof requires the SEEDED registry (run-2 feedback A4). The stage used to
// auto-complete on `artifacts/protocol_model.json` existing; a load that
// saved the artifact but silently seeded zero invariants passed.
package completion

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/invariants"
	"websec/internal/protocolgraph"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// modelWith is the Python MODEL dict; invs overrides the invariants list
// (`{**MODEL, "invariants": ...}`).
func modelWith(invs ...validation.Value) validation.Value {
	return validation.VObj(
		kv("protocol_id", validation.VStr("vault")),
		kv("name", validation.VStr("Vault")),
		kv("snapshot_id", validation.VStr("unpinned")),
		kv("chains", validation.VArr(validation.VStr("ethereum"))),
		kv("subsystems", validation.VArr(validation.VStr("defi-vault"))),
		kv("contracts", validation.VArr(validation.VObj(
			kv("name", validation.VStr("Vault")),
			kv("path", validation.VStr("Vault.sol")),
			kv("role", validation.VStr("core")),
			kv("in_scope", validation.VBool(true)),
			kv("entry_points", validation.VArr(validation.VStr("deposit"))),
			kv("state_variables", validation.VArr(validation.VObj(
				kv("name", validation.VStr("totalAssets")),
				kv("kind", validation.VStr("balance")),
				kv("accounting", validation.VBool(true))))),
		))),
		kv("actors", validation.VArr(validation.VObj(
			kv("id", validation.VStr("user")),
			kv("kind", validation.VStr("EOA")),
			kv("trust", validation.VStr("externally-owned"))))),
		kv("assets", validation.VArr(validation.VObj(
			kv("id", validation.VStr("share")),
			kv("kind", validation.VStr("share")),
			kv("erc", validation.VStr("4626")),
			kv("decimals", validation.VInt(18))))),
		kv("relations", validation.VArr()),
		kv("invariants", validation.VArr(invs...)),
	)
}

func model() validation.Value {
	return modelWith(validation.VObj(
		kv("id", validation.VStr("INV-1")),
		kv("statement", validation.VStr(
			"the exchange rate must not move for existing shares")),
		kv("applies_to", validation.VArr(validation.VStr("Vault"))),
		kv("kind", validation.VStr("economic")),
		kv("severity_if_broken", validation.VStr("critical"))))
}

// proofCamp is _camp(tmp_path).
func proofCamp(t *testing.T) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "proof", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"),
		[]byte("contract Vault {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// proof is `CMP.PROOFS["protocol-model"](c)`.
func proof(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	res, err := Proofs["protocol-model"](c)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func isDone(t *testing.T, res validation.Value) bool {
	t.Helper()
	d, ok := fieldAt(res, "done")
	if !ok || d.Kind != validation.Bool {
		t.Fatalf("proof has no bool done: %s", validation.CanonCompact(res))
	}
	return d.B
}

func missingOf(t *testing.T, res validation.Value) []string {
	t.Helper()
	miss, ok := fieldAt(res, "missing")
	if !ok || miss.Kind != validation.Arr {
		t.Fatalf("proof has no missing list: %s", validation.CanonCompact(res))
	}
	return strList(miss)
}

func anyContains(items []string, needle string) bool {
	for _, s := range items {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func TestNoModelNotDone(t *testing.T) {
	c := proofCamp(t)
	res := proof(t, c)
	if isDone(t, res) {
		t.Fatal("a campaign without a model must not be done")
	}
	if !anyContains(missingOf(t, res), "protocol_model.json") {
		t.Errorf("missing must name the artifact: %v", missingOf(t, res))
	}
}

// TestZeroInvariantModelNotDone: a model that declares no invariants is not
// auditable — the seed step has nothing to seed, and the stage must say so.
func TestZeroInvariantModelNotDone(t *testing.T) {
	c := proofCamp(t)
	if _, err := protocolgraph.SaveModel(c, modelWith(), ""); err != nil {
		t.Fatal(err)
	}
	res := proof(t, c)
	if isDone(t, res) {
		t.Fatal("a zero-invariant model must not be done")
	}
	if !anyContains(missingOf(t, res), "no invariants") {
		t.Errorf("missing must say no invariants: %v", missingOf(t, res))
	}
}

// TestSavedButUnseededNotDone: the run-2 failure state — the artifact
// exists, the registry is empty; the proof must fail with the unseeded ids
// named, not on the file.
func TestSavedButUnseededNotDone(t *testing.T) {
	c := proofCamp(t)
	// saves the artifact; deliberately does NOT seed
	if _, err := protocolgraph.SaveModel(c, model(), ""); err != nil {
		t.Fatal(err)
	}
	res := proof(t, c)
	if isDone(t, res) {
		t.Fatal("a saved-but-unseeded model must not be done")
	}
	if !anyContains(missingOf(t, res), "INV-1") ||
		!anyContains(missingOf(t, res), "registry") {
		t.Errorf("missing must name INV-1 and the registry: %v", missingOf(t, res))
	}
	if note := objStr(res, "note"); !strings.Contains(note, "unseeded") {
		t.Errorf("note must say unseeded, got %q", note)
	}
}

// TestLoadedAndSeededIsDone is test_loaded_and_seeded_is_done.
//
// PORT-NOTE: the Python test drives ORC.Orchestrator(c).load_protocol_model
// (orchestrator.py is not ported). The portable part — save_model +
// load_model + invariants.seed_from_model — is inlined here.
func TestLoadedAndSeededIsDone(t *testing.T) {
	c := proofCamp(t)
	path, err := protocolgraph.SaveModel(c, model(), "")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := protocolgraph.LoadModel(c, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invariants.SeedFromModel(c, loaded); err != nil {
		t.Fatal(err)
	}
	res := proof(t, c)
	if !isDone(t, res) {
		t.Fatalf("loaded + seeded must be done, missing=%v", missingOf(t, res))
	}
	if note := objStr(res, "note"); !strings.Contains(note, "seeded") {
		t.Errorf("note must say seeded, got %q", note)
	}
}

// TestPartialSeedNamesTheGap: two invariants, one seeded — the missing one
// is named.
func TestPartialSeedNamesTheGap(t *testing.T) {
	c := proofCamp(t)
	two := modelWith(
		validation.VObj(
			kv("id", validation.VStr("INV-1")),
			kv("statement", validation.VStr(
				"the exchange rate must not move for existing shares")),
			kv("applies_to", validation.VArr(validation.VStr("Vault"))),
			kv("kind", validation.VStr("economic")),
			kv("severity_if_broken", validation.VStr("critical"))),
		validation.VObj(
			kv("id", validation.VStr("INV-2")),
			kv("statement", validation.VStr(
				"deposits must mint shares at the pre-deposit rate")),
			kv("applies_to", validation.VArr(validation.VStr("Vault"))),
			kv("kind", validation.VStr("economic")),
			kv("severity_if_broken", validation.VStr("high"))))
	if _, err := protocolgraph.SaveModel(c, two, ""); err != nil {
		t.Fatal(err)
	}
	links := validation.VObj(kv("invariants", validation.VObj(
		kv("INV-1", validation.VObj(
			kv("status", validation.VStr("CHECKED_AGAINST_CODE")),
			kv("source", validation.VStr("model")))))))
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	res := proof(t, c)
	if isDone(t, res) {
		t.Fatal("a partial seed must not be done")
	}
	if !anyContains(missingOf(t, res), "INV-2") {
		t.Errorf("missing must name INV-2: %v", missingOf(t, res))
	}
}
