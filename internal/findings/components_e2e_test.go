// Components end-to-end (Task 6, G9): a frontend component + a
// frontend-injection finding flow through ingest → gate dry-run → report
// like contract findings, while structidx never pretends over the
// component tree.
//
// TDD: written BEFORE the tracked-but-opaque renderers; the report-excerpt
// assertions must FAIL (no component line) until report.go renders the
// block. The prescreen/prior/seam assertions pin laws without changing
// the code they cover.
package findings_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/archetypes"
	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/orchestrator"
	"websec/internal/protocolgraph"
	"websec/internal/report"
	"websec/internal/risk"
	"websec/internal/sandbox"
	"websec/internal/sharedmem"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

const e2eSwapHTML = `<!doctype html><html><body>
<form id="swap" onsubmit="return approveAndSwap(this)">
<input id="spender" name="spender"><input id="amount" name="amount">
</form><script src="https://third-party.example/widget.js"></script>
</body></html>
`

// e2eCamp builds a fixture campaign whose pinned tree is a frontend app/
// subtree: app/swap.html plus one contract so the campaign is not
// degenerate.
func e2eCamp(t *testing.T) (*state.Campaign, string, string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Component Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	app := filepath.Join(target, "app")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "swap.html"),
		[]byte(e2eSwapHTML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"),
		[]byte("contract Vault {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c, target, app
}

// e2eModel is a protocol model with one paid, in-scope frontend component.
func e2eModel() validation.Value {
	return validation.VObj(
		validation.KV{K: "protocol_id", V: validation.VStr("p")},
		validation.KV{K: "name", V: validation.VStr("nn")},
		validation.KV{K: "contracts", V: validation.VArr()},
		validation.KV{K: "actors", V: validation.VArr()},
		validation.KV{K: "assets", V: validation.VArr()},
		validation.KV{K: "relations", V: validation.VArr()},
		validation.KV{K: "components", V: validation.VArr(validation.VObj(
			validation.KV{K: "kind", V: validation.VStr("frontend")},
			validation.KV{K: "path", V: validation.VStr("app/")},
			validation.KV{K: "trust", V: validation.VStr("untrusted")},
			validation.KV{K: "in_scope", V: validation.VBool(true)},
			validation.KV{K: "paid_for", V: validation.VBool(true)},
		))},
	)
}

func e2eObjAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V
		}
	}
	return validation.VNull()
}

func e2eObjStr(v validation.Value, key string) string {
	got := e2eObjAt(v, key)
	if got.Kind == validation.Str {
		return got.S
	}
	return ""
}

// seedE2EMemory installs one promoted shared row (MEM-shared01) through
// the public seams so RecordMemoryCheck verifies.
func seedE2EMemory(t *testing.T) {
	t.Helper()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(t.TempDir(), "gmem"))
	row := validation.VObj(
		validation.KV{K: "memory_id", V: validation.VStr("MEM-shared01")},
		validation.KV{K: "campaign_id", V: validation.VStr("ingest:test:case")},
		validation.KV{K: "finding_id", V: validation.VNull()},
		validation.KV{K: "snapshot_id", V: validation.VNull()},
		validation.KV{K: "created_at", V: validation.VStr("2026-09-06T00:00:00+00:00")},
		validation.KV{K: "kind", V: validation.VStr("confirmed")},
		validation.KV{K: "status", V: validation.VStr("CONFIRMED")},
		validation.KV{K: "pattern", V: validation.VStr("Shared memory pattern")},
		validation.KV{K: "bug_class", V: validation.VStr("logic-error")},
		validation.KV{K: "cwe", V: validation.VNull()},
		validation.KV{K: "evidence_summary", V: validation.VStr("Seeded incident.")},
		validation.KV{K: "partition", V: validation.VStr("dev")},
		validation.KV{K: "schema_version", V: validation.VInt(2)},
		validation.KV{K: "rejection_class", V: validation.VNull()},
		validation.KV{K: "deciding_propositions", V: validation.VArr()},
		validation.KV{K: "promotion_status", V: validation.VStr("promoted")},
		validation.KV{K: "approved_by", V: validation.VStr("operator")},
		validation.KV{K: "approved_at", V: validation.VStr("2026-09-06T00:00:00+00:00")})
	gdir := sharedmem.GlobalStoreDir()
	if err := os.MkdirAll(gdir, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := validation.VObj(
		validation.KV{K: "program_key", V: validation.VStr("test|other|-")},
		validation.KV{K: "published_at", V: validation.VStr("2026-09-06T00:00:00+00:00")},
		validation.KV{K: "row", V: row},
		validation.KV{K: "scope", V: validation.VStr("global")})
	if err := validation.WriteJson(filepath.Join(gdir, "memory.json"),
		validation.VArr(wrapper), ""); err != nil {
		t.Fatal(err)
	}
	findings.SetSharedMemoryRows(sharedmem.LoadSharedMemory)
	findings.SetLearningAllMemory(learning.AllMemory)
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(
			func(string) ([]validation.Value, error) { return nil, nil })
		findings.SetLearningAllMemory(
			func(*state.Campaign) ([]validation.Value, error) { return nil, nil })
	})
}

func e2eDeployment() validation.Value {
	return validation.VObj(
		validation.KV{K: "network", V: validation.VStr("ethereum-mainnet")},
		validation.KV{K: "chain_id", V: validation.VInt(1)},
		validation.KV{K: "contracts", V: validation.VArr(validation.VObj(
			validation.KV{K: "name", V: validation.VStr("Vault")},
			validation.KV{K: "address", V: validation.VStr("0xabababababababababababababababababababab")},
			validation.KV{K: "source_match", V: validation.VStr("verified")},
		))},
	)
}

// TestComponentsE2E_ComponentFindingFlows is the doc's test clause: a
// frontend-injection finding anchored on the pinned app/ tree ingests,
// clears the CONFIRMED gate dry-run, and surfaces in the report next to
// the tracked-but-opaque component line.
func TestComponentsE2E_ComponentFindingFlows(t *testing.T) {
	t.Setenv("FORK_RPC_URL", "https://rpc.example")
	c, _, app := e2eCamp(t)
	seedE2EMemory(t)
	if _, err := protocolgraph.SaveModel(c, e2eModel(), ""); err != nil {
		t.Fatal(err)
	}
	// Snapshot pins the frontend subtree: the content hash cited below
	// must equal the pinned tree's hash at assert time.
	wantHash, _, err := snapshot.ContentHash(app)
	if err != nil {
		t.Fatal(err)
	}
	f, err := findings.IngestHypothesis(c, validation.VObj(
		validation.KV{K: "title", V: validation.VStr(
			"DOM-XSS sink in the swap approval flow redirects user approvals")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("frontend-injection")},
			validation.KV{K: "description", V: validation.VStr(
				"the swap page reflects attacker-controlled spender input")},
		)},
		// The affected anchor cites the file; the schema's affected items
		// carry no hash field (additionalProperties:false), so the pinned
		// content hash rides the evidence description instead.
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("app/swap.html")},
			validation.KV{K: "function", V: validation.VStr("approveAndSwap")},
			validation.KV{K: "entry_point", V: validation.VBool(true)},
		))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()},
		)},
	), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := e2eObjStr(f, "finding_id")
	if fid == "" {
		t.Fatal("ingest minted no finding id")
	}
	if aff := e2eObjAt(f, "affected"); aff.Kind != validation.Arr ||
		len(aff.A) != 1 || e2eObjStr(aff.A[0], "path") != "app/swap.html" {
		t.Fatalf("affected anchor = %v, want app/swap.html", aff)
	}
	// The pin proof: ingest stamps the active snapshot as the finding's
	// source pin.
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	if sid == nil || e2eObjStr(e2eObjAt(f, "snapshot_ids"), "source") != *sid {
		t.Fatalf("finding source pin ≠ active snapshot %v", sid)
	}
	// R3-3 ripple: POSSIBLE carries an E2 floor — the triage read earns
	// it before the stamp (the E4 exec evidence below stands on it).
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		validation.KV{K: "evidence_id", V: validation.VStr("EV-triage")},
		validation.KV{K: "level", V: validation.VStr("E2")},
		validation.KV{K: "type", V: validation.VStr("manual")},
		validation.KV{K: "description",
			V: validation.VStr("manual code/traffic read at triage")},
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage",
		"triage", "", false); err != nil {
		t.Fatal(err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "node repro/dom_xss_repro.js", FindingID: &fid,
		ReportedBy: "e2e-harness",
		StdoutText: "REPRODUCED: approval redirected to attacker\n"})
	if err != nil {
		t.Fatal(err)
	}
	desc := "independent reproduction of the DOM-XSS sink in app/swap.html " +
		"(pinned content " + wantHash + ")"
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		validation.KV{K: "evidence_id", V: validation.VStr("EV-domxss")},
		validation.KV{K: "level", V: validation.VStr("E6")},
		validation.KV{K: "type", V: validation.VStr("manual")},
		validation.KV{K: "description", V: validation.VStr(desc)},
		validation.KV{K: "sandbox_profile", V: e2eObjAt(rec, "profile")},
		validation.KV{K: "artifact_id", V: e2eObjAt(rec, "exec_id")},
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"sink traced to spender reflection"); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			validation.KV{K: "memory_ids", V: validation.VArr(
				validation.VStr("MEM-shared01"))},
			validation.KV{K: "mode", V: validation.VStr("negative")})}); err != nil {
		t.Fatal(err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := e2eObjAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		validation.KV{K: "status", V: validation.VStr("reproduced")},
		validation.KV{K: "tier_reached", V: validation.VStr("T3")},
		validation.KV{K: "attempts", V: validation.VArr()}))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	// A deployment pin (no chain pin: frontend-injection is a
	// single-chain E6 class, so no cross-chain witness is demanded) plus
	// FORK_RPC_URL clears the structural reachability arm.
	if _, err := snapshot.AttachDeploymentPin(c, *sid, e2eDeployment()); err != nil {
		t.Fatal(err)
	}
	reloaded, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := findings.ConfirmationGateDetail(c, reloaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail) != 0 {
		t.Fatalf("gate dry-run failures = %v, want CONFIRMED-eligible", detail)
	}
	// The pinned tree did not drift: the cited hash still matches.
	nowHash, _, err := snapshot.ContentHash(app)
	if err != nil {
		t.Fatal(err)
	}
	if nowHash != wantHash {
		t.Fatalf("pinned content hash moved: %q vs cited %q", nowHash, wantHash)
	}
	if !strings.Contains(desc, wantHash) {
		t.Fatalf("evidence citation lost the hash: %q", desc)
	}
	path, err := report.Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "- frontend app/: in_scope, paid") {
		t.Fatal("report excerpt missing the tracked-but-opaque component line")
	}
	if !strings.Contains(text, fid) {
		t.Fatal("report excerpt missing the component finding")
	}
}

// TestComponentsE2E_PrescreenNeverPretends pins the opaque-surface law:
// the snapshot hashes everything (swap.html is listed) but the INDEX is
// the solidity parser, so prescreen over a component-only tree yields
// zero archetype hits.
func TestComponentsE2E_PrescreenNeverPretends(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Opaque Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	comp := filepath.Join(root, "frontend-only")
	app := filepath.Join(comp, "app")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "swap.html"),
		[]byte(e2eSwapHTML), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, comp, nil, nil); err != nil {
		t.Fatal(err)
	}
	tree, err := structidx.IndexTreeValue(comp)
	if err != nil {
		t.Fatal(err)
	}
	if n := e2eObjAt(tree, "nodes"); n.Kind != validation.Arr || len(n.A) != 0 {
		t.Fatalf("component-only index must hold zero nodes, got %v", n)
	}
	if o := e2eObjAt(tree, "other_files_listed"); o.Kind != validation.Int ||
		o.I != 1 {
		t.Fatalf("snapshot must still list swap.html, got %v", o)
	}
	rep, err := archetypes.Prescreen(c, comp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m := e2eObjAt(rep, "matched_ids"); m.Kind != validation.Arr ||
		len(m.A) != 0 {
		t.Fatalf("prescreen over components matched %v, want zero hits", m)
	}
}

// e2eCase builds one eval case row for the priors law test.
func e2eCase(class, outcome string) validation.Value {
	return validation.VObj(validation.KV{K: "gold", V: validation.VObj(
		validation.KV{K: "bug_class", V: validation.VStr(class)},
		validation.KV{K: "outcome", V: validation.VStr(outcome)},
	)})
}

// TestComponentsE2E_PaidForPriorPath pins the paid-for join law at the
// seam it actually lives on: AcceptancePriorsFrom. A class with no
// adjudicated rows never appears in the map (the consumer falls back to
// the global prior); a thin class carries the global rate under its own
// name with Fallback; a thick class carries its own number and is
// eligible for G3 priors. No code changes: the fallback IS the law.
func TestComponentsE2E_PaidForPriorPath(t *testing.T) {
	thick := []validation.Value{
		e2eCase("reentrancy", risk.AcceptedOutcome),
		e2eCase("reentrancy", "disproved"),
		e2eCase("reentrancy", risk.AcceptedOutcome),
	}
	priors, global := risk.AcceptancePriorsFrom(thick, 3)
	if _, ok := priors["frontend-injection"]; ok {
		t.Fatal("unknown class must not appear in the prior map " +
			"(consumer falls back to global)")
	}
	if global.Fallback {
		t.Fatal("the global prior is always exact, never fallback")
	}
	thin := append(append([]validation.Value{}, thick...),
		e2eCase("frontend-injection", risk.AcceptedOutcome),
		e2eCase("frontend-injection", "disproved"))
	priors, global = risk.AcceptancePriorsFrom(thin, 3)
	p, ok := priors["frontend-injection"]
	if !ok {
		t.Fatal("thin class must appear in the map as a fallback carrier")
	}
	if !p.Fallback || p.N != 2 {
		t.Fatalf("thin prior = %+v, want Fallback with n=2", p)
	}
	if p.Rate != global.Rate {
		t.Fatalf("thin prior rate %v ≠ global rate %v", p.Rate, global.Rate)
	}
	eligible := append(append([]validation.Value{}, thin...),
		e2eCase("frontend-injection", risk.AcceptedOutcome))
	priors, _ = risk.AcceptancePriorsFrom(eligible, 3)
	p, ok = priors["frontend-injection"]
	if !ok || p.Fallback {
		t.Fatalf("thick class must carry its own prior, got %+v", p)
	}
}

// TestComponentsE2E_ModelWriterValidates proves the brief's no-change
// premise at the exact seam: orchestrator.LoadProtocolModel funnels the
// doc through protocolgraph.SaveModel, which validates — a component
// with an off-enum kind is rejected before anything is written.
func TestComponentsE2E_ModelWriterValidates(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Seam Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	bad := e2eModel()
	comps := e2eObjAt(bad, "components")
	comps.A[0].O = validation.SetOrAppend(comps.A[0].O, "kind",
		validation.VStr("quantum-frontend"))
	_, err = orchestrator.New(c).LoadProtocolModel(bad)
	if err == nil {
		t.Fatal("model with an off-enum component kind must fail validation")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("error %q must name the validation seam", err)
	}
	// Rejected before anything is written: no model artifact lands.
	if _, serr := os.Stat(filepath.Join(c.ArtifactsDir,
		"protocol_model.json")); !os.IsNotExist(serr) {
		t.Fatalf("invalid model must not be written, stat = %v", serr)
	}
}
