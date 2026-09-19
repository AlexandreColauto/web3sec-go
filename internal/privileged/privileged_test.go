// Port of tests/test_privileged_baseline.py (5) and
// tests/test_privileged_bands.py (5). The Python twin was retired 2026-09-09; this package is the source of truth.
//
// DEVIATION (declared): the Python fixtures confirm findings through the
// validated APIs with a queued/approved memory row; this harness uses
// sandbox.RegisterExec (the honest stand-in for out-of-band runs) plus a
// fixed global-memory row, exactly like the immunize/forkpoc Go tests. No
// gate is bypassed.
package privileged

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"websec/internal/chainengine"
	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func newCampaign(t *testing.T, name string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), name, state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// campaignWithModel is test_privileged_baseline._campaign_with_model.
func campaignWithModel(t *testing.T, name string,
	privileges validation.Value) *state.Campaign {
	t.Helper()
	return campaignWithModelIn(t, t.TempDir(), name, privileges)
}

// campaignWithModelIn is campaignWithModel with an explicit campaign root, so
// twin campaigns can share one directory.
func campaignWithModelIn(t *testing.T, dir, name string,
	privileges validation.Value) *state.Campaign {
	t.Helper()
	c, err := state.Init(dir, name, state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	model := validation.VObj(
		kv("protocol_id", validation.VStr("t")),
		kv("name", validation.VStr("t")),
		kv("contracts", validation.VArr()),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("relations", validation.VArr()),
		kv("privileges", privileges))
	raw, err := json.Marshal(toAnyJSON(model))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.ArtifactsDir, "protocol_model.json"),
		raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return c
}

// toAnyJSON renders a Value through its canonical JSON so the fixture file is
// written byte-identically to the Python fixture's json.dumps.
func toAnyJSON(v validation.Value) any {
	var out any
	if err := json.Unmarshal([]byte(validation.CanonCompact(v)), &out); err != nil {
		panic(err)
	}
	return out
}

// seedGlobalMemory is conftest.seed_global_memory_row.
func seedGlobalMemory(t *testing.T) {
	t.Helper()
	row := validation.VObj(
		kv("memory_id", validation.VStr("MEM-shared01")),
		kv("campaign_id", validation.VStr("ingest:test:case")),
		kv("finding_id", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("kind", validation.VStr("confirmed")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("pattern", validation.VStr("Shared memory pattern")),
		kv("bug_class", validation.VStr("logic-error")),
		kv("cwe", validation.VNull()),
		kv("evidence_summary", validation.VStr("Seeded incident.")),
		kv("partition", validation.VStr("dev")),
		kv("schema_version", validation.VInt(2)),
		kv("rejection_class", validation.VNull()),
		kv("deciding_propositions", validation.VArr()),
		kv("promotion_status", validation.VStr("promoted")),
		kv("approved_by", validation.VStr("operator")),
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")),
	)
	wrapper := validation.VArr(validation.VObj(
		kv("program_key", validation.VStr("test|other|-")),
		kv("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("row", row),
		kv("scope", validation.VStr("global"))))
	findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
		return wrapper.A, nil
	})
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(
			func(string) ([]validation.Value, error) { return nil, nil })
	})
}

// confirmed is test_privileged_baseline._confirmed /
// test_privileged_bands._confirmed: one CONFIRMED access-control finding.
func confirmed(t *testing.T, c *state.Campaign, title string, granted,
	required []string, blast string, extractable *float64, capital *float64) validation.Value {
	t.Helper()
	attacker := validation.VObj(
		kv("profile", validation.VStr("test attacker")),
		kv("capabilities", validation.VArr()))
	if capital != nil {
		attacker.O = append(attacker.O, kv("capital_profile", validation.VObj(
			kv("required_usd", validation.VFloat(*capital)))))
	}
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("cwe", validation.VStr("CWE-862")),
			kv("description", validation.VStr(
				"test fixture: privileged path moves funds")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/MiniVault.sol")),
			kv("contract", validation.VStr("MiniVault")),
			kv("function", validation.VStr("rescue"))))),
		kv("attacker", attacker),
		kv("capabilities", validation.VObj(
			kv("granted", validation.StrArr(granted)),
			kv("required", validation.StrArr(required)))),
	), "attacker", "06", "")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	fid := validation.ObjStr(f, "finding_id")
	driveToConfirmed(t, c, fid, extractable, blast)
	out, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// driveToConfirmed walks one finding through the evidence, critic, memory and
// reproduction gates and lands it CONFIRMED.
func driveToConfirmed(t *testing.T, c *state.Campaign, fid string,
	extractable *float64, blast string) {
	t.Helper()
	// R3-3: the POSSIBLE floor is E2, so the fixture's reachability evidence
	// lands BEFORE the status stamp (evidence floors gate every status). The
	// item is the finding's first rise above E0, so it pays the one discovery
	// slot the POSSIBLE move used to pay; the later exec-backed E4 rides that
	// same rise for free, leaving the slot spend unchanged.
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-reach")),
		kv("level", validation.VStr("E2")),
		kv("type", validation.VStr("reachability")),
		kv("description", validation.VStr("reachable entry point")))); err != nil {
		t.Fatalf("add reachability evidence: %v", err)
	}
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage passed",
		"triage", "", false); err != nil {
		t.Fatalf("transition POSSIBLE: %v", err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_x",
		ReportedBy: "test-harness", FindingID: &fid,
		StdoutText: "PASS: test_x\n"})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	tier := "T1"
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-unit")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("sandboxed unit PoC")),
		kv("sandbox_profile", validation.ObjAt(rec, "profile")),
		kv("artifact_id", validation.ObjAt(rec, "exec_id")))); err != nil {
		t.Fatalf("add unit evidence: %v", err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"no compensating control"); err != nil {
		t.Fatalf("critic verdict: %v", err)
	}
	seedGlobalMemory(t)
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatalf("memory check: %v", err)
	}
	if extractable != nil {
		if _, err := risk.RecordEconomicImpact(c, fid,
			validation.VFloat(*extractable), validation.VFloat(*extractable),
			validation.VNull()); err != nil {
			t.Fatalf("record impact: %v", err)
		}
	}
	pinReproduction(t, c, fid, tier, blast)
	if _, err := findings.Transition(c, fid, "CONFIRMED", "gates passed",
		"", "", false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
}

// pinReproduction writes the reproduced tier (and optional blast radius) onto
// the finding, the last gate before CONFIRMED.
func pinReproduction(t *testing.T, c *state.Campaign, fid, tier, blast string) {
	t.Helper()
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := validation.ObjAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr(tier)),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if blast != "" {
		ei := validation.ObjAt(vf, "economic_impact")
		if ei.Kind != validation.Obj {
			ei = validation.VObj()
		}
		ei.O = validation.SetOrAppend(ei.O, "blast_radius", validation.VStr(blast))
		vf.O = validation.SetOrAppend(vf.O, "economic_impact", ei)
	}
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatalf("save finding: %v", err)
	}
}

func floatPtr(f float64) *float64 { return &f }

// pyStr is Python's str() for the scalar shapes these fixtures carry.
func pyStr(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Null:
		return "None"
	}
	return validation.CanonCompact(v)
}

// --- test_privileged_baseline.py -------------------------------------------

func TestPrivilegedRolesNormalizesDedupesSorts(t *testing.T) {
	model := validation.VObj(kv("privileges", validation.VArr(
		validation.VObj(kv("role", validation.VStr("Owner")),
			kv("capability", validation.VStr("drain"))),
		validation.VObj(kv("role", validation.VStr("owner")),
			kv("capability", validation.VStr("pause"))),
		validation.VObj(kv("role", validation.VStr("governor")),
			kv("capability", validation.VStr("upgrade"))))))
	got := PrivilegedRoles(model)
	if len(got) != 2 || got[0] != "governor" || got[1] != "owner" {
		t.Fatalf("roles = %v", got)
	}
	if len(PrivilegedRoles(validation.VObj())) != 0 {
		t.Fatal("empty model must have no roles")
	}
	if len(PrivilegedRoles(validation.VObj(
		kv("privileges", validation.VArr())))) != 0 {
		t.Fatal("empty table must have no roles")
	}
}

func TestRoleBaselineIsEntrypointPlusRoleLabel(t *testing.T) {
	got := RoleBaseline("owner")
	if len(got) != 2 || got[0] != "call_any_entry_point" ||
		got[1] != "role_owner" {
		t.Fatalf("baseline = %v", got)
	}
}

func TestEOATerminalReportUnaffectedByRoleRequiredFindings(t *testing.T) {
	dir := t.TempDir()
	findings.SetFindingIDSource(findings.PinnedFindingID)
	t.Cleanup(func() { findings.SetFindingIDSource(nil) })
	// twin campaigns: same model, same unprivileged finding; B alone gains a
	// role-required CONFIRMED finding
	privileges := validation.VArr(validation.VObj(
		kv("role", validation.VStr("governor")),
		kv("capability", validation.VStr("drain vault")),
		kv("mechanism", validation.VStr("timelock queue"))))
	mk := func(name string) *state.Campaign {
		return campaignWithModelIn(t, dir, name, privileges)
	}
	a := mk("sep-a")
	findings.ResetPinnedFindingIDs()
	sharedA := confirmed(t, a, "Unprivileged rescue drain",
		[]string{"drain_treasury"}, nil, "", nil, nil)
	b := mk("sep-b")
	findings.ResetPinnedFindingIDs()
	sharedB := confirmed(t, b, "Unprivileged rescue drain",
		[]string{"drain_treasury"}, nil, "", nil, nil)
	roleOnly := confirmed(t, b, "Governor drains the vault",
		[]string{"drain_treasury"}, []string{"role_governor"}, "", nil, nil)
	if validation.ObjStr(sharedB, "finding_id") != validation.ObjStr(sharedA, "finding_id") {
		t.Fatalf("twins minted different ids: %s vs %s",
			validation.ObjStr(sharedA, "finding_id"), validation.ObjStr(sharedB, "finding_id"))
	}
	ra, err := chainengine.TerminalReport(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := chainengine.TerminalReport(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonCompact(ra) != validation.CanonCompact(rb) {
		t.Fatalf("EOA reports differ:\n%s\n%s", validation.CanonCompact(ra),
			validation.CanonCompact(rb))
	}
	if len(listOf(ra, "direct").A) == 0 {
		t.Fatal("shared finding must be a real EOA terminal path")
	}
	if validation.ObjStr(listOf(ra, "direct").A[0], "terminal_finding") !=
		validation.ObjStr(sharedA, "finding_id") {
		t.Fatalf("direct = %v", listOf(ra, "direct"))
	}
	exp, err := PrivilegedExposure(b)
	if err != nil {
		t.Fatal(err)
	}
	roles := listOf(exp, "roles").A
	if len(roles) != 1 || validation.ObjStr(roles[0], "role") != "governor" {
		t.Fatalf("roles = %v", roles)
	}
	found := false
	for _, p := range listOf(roles[0], "direct").A {
		if validation.ObjStr(p, "terminal_finding") == validation.ObjStr(roleOnly, "finding_id") {
			found = true
		}
	}
	if !found {
		t.Fatalf("role-required finding lost: %v", listOf(roles[0], "direct"))
	}
}

func TestRoleCaptureChainComposesOnEOATrack(t *testing.T) {
	c := campaignWithModel(t, "capture", validation.VArr(validation.VObj(
		kv("role", validation.VStr("governor")),
		kv("capability", validation.VStr("drain vault")),
		kv("mechanism", validation.VStr("timelock queue")))))
	fCap := confirmed(t, c, "Multisig key compromise",
		[]string{"role_governor"}, nil, "", nil, nil)
	fDrain := confirmed(t, c, "Governor drains the vault",
		[]string{"drain_treasury"}, []string{"role_governor"}, "", nil, nil)
	rep, err := chainengine.TerminalReport(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range listOf(rep, "shortest_by_terminal").A {
		ps := listOf(p, "path").A
		if len(ps) == 2 && pyStr(ps[0]) == validation.ObjStr(fCap, "finding_id") &&
			pyStr(ps[1]) == validation.ObjStr(fDrain, "finding_id") {
			found = true
		}
	}
	if !found {
		t.Fatalf("two-step capture path missing: %v",
			listOf(rep, "shortest_by_terminal"))
	}
}

func TestPrivilegedExposureNoModel(t *testing.T) {
	c := newCampaign(t, "empty")
	got, err := PrivilegedExposure(c)
	if err != nil {
		t.Fatal(err)
	}
	want := validation.VObj(
		kv("track", validation.VStr("privileged")),
		kv("note", validation.VStr(Note)),
		kv("roles", validation.VArr()))
	if validation.CanonCompact(got) != validation.CanonCompact(want) {
		t.Fatalf("got %s", validation.CanonCompact(got))
	}
}

// --- test_privileged_bands.py ----------------------------------------------

// c is test_privileged_bands._c.
func constraint(kw map[string]validation.Value) validation.Value {
	base := validation.VObj(
		kv("role", validation.VStr("owner")),
		kv("capability", validation.VStr("drain")),
		kv("mechanism", validation.VStr("m")),
		kv("timelocked", validation.VNull()),
		kv("multisig_threshold", validation.VNull()),
		kv("can_drain", validation.VBool(false)))
	out := []validation.KV{}
	for _, k := range []string{"role", "capability", "mechanism", "timelocked",
		"multisig_threshold", "can_drain"} {
		if v, ok := kw[k]; ok {
			out = append(out, kv(k, v))
			continue
		}
		out = append(out, kv(k, validation.ObjAt(base, k)))
	}
	return validation.VObj(out...)
}

func TestBandRules(t *testing.T) {
	tl := func(b bool) validation.Value { return validation.VBool(b) }
	th := func(i int64) validation.Value { return validation.VInt(i) }
	cases := []struct {
		name        string
		constraints []validation.Value
		want        string
	}{
		{"empty", nil, "unconstrained"},
		{"bare", []validation.Value{constraint(nil)}, "unconstrained"},
		{"timelocked", []validation.Value{
			constraint(map[string]validation.Value{"timelocked": tl(true)})},
			"timelocked"},
		{"timelocked null", []validation.Value{constraint(nil)}, "unconstrained"},
		{"threshold 3", []validation.Value{
			constraint(map[string]validation.Value{"multisig_threshold": th(3)})},
			"multi-signatory"},
		{"threshold 2", []validation.Value{
			constraint(map[string]validation.Value{"multisig_threshold": th(2)})},
			"unconstrained"},
		{"timelocked false", []validation.Value{
			constraint(map[string]validation.Value{"timelocked": tl(false)})},
			"unconstrained"},
		{"threshold true", []validation.Value{
			constraint(map[string]validation.Value{"multisig_threshold": tl(true)})},
			"unconstrained"},
		{"timelock beats threshold", []validation.Value{
			constraint(map[string]validation.Value{"multisig_threshold": th(5)}),
			constraint(map[string]validation.Value{"timelocked": tl(true)})},
			"timelocked"},
	}
	for _, tc := range cases {
		if got := ExposureBand(tc.constraints); got != tc.want {
			t.Errorf("%s: band = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestPathConstraintsSortedAndFiltered(t *testing.T) {
	model := validation.VObj(kv("privileges", validation.VArr(
		validation.VObj(kv("role", validation.VStr("owner")),
			kv("capability", validation.VStr("z-drain")),
			kv("timelocked", validation.VBool(true))),
		validation.VObj(kv("role", validation.VStr("owner")),
			kv("capability", validation.VStr("a-pause"))),
		validation.VObj(kv("role", validation.VStr("governor")),
			kv("capability", validation.VStr("b-upgrade"))))))
	cs := PathConstraints(model, "Owner")
	if len(cs) != 2 || validation.ObjStr(cs[0], "capability") != "a-pause" ||
		validation.ObjStr(cs[1], "capability") != "z-drain" {
		t.Fatalf("constraints = %v", cs)
	}
	if len(PathConstraints(model, "nobody")) != 0 {
		t.Fatal("unknown role must have no constraints")
	}
}

func TestUnparseableProtocolModelFailsSoft(t *testing.T) {
	c := newCampaign(t, "corrupt-model")
	if err := os.WriteFile(filepath.Join(c.ArtifactsDir, "protocol_model.json"),
		[]byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if LoadProtocolModel(c) != nil {
		t.Fatal("corrupt model must load as nil")
	}
	exp, err := PrivilegedExposure(c)
	if err != nil {
		t.Fatalf("corrupt model must not raise: %v", err)
	}
	if len(listOf(exp, "roles").A) != 0 {
		t.Fatalf("roles = %v", listOf(exp, "roles"))
	}
}

func TestPathOrderingIsSeverityFirstExtractableSecond(t *testing.T) {
	c := campaignWithModel(t, "ordering", validation.VArr(validation.VObj(
		kv("role", validation.VStr("governor")),
		kv("capability", validation.VStr("drain vault")),
		kv("mechanism", validation.VStr("timelock queue")))))
	confirmed(t, c, "Solvency drain", []string{"drain_treasury"},
		[]string{"role_governor"}, "protocol-solvency", floatPtr(800000), nil)
	confirmed(t, c, "Single user drain",
		[]string{"extract_protocol_liquidity"}, []string{"role_governor"},
		"single-user", floatPtr(50000), nil)
	confirmed(t, c, "Unrecorded blast, deep pockets",
		[]string{"withdraw_unbacked_assets"}, []string{"role_governor"},
		"", nil, floatPtr(10000000))
	exp, err := PrivilegedExposure(c)
	if err != nil {
		t.Fatal(err)
	}
	direct := listOf(listOf(exp, "roles").A[0], "direct").A
	if len(direct) != 3 {
		t.Fatalf("direct = %v", direct)
	}
	want := []string{"drain_treasury", "extract_protocol_liquidity",
		"withdraw_unbacked_assets"}
	for i, w := range want {
		if got := validation.ObjStr(direct[i], "terminal_capability"); got != w {
			t.Fatalf("direct[%d] = %s, want %s (all: %v)", i, got, w, direct)
		}
	}
	if got := validation.ObjAt(direct[2], "total_capital_required_usd"); got.Kind !=
		validation.Flt || got.F != 10000000 {
		t.Fatalf("last path capital = %v, want 1e7", got)
	}
}

func TestExposureEnrichmentCarriesBandConstraintsBlast(t *testing.T) {
	c := campaignWithModel(t, "bands", validation.VArr(validation.VObj(
		kv("role", validation.VStr("owner")),
		kv("capability", validation.VStr("drain vault")),
		kv("mechanism", validation.VStr("timelock queue")),
		kv("timelocked", validation.VBool(true)),
		kv("multisig_threshold", validation.VNull()),
		kv("can_drain", validation.VBool(true)))))
	confirmed(t, c, "Owner drains the vault", []string{"drain_treasury"},
		[]string{"role_owner"}, "all-users", floatPtr(800000), nil)
	exp, err := PrivilegedExposure(c)
	if err != nil {
		t.Fatal(err)
	}
	roles := listOf(exp, "roles").A
	if len(roles) != 1 {
		t.Fatalf("roles = %v", roles)
	}
	role := roles[0]
	if validation.ObjStr(role, "exposure_band") != "timelocked" {
		t.Fatalf("band = %s", validation.ObjStr(role, "exposure_band"))
	}
	cs := listOf(role, "constraints").A
	if len(cs) != 1 || validation.ObjStr(cs[0], "capability") != "drain vault" {
		t.Fatalf("constraints = %v", cs)
	}
	if len(listOf(role, "direct").A) != 1 {
		t.Fatalf("direct = %v", listOf(role, "direct"))
	}
	for _, key := range []string{"direct", "terminal_chains",
		"shortest_by_terminal"} {
		for _, p := range listOf(role, key).A {
			if validation.ObjStr(p, "exposure_band") != "timelocked" {
				t.Fatalf("%s band = %s", key, validation.ObjStr(p, "exposure_band"))
			}
			if validation.CanonCompact(validation.ObjAt(p, "constraints")) !=
				validation.CanonCompact(validation.VArr(cs...)) {
				t.Fatalf("%s constraints = %v", key, validation.ObjAt(p, "constraints"))
			}
			if validation.ObjStr(p, "blast_radius") != "all-users" {
				t.Fatalf("%s blast = %s", key, validation.ObjStr(p, "blast_radius"))
			}
		}
	}
}
