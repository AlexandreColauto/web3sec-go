// Port of tests/test_report_clusters.py (8 functions) and
// tests/test_report_privileged.py (12 functions). The Python twin was retired 2026-09-09; this package is the source of truth.
//
// DEVIATION (declared): Python's `det` fixture monkeypatches `now_iso` and
// `uuid` module-wide; the Go harness uses the production golden hooks
// WEBV2_NOW / WEBV2_UUID + state.ResetIDStream (the same pins the cross-twin
// golden suite uses), and patches `policy_path` into the state file after
// init because Go's state.InitOpts does not take a policy path yet. The
// isolated per-twin global memory store is the real
// WEBV2_GLOBAL_MEMORY_DIR override, published through the real publish path.
package report

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/floors"
	"websec/internal/learning"
	"websec/internal/relations"
	"websec/internal/reproduction"
	"websec/internal/risk"
	"websec/internal/sandbox"
	"websec/internal/sharedmem"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// kv/objAt/listAt/asObj/pyTruthyInt64Only/count live in report.go (same package).

func seedSharedMemory(t *testing.T) {
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
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")))
	gdir := sharedmem.GlobalStoreDir()
	if err := os.MkdirAll(gdir, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := validation.VObj(
		kv("program_key", validation.VStr("test|other|-")),
		kv("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("row", row),
		kv("scope", validation.VStr("global")))
	if err := validation.WriteJson(filepath.Join(gdir, "memory.json"),
		validation.VArr(wrapper), ""); err != nil {
		t.Fatal(err)
	}
}

func installMemorySeams(t *testing.T) {
	t.Helper()
	findings.SetSharedMemoryRows(sharedmem.LoadSharedMemory)
	findings.SetLearningAllMemory(learning.AllMemory)
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(
			func(string) ([]validation.Value, error) { return nil, nil })
		findings.SetLearningAllMemory(
			func(*state.Campaign) ([]validation.Value, error) { return nil, nil })
	})
}

// ---------------------------------------------------------------------------
// test_report_clusters.py
// ---------------------------------------------------------------------------

// clusterCamp is that module's `camp` fixture.
func clusterCamp(t *testing.T) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	installMemorySeams(t)
	c, err := state.Init(root, "Cluster Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "ShareVault.sol"),
		[]byte("contract ShareVault {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := floors.SetFloorPolicy(c, "share-price-inflation", "E4",
		"pytest-harness", "fixture campaign without a deployment pin: "+
			"E4 sandbox repro is the ceiling"); err != nil {
		t.Fatal(err)
	}
	return c
}

// mk is that module's _mk.
func mk(t *testing.T, camp *state.Campaign, hint, function,
	title string) validation.Value {
	t.Helper()
	f, err := findings.IngestHypothesis(camp, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("share-price-inflation")),
			kv("description", validation.VStr("the vault prices shares from "+
				"the external token balance, an attacker-movable source")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/ShareVault.sol")),
			kv("contract", validation.VStr("ShareVault")),
			kv("function", validation.VStr(function))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.VArr()),
			kv("required", validation.VArr()))),
	), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	rec, err := sandbox.RegisterExec(camp, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "pytest-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatal(err)
	}
	add := func(item validation.Value) {
		t.Helper()
		if _, err := findings.AddEvidence(camp, fid, item); err != nil {
			t.Fatal(err)
		}
	}
	add(validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+hint)),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("repro under sandbox")),
		kv("sandbox_profile", validation.ObjAt(rec, "profile")),
		kv("artifact_id", validation.ObjAt(rec, "exec_id"))))
	add(validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+hint+"-diff")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("differential")),
		kv("description", validation.VStr(
			"differential repro of the same root cause")),
		kv("sandbox_profile", validation.ObjAt(rec, "profile")),
		kv("artifact_id", validation.ObjAt(rec, "exec_id"))))
	// R3-3 ripple: the floor now gates the POSSIBLE stamp (E2), so the
	// exec-backed evidence this fixture already mints lands BEFORE the triage
	// move — same items, same array order; the move just stops being an E0
	// word-stamp.
	if _, err := findings.Transition(camp, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(camp.ArtifactsDir, "impact-"+hint+".json")
	if err := os.WriteFile(art, []byte(`{"extractable_usd": 1000000}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	aid, err := camp.RegisterArtifact("economic-impact", art, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	add(validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+hint+"-econ")),
		kv("level", validation.VStr("E7")),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr(
			"economic impact quantified from the PoC")),
		kv("artifact_id", validation.VStr(aid))))
	if _, err := findings.SetCriticVerdict(camp, fid, "confirmed", "ok"); err != nil {
		t.Fatal(err)
	}
	seedSharedMemory(t)
	if _, err := findings.RecordMemoryCheck(camp, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	vf, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := validation.ObjAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("status", validation.VStr("reproduced")),
		kv("tier_reached", validation.VStr("T3")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(camp, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(camp, fid, "CONFIRMED", "gate", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	out, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// fourSurfaces is that module's _four_surfaces.
func fourSurfaces(t *testing.T, camp *state.Campaign) []validation.Value {
	t.Helper()
	return []validation.Value{
		mk(t, camp, "d1", "deposit", "Empty-pool 1:1 mint via deposit"),
		mk(t, camp, "d2", "deposit", "Deposit share-price set by first actor"),
		mk(t, camp, "dn", "donate", "Donation inflates the share price"),
		mk(t, camp, "ft", "transferWithFee",
			"Fee-on-transfer desync inflates the share price"),
	}
}

// findingSection is that module's _finding_section.
func reportFindingSection(t *testing.T, text, fid string) string {
	t.Helper()
	marker := "- id: `" + fid + "`"
	if !strings.Contains(text, marker) {
		t.Fatalf("no report section for %s", fid)
	}
	tail := strings.SplitN(text, marker, 2)[1]
	if nxt := strings.Index(tail, "\n### "); nxt != -1 {
		return tail[:nxt]
	}
	return tail
}

func mustGenerate(t *testing.T, camp *state.Campaign) string {
	t.Helper()
	path, err := Generate(camp)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestClustersGroupByClassAndLocation(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	view, err := relations.RootCauseClusters(camp)
	if err != nil {
		t.Fatal(err)
	}
	clusters := listAt(view, "clusters")
	if len(clusters) != 1 {
		t.Fatalf("clusters = %d, want 1", len(clusters))
	}
	cl := clusters[0]
	if got := validation.ObjStr(cl, "class"); got != "share-price-inflation" {
		t.Errorf("class = %q", got)
	}
	members := map[string]bool{}
	for _, m := range strList(validation.ObjAt(cl, "members")) {
		members[m] = true
	}
	for _, f := range fs {
		if !members[validation.ObjStr(f, "finding_id")] {
			t.Errorf("%s missing from members", validation.ObjStr(f, "finding_id"))
		}
	}
	if len(members) != 4 {
		t.Errorf("members = %d, want 4", len(members))
	}
	subs := listAt(cl, "subclusters")
	if len(subs) != 3 {
		t.Fatalf("subclusters = %d, want 3", len(subs))
	}
	byLoc := map[string]validation.Value{}
	for _, sc := range subs {
		key := strings.Join(strList(validation.ObjAt(sc, "locations")), "|")
		byLoc[key] = sc
	}
	dep, ok := byLoc["src/ShareVault.sol::deposit"]
	if !ok {
		t.Fatalf("no deposit subcluster: %v", byLoc)
	}
	depIDs := map[string]bool{}
	for _, id := range strList(validation.ObjAt(dep, "finding_ids")) {
		depIDs[id] = true
	}
	if len(depIDs) != 2 || !depIDs[validation.ObjStr(fs[0], "finding_id")] ||
		!depIDs[validation.ObjStr(fs[1], "finding_id")] {
		t.Errorf("deposit finding_ids = %v", depIDs)
	}
	don, ok := byLoc["src/ShareVault.sol::donate"]
	if !ok {
		t.Fatalf("no donate subcluster")
	}
	if got := strList(validation.ObjAt(don, "finding_ids")); len(got) != 1 ||
		got[0] != validation.ObjStr(fs[2], "finding_id") {
		t.Errorf("donate finding_ids = %v", got)
	}
	fee, ok := byLoc["src/ShareVault.sol::transferWithFee"]
	if !ok {
		t.Fatalf("no transferWithFee subcluster")
	}
	if got := strList(validation.ObjAt(fee, "finding_ids")); len(got) != 1 ||
		got[0] != validation.ObjStr(fs[3], "finding_id") {
		t.Errorf("fee finding_ids = %v", got)
	}
}

func TestSingleMemberClassesAreNotClusters(t *testing.T) {
	camp := clusterCamp(t)
	mk(t, camp, "a", "deposit", "A finding alone")
	f2 := mk(t, camp, "b", "withdraw", "B finding alone")
	rc := validation.ObjAt(f2, "root_cause")
	rc.O = validation.SetOrAppend(rc.O, "class", validation.VStr("reentrancy"))
	f2.O = validation.SetOrAppend(f2.O, "root_cause", rc)
	if err := findings.SaveFinding(camp, &f2); err != nil {
		t.Fatal(err)
	}
	view, err := relations.RootCauseClusters(camp)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(listAt(view, "clusters")); got != 0 {
		t.Errorf("clusters = %d, want 0", got)
	}
}

func TestAttestedCausationEdgesAreSurfaced(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	actor := "alice"
	if _, err := relations.MintRelation(camp, "caused_by",
		validation.VObj(kv("type", validation.VStr("finding")),
			kv("id", validation.ObjAt(fs[2], "finding_id"))),
		validation.VObj(kv("type", validation.VStr("finding")),
			kv("id", validation.ObjAt(fs[0], "finding_id"))),
		nil, &actor, nil); err != nil {
		t.Fatal(err)
	}
	view, err := relations.RootCauseClusters(camp)
	if err != nil {
		t.Fatal(err)
	}
	cl := listAt(view, "clusters")[0]
	edges := listAt(cl, "attested_causation")
	if len(edges) != 1 {
		t.Fatalf("attested_causation = %d, want 1", len(edges))
	}
	if validation.ObjStr(edges[0], "src") != validation.ObjStr(fs[2], "finding_id") ||
		validation.ObjStr(edges[0], "dst") != validation.ObjStr(fs[0], "finding_id") ||
		validation.ObjStr(edges[0], "actor") != "alice" {
		t.Errorf("edge = %s", validation.DumpIndented(edges[0]))
	}
}

func TestReportRendersClusterSection(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	text := mustGenerate(t, camp)
	if !strings.Contains(text, "## Root-cause clusters") {
		t.Fatalf("no cluster section")
	}
	section := strings.Split(strings.Split(text, "## Root-cause clusters")[1],
		"\n## ")[0]
	if !strings.Contains(section, "share-price-inflation") {
		t.Errorf("class missing from the section")
	}
	if !strings.Contains(section, "4 findings share this root cause") {
		t.Errorf("share count missing from the section")
	}
	depLine := ""
	donLine := ""
	feeLine := ""
	for _, l := range strings.Split(section, "\n") {
		if strings.Contains(l, "deposit") && strings.Contains(l, "closes") {
			depLine = l
		}
		if strings.Contains(l, "donate") && strings.Contains(l, "closes") {
			donLine = l
		}
		if strings.Contains(l, "transferWithFee") && strings.Contains(l, "closes") {
			feeLine = l
		}
	}
	if !strings.Contains(depLine, validation.ObjStr(fs[0], "finding_id")) ||
		!strings.Contains(depLine, validation.ObjStr(fs[1], "finding_id")) {
		t.Errorf("deposit closure line = %q", depLine)
	}
	if !strings.Contains(donLine, validation.ObjStr(fs[2], "finding_id")) {
		t.Errorf("donate closure line = %q", donLine)
	}
	if !strings.Contains(feeLine, validation.ObjStr(fs[3], "finding_id")) {
		t.Errorf("fee closure line = %q", feeLine)
	}
	if !strings.Contains(section, "does NOT close") &&
		!strings.Contains(strings.ToLower(section), "separate") {
		t.Errorf("no cross-subcluster warning")
	}
}

func TestReportWithoutClusteringHasNoSection(t *testing.T) {
	camp := clusterCamp(t)
	mk(t, camp, "a", "deposit", "A finding alone")
	f2 := mk(t, camp, "b", "withdraw", "B finding alone")
	rc := validation.ObjAt(f2, "root_cause")
	rc.O = validation.SetOrAppend(rc.O, "class", validation.VStr("reentrancy"))
	f2.O = validation.SetOrAppend(f2.O, "root_cause", rc)
	if err := findings.SaveFinding(camp, &f2); err != nil {
		t.Fatal(err)
	}
	text := mustGenerate(t, camp)
	if strings.Contains(text, "Root-cause clusters") {
		t.Errorf("empty cluster heading rendered")
	}
}

func TestReportSurfacesAttestedCausation(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	actor := "alice"
	if _, err := relations.MintRelation(camp, "caused_by",
		validation.VObj(kv("type", validation.VStr("finding")),
			kv("id", validation.ObjAt(fs[2], "finding_id"))),
		validation.VObj(kv("type", validation.VStr("finding")),
			kv("id", validation.ObjAt(fs[0], "finding_id"))),
		nil, &actor, nil); err != nil {
		t.Fatal(err)
	}
	text := mustGenerate(t, camp)
	section := strings.Split(strings.Split(text, "## Root-cause clusters")[1],
		"\n## ")[0]
	if !strings.Contains(section, "caused_by") {
		t.Errorf("caused_by missing from the section")
	}
	if !strings.Contains(section, validation.ObjStr(fs[2], "finding_id")) ||
		!strings.Contains(section, validation.ObjStr(fs[0], "finding_id")) {
		t.Errorf("causation endpoints missing from the section")
	}
	if !strings.Contains(section, "alice") {
		t.Errorf("actor missing from the section")
	}
}

func patchVerified(fid string) validation.Value {
	return validation.VObj(
		kv("patch_blocks_poc", validation.VBool(true)),
		kv("boundary_mutations_tested", validation.VInt(3)),
		kv("boundary_bypass_found", validation.VBool(false)),
		kv("artifact_id", validation.VStr("EX-test00000001")),
		kv("patch", validation.VStr("guard external transfers in donate()")),
		kv("mutations", validation.VArr(validation.VStr("adjacent input"),
			validation.VStr("adjacent path"),
			validation.VStr("reordered calls"))),
		kv("actor", validation.VStr("alice")))
}

func TestCreditScopeOnImmunizedSibling(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	vf, err := findings.LoadFinding(camp, validation.ObjStr(fs[2], "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	ver := validation.ObjAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "patch_verified",
		patchVerified(validation.ObjStr(fs[2], "finding_id")))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(camp, &vf); err != nil {
		t.Fatal(err)
	}
	text := mustGenerate(t, camp)
	sec := reportFindingSection(t, text, validation.ObjStr(fs[2], "finding_id"))
	low := strings.ToLower(sec)
	if !strings.Contains(low, "credit scope") &&
		!strings.Contains(sec, "NOT immunized") {
		t.Errorf("no credit-scope note: %q", sec)
	}
	for _, other := range []validation.Value{fs[0], fs[1], fs[3]} {
		if !strings.Contains(sec, validation.ObjStr(other, "finding_id")) {
			t.Errorf("sibling %s missing from the credit-scope note",
				validation.ObjStr(other, "finding_id"))
		}
	}
}

func TestNoCreditScopeNoteWithoutSiblings(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	reclass := func(f validation.Value, class string) {
		t.Helper()
		rc := validation.ObjAt(f, "root_cause")
		rc.O = validation.SetOrAppend(rc.O, "class", validation.VStr(class))
		f.O = validation.SetOrAppend(f.O, "root_cause", rc)
		if err := findings.SaveFinding(camp, &f); err != nil {
			t.Fatal(err)
		}
	}
	reclass(fs[0], "reentrancy")
	reclass(fs[1], "reentrancy")
	reclass(fs[3], "logic-error")
	vf, err := findings.LoadFinding(camp, validation.ObjStr(fs[2], "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	ver := validation.ObjAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "patch_verified",
		patchVerified(validation.ObjStr(fs[2], "finding_id")))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(camp, &vf); err != nil {
		t.Fatal(err)
	}
	text := mustGenerate(t, camp)
	sec := reportFindingSection(t, text, validation.ObjStr(fs[2], "finding_id"))
	if strings.Contains(strings.ToLower(sec), "credit scope") {
		t.Errorf("credit-scope note rendered without siblings: %q", sec)
	}
	if strings.Contains(sec, "NOT immunized") {
		t.Errorf("NOT-immunized line rendered without siblings")
	}
}

// ---------------------------------------------------------------------------
// test_report_privileged.py
// ---------------------------------------------------------------------------

const privFixedAt = "2026-09-06T00:00:00+00:00"

func governorTimelocked() validation.Value {
	return validation.VObj(
		kv("role", validation.VStr("governor")),
		kv("capability", validation.VStr("drain vault via timelock queue")),
		kv("mechanism", validation.VStr("timelock queue")),
		kv("timelocked", validation.VBool(true)),
		kv("multisig_threshold", validation.VNull()),
		kv("can_drain", validation.VBool(true)))
}

func ownerBare() validation.Value {
	return validation.VObj(
		kv("role", validation.VStr("owner")),
		kv("capability", validation.VStr("upgrade proxy")),
		kv("mechanism", validation.VStr("proxy admin")),
		kv("timelocked", validation.VNull()),
		kv("multisig_threshold", validation.VNull()),
		kv("can_drain", validation.VBool(false)))
}

func privilegedPolicy(program string) validation.Value {
	return validation.VObj(
		kv("program", validation.VStr(program)),
		kv("program_url", validation.VStr("https://example.invalid/test-program")),
		kv("platform", validation.VStr("other")),
		kv("chains", validation.VArr(validation.VStr("ethereum"))),
		kv("scope", validation.VArr(validation.VObj(
			kv("target", validation.VStr("src/")),
			kv("kind", validation.VStr("path"))))),
		kv("severity_rules", validation.VArr(validation.VObj(
			kv("severity", validation.VStr("critical")),
			kv("match", validation.VObj(
				kv("bug_classes",
					validation.VArr(validation.VStr("access-control")))))))),
		kv("poc_requirements", validation.VObj(
			kv("min_evidence_level", validation.VStr("E4")),
			kv("require_fork_repro", validation.VBool(false)))))
}

// privSpec is one `confirmed` entry of the det fixture.
type privSpec struct {
	title    string
	granted  []string
	required []string
	blast    string
}

// privDet is the `det` fixture factory.
func privDet(t *testing.T) func(privileges []validation.Value,
	confirmed []privSpec) (*state.Campaign, []string) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("WEBV2_NOW", privFixedAt)
	t.Setenv("WEBV2_UUID", "t31-privileged")
	installMemorySeams(t)
	// Python's det patches uuid4 (finding ids included); the Go equivalent is
	// the findings package's pinned finding-id stream plus state.ResetIDStream
	// for state.new_id (artifact/memory ids).
	findings.SetFindingIDSource(findings.PinnedFindingID)
	t.Cleanup(func() { findings.SetFindingIDSource(nil) })
	build := func(privileges []validation.Value,
		confirmed []privSpec) (*state.Campaign, []string) {
		matches, err := filepath.Glob(filepath.Join(tmp, "campaigns", "C-*"))
		if err != nil {
			t.Fatal(err)
		}
		n := len(matches) + 1
		h := sha1.Sum([]byte("Test Program|" + itoa10(n)))
		tag := hex.EncodeToString(h[:])[:10]
		store := filepath.Join(tmp, "shared-"+tag)
		t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", store)
		policyPath := filepath.Join(tmp, "policy-"+tag+".json")
		if err := validation.WriteJson(policyPath,
			privilegedPolicy("Test Program"), ""); err != nil {
			t.Fatal(err)
		}
		camp, err := state.Init(tmp, "Test Program",
			state.InitOpts{CampaignID: "C-" + tag})
		if err != nil {
			t.Fatal(err)
		}
		doc, err := validation.ReadJson(camp.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(policyPath))
		if err := validation.WriteJson(camp.StatePath, doc, "campaign_state"); err != nil {
			t.Fatal(err)
		}
		state.ResetIDStream()
		findings.ResetPinnedFindingIDs()
		model := validation.VObj(
			kv("protocol_id", validation.VStr("t")),
			kv("name", validation.VStr("t")),
			kv("contracts", validation.VArr()),
			kv("actors", validation.VArr()),
			kv("assets", validation.VArr()),
			kv("relations", validation.VArr()),
			kv("privileges", validation.VArr(privileges...)))
		if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
			"protocol_model.json"), model, ""); err != nil {
			t.Fatal(err)
		}
		fids := []string{}
		for _, spec := range confirmed {
			fids = append(fids, privConfirmed(t, camp, spec))
		}
		return camp, fids
	}
	return build
}

func itoa10(n int) string {
	if n == 0 {
		return "0"
	}
	out := ""
	for n > 0 {
		out = string(rune('0'+n%10)) + out
		n /= 10
	}
	return out
}

// privConfirmed is that module's _confirmed.
func privConfirmed(t *testing.T, camp *state.Campaign, spec privSpec) string {
	t.Helper()
	blast := spec.blast
	if blast == "" {
		blast = "all-users"
	}
	f, err := findings.IngestHypothesis(camp, validation.VObj(
		kv("title", validation.VStr(spec.title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("cwe", validation.VStr("CWE-862")),
			kv("description", validation.VStr(
				"test fixture: privileged path moves funds")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/MiniVault.sol")),
			kv("contract", validation.VStr("MiniVault")),
			kv("function", validation.VStr("rescue"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("test attacker")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", strArrPriv(spec.granted)),
			kv("required", strArrPriv(spec.required)))),
	), "attacker", "06", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	// R3-3 ripple: the floor now gates the POSSIBLE stamp (E2), so the
	// reachability evidence lands first and the triage move follows it.
	if _, err := findings.AddEvidence(camp, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-reach")),
		kv("level", validation.VStr("E2")),
		kv("type", validation.VStr("reachability")),
		kv("description", validation.VStr("reachable entry point")))); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(camp, fid, "POSSIBLE", "triage passed",
		"triage passed", "", false); err != nil {
		t.Fatal(err)
	}
	rec, err := sandbox.RegisterExec(camp, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_x",
		ReportedBy: "test-harness", FindingID: &fid,
		StdoutText: "PASS: test_x\n"})
	if err != nil {
		t.Fatal(err)
	}
	execID := validation.ObjStr(rec, "exec_id")
	tier := "T1"
	if _, err := reproduction.RecordAttempt(camp, fid, "reproduced",
		reproduction.RecordOpts{Tier: &tier, ExecID: &execID}); err != nil {
		t.Fatal(err)
	}
	if _, err := reproduction.MintReproEvidence(camp, fid, execID,
		"sandboxed unit PoC", &tier, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(camp, fid, "confirmed",
		"no compensating control"); err != nil {
		t.Fatal(err)
	}
	bugClass := "access-control"
	prior, err := learning.QueueMemory(camp, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "prior incident for " + spec.title +
			": privileged path moved funds",
		BugClass:        &bugClass,
		EvidenceSummary: "earlier campaign, E4-confirmed"})
	if err != nil {
		t.Fatal(err)
	}
	priorID := validation.ObjStr(prior, "memory_id")
	if _, err := learning.ApproveMemory(camp, priorID, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := sharedmem.PublishCampaign(camp, "pytest-harness", true); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.RecordMemoryCheck(camp, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr(priorID))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	if _, err := risk.RecordEconomicImpact(camp, fid, validation.VInt(800000),
		validation.VInt(800000), validation.VNull()); err != nil {
		t.Fatal(err)
	}
	vf, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	ei := validation.ObjAt(vf, "economic_impact")
	if ei.Kind != validation.Obj {
		ei = validation.VObj()
	}
	ei.O = validation.SetOrAppend(ei.O, "blast_radius", validation.VStr(blast))
	vf.O = validation.SetOrAppend(vf.O, "economic_impact", ei)
	if err := findings.SaveFinding(camp, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(camp, fid, "CONFIRMED", "gates passed",
		"gates passed", "", false); err != nil {
		t.Fatal(err)
	}
	return fid
}

func strArrPriv(xs []string) validation.Value {
	out := make([]validation.Value, 0, len(xs))
	for _, x := range xs {
		out = append(out, validation.VStr(x))
	}
	return validation.VArr(out...)
}

// sectionBlock is that module's _section_block.
func sectionBlock(t *testing.T, md string) string {
	t.Helper()
	start := strings.Index(md, "## Privileged-actor exposure")
	if start < 0 {
		t.Fatalf("no privileged section")
	}
	end := strings.Index(md[start:], "## Results")
	if end < 0 {
		t.Fatalf("no Results section after the privileged one")
	}
	return md[start : start+end]
}

func TestSectionRendersWithPrivileges(t *testing.T) {
	det := privDet(t)
	camp, fids := det([]validation.Value{governorTimelocked()}, []privSpec{{
		title:    "Governor drains the vault",
		granted:  []string{"drain_treasury"},
		required: []string{"role_governor"}}})
	md := mustGenerate(t, camp)
	fid := fids[0]
	if !strings.Contains(md, "## Privileged-actor exposure") {
		t.Fatalf("no privileged section")
	}
	if !strings.Contains(md, "- **governor** (`role_governor`) — band: "+
		"`timelocked`; constraints: drain vault via timelock queue (timelocked") {
		t.Errorf("governor line missing")
	}
	if !strings.Contains(md, "- direct: 1 path, best: "+fid+
		" -> drain_treasury") {
		t.Errorf("direct path line missing")
	}
	if !strings.Contains(md, "Separate attacker track: bounded privileged "+
		"roles as explicit baselines;") {
		t.Errorf("separate-attacker-track line missing")
	}
	if !strings.Contains(md, "the unprivileged-EOA results above are "+
		"unaffected by this section.") {
		t.Errorf("unaffected-by-section line missing")
	}
	if strings.Index(md, "## Privileged-actor exposure") >=
		strings.Index(md, "## Results") {
		t.Errorf("privileged section is not before Results")
	}
}

func TestRoleWithoutTerminalPathsIsListed(t *testing.T) {
	det := privDet(t)
	camp, _ := det([]validation.Value{governorTimelocked(), ownerBare()},
		[]privSpec{{title: "Governor drains the vault",
			granted:  []string{"drain_treasury"},
			required: []string{"role_governor"}}})
	md := mustGenerate(t, camp)
	if !strings.Contains(md, "- **owner** (`role_owner`) — band: "+
		"`unconstrained`; no terminal paths recorded") {
		t.Errorf("owner line missing")
	}
	if strings.Index(md, "**governor**") >= strings.Index(md, "**owner**") {
		t.Errorf("roles are not sorted: governor must precede owner")
	}
}

func TestMultiStepPathsReportedWhenPresent(t *testing.T) {
	det := privDet(t)
	camp, _ := det([]validation.Value{governorTimelocked()}, []privSpec{
		{title: "Governor takes over the upgrade mechanism",
			granted:  []string{"set_implementation"},
			required: []string{"role_governor"}},
		{title: "Upgraded implementation drains the vault",
			granted:  []string{"drain_treasury"},
			required: []string{"role_governor", "set_implementation"}}})
	md := mustGenerate(t, camp)
	block := sectionBlock(t, md)
	if !strings.Contains(block, "- chains: 1 multi-step path") {
		t.Errorf("multi-step chain line missing: %q", block)
	}
	if !strings.Contains(block, "-> drain_treasury") {
		t.Errorf("chain target missing from the block")
	}
}

// normalizePriv is that module's _normalize.
func normalizePriv(md string) string {
	out := []string{}
	for _, line := range strings.Split(md, "\n") {
		switch {
		case strings.HasPrefix(line, "<!-- state-head: "):
			line = "<!-- state-head:"
		case strings.HasPrefix(line, "- generated: "):
			line = "- generated:"
		case strings.HasPrefix(line, "- campaign: `C-") &&
			strings.HasSuffix(line, "`"):
			line = "- campaign: `C-x`"
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func TestSectionAbsentWithoutPrivilegesIsByteIdentical(t *testing.T) {
	det := privDet(t)
	spec := []privSpec{{title: "Governor drains the vault",
		granted:  []string{"drain_treasury"},
		required: []string{"role_governor"}}}
	campA, fidsA := det([]validation.Value{governorTimelocked()}, spec)
	mdPriv := mustGenerate(t, campA)
	if !strings.Contains(mdPriv, "## Privileged-actor exposure") {
		t.Fatalf("privileged twin rendered no section")
	}
	campB, fidsB := det(nil, spec)
	mdNone := mustGenerate(t, campB)
	if strings.Contains(mdNone, "Privileged-actor exposure") {
		t.Errorf("empty-privileges twin rendered the section")
	}
	if strings.Contains(mdNone, "bounded privileged roles") {
		t.Errorf("empty-privileges twin rendered the separate-track line")
	}
	if len(fidsA) != len(fidsB) {
		t.Fatalf("twin finding ids differ: %v vs %v", fidsA, fidsB)
	}
	for i := range fidsA {
		if fidsA[i] != fidsB[i] {
			t.Fatalf("twin finding ids differ: %v vs %v", fidsA, fidsB)
		}
	}
	evA, err := campA.Events()
	if err != nil {
		t.Fatal(err)
	}
	evB, err := campB.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(evA) != len(evB) {
		t.Fatalf("event counts differ: %d vs %d", len(evA), len(evB))
	}
	if _, err := Generate(campA); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(campB); err != nil {
		t.Fatal(err)
	}
	evA2, _ := campA.Events()
	evB2, _ := campB.Events()
	if len(evA2) != len(evB2) {
		t.Errorf("event counts diverged after regeneration: %d vs %d",
			len(evA2), len(evB2))
	}
	a := normalizePriv(mdPriv)
	b := normalizePriv(mdNone)
	if b != strings.Replace(a, sectionBlock(t, a), "", 1) {
		t.Errorf("the no-privileges report is not the privileged report " +
			"minus its section")
	}
	if !strings.Contains(mdNone, fidsA[0]) {
		t.Errorf("the finding is missing from the no-privileges report")
	}
}

func TestPrivilegedSectionTwoRunsByteIdentical(t *testing.T) {
	det := privDet(t)
	camp, _ := det([]validation.Value{governorTimelocked(), ownerBare()},
		[]privSpec{{title: "Governor drains the vault",
			granted:  []string{"drain_treasury"},
			required: []string{"role_governor"}}})
	first, err := PrivilegedSection(camp)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrivilegedSection(camp)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatalf("fixture must produce a non-empty section")
	}
	foundDirect, foundNone := false, false
	for _, line := range first {
		if strings.Contains(line, "direct: 1 path, best:") {
			foundDirect = true
		}
		if strings.Contains(line, "no terminal paths recorded") {
			foundNone = true
		}
	}
	if !foundDirect || !foundNone {
		t.Errorf("section missing a render shape: %v", first)
	}
	if len(second) != len(first) {
		t.Fatalf("second render has %d lines, want %d", len(second), len(first))
	}
	for i := range first {
		if second[i] != first[i] {
			t.Errorf("line %d differs:\n%q\n%q", i, first[i], second[i])
		}
	}
}

func TestNoModelArtifactRendersNothing(t *testing.T) {
	det := privDet(t)
	camp, _ := det(nil, nil)
	if err := os.Remove(filepath.Join(camp.ArtifactsDir,
		"protocol_model.json")); err != nil {
		t.Fatal(err)
	}
	md := mustGenerate(t, camp)
	if strings.Contains(md, "Privileged-actor exposure") {
		t.Errorf("section rendered without a model artifact")
	}
}

func TestCountPluralizes(t *testing.T) {
	cases := []struct {
		n        int
		singular string
		want     string
	}{
		{0, "path", "0 paths"},
		{1, "path", "1 path"},
		{2, "path", "2 paths"},
		{3, "multi-step path", "3 multi-step paths"},
	}
	if len(cases) != 4 {
		t.Fatalf("cases = %d, want 4", len(cases))
	}
	for _, c := range cases {
		if got := count(c.n, c.singular); got != c.want {
			t.Errorf("count(%d, %q) = %q, want %q", c.n, c.singular, got, c.want)
		}
	}
}

func malformedModels() []struct {
	label string
	doc   validation.Value
} {
	return []struct {
		label string
		doc   validation.Value
	}{
		{"privileges is a string",
			validation.VObj(kv("privileges", validation.VStr("oops")))},
		{"list containing a string",
			validation.VObj(kv("privileges",
				validation.VArr(validation.VStr("oops"))))},
		{"privileges is a dict",
			validation.VObj(kv("privileges",
				validation.VObj(kv("role", validation.VStr("owner")))))},
		{"privileges is an int",
			validation.VObj(kv("privileges", validation.VInt(7)))},
	}
}

func TestMalformedModelFailsSoft(t *testing.T) {
	for _, tc := range malformedModels() {
		det := privDet(t)
		camp, _ := det(nil, nil)
		if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
			"protocol_model.json"), tc.doc, ""); err != nil {
			t.Fatal(err)
		}
		sec, err := PrivilegedSection(camp)
		if err != nil {
			t.Fatalf("%s: privileged_section error: %v", tc.label, err)
		}
		if len(sec) != 0 {
			t.Errorf("%s: section = %v, want []", tc.label, sec)
		}
		md := mustGenerate(t, camp)
		if strings.Contains(md, "Privileged-actor exposure") {
			t.Errorf("%s: section rendered", tc.label)
		}
	}
}

func TestUnparseableModelArtifactRendersNoSection(t *testing.T) {
	det := privDet(t)
	camp, _ := det(nil, nil)
	if err := os.WriteFile(filepath.Join(camp.ArtifactsDir,
		"protocol_model.json"), []byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	sec, err := PrivilegedSection(camp)
	if err != nil {
		t.Fatalf("privileged_section error: %v", err)
	}
	if len(sec) != 0 {
		t.Errorf("section = %v, want []", sec)
	}
}

func TestTopLevelListArtifactDoesNotCrashThePrivilegedTrack(t *testing.T) {
	det := privDet(t)
	camp, _ := det(nil, nil)
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"protocol_model.json"),
		validation.VArr(validation.VStr("not"), validation.VStr("a"),
			validation.VStr("dict")), ""); err != nil {
		t.Fatal(err)
	}
	sec, err := PrivilegedSection(camp)
	if err != nil {
		t.Fatalf("privileged_section error: %v", err)
	}
	if len(sec) != 0 {
		t.Errorf("section = %v, want []", sec)
	}
}

func TestJunkEntriesDroppedValidKept(t *testing.T) {
	det := privDet(t)
	camp, _ := det(nil, nil)
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"protocol_model.json"), validation.VObj(
		kv("privileges", validation.VArr(validation.VStr("oops"),
			validation.VNull(),
			validation.VObj(kv("role", validation.VStr("owner")),
				kv("capability", validation.VStr("upgrade")))))), ""); err != nil {
		t.Fatal(err)
	}
	md := mustGenerate(t, camp)
	block := sectionBlock(t, md)
	if !strings.Contains(block, "- **owner** (`role_owner`)") {
		t.Errorf("owner line missing: %q", block)
	}
	if !strings.Contains(block, "band: `unconstrained`") {
		t.Errorf("owner band missing")
	}
	if strings.Contains(block, "oops") {
		t.Errorf("junk entry leaked into the block")
	}
}

func TestConstraintsRenderWithValidEntry(t *testing.T) {
	det := privDet(t)
	camp, _ := det([]validation.Value{governorTimelocked()},
		[]privSpec{{title: "Governor drains the vault",
			granted:  []string{"drain_treasury"},
			required: []string{"role_governor"}}})
	md := mustGenerate(t, camp)
	block := sectionBlock(t, md)
	if !strings.Contains(block,
		"constraints: drain vault via timelock queue (timelocked") {
		t.Errorf("constraints line missing: %q", block)
	}
	if strings.Contains(block, "none recorded") {
		t.Errorf("constraints rendered as none recorded")
	}
}
