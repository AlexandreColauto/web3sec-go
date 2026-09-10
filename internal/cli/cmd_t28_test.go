package cli

// cmd_t28_test: the relations/resemble/publish/globalize/shared/memory CLI
// contract. Help blocks are byte-exact against the pinned argparse output;
// the no-op reporting tests are 1:1 ports of tests/test_noop_reporting.py
// (publish + memory halves).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/bounty"
	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/relations"
	"websec/internal/sandbox"
	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/validation"
)

// kv is the keyed-object constructor used throughout these fixtures.
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// ---- help blocks -----------------------------------------------------------

func TestT28HelpBlocks(t *testing.T) {
	cases := []struct{ name, want string }{
		{"relations", relationsHelp},
		{"resemble", resembleHelp},
		{"publish", publishHelp},
		{"globalize", globalizeHelp},
		{"shared", sharedHelp},
		{"memory", memoryHelp},
	}
	for _, tc := range cases {
		code, out, errS := run(t, tc.name, "--help")
		if code != 0 {
			t.Fatalf("%s --help exit = %d (err=%q)", tc.name, code, errS)
		}
		if out != tc.want {
			t.Fatalf("%s help mismatch:\n--- got ---\n%s--- want ---\n%s",
				tc.name, out, tc.want)
		}
		if errS != "" {
			t.Fatalf("%s stderr = %q", tc.name, errS)
		}
	}
}

// ---- argparse errors -------------------------------------------------------

func TestT28ArgErrors(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantSub string
	}{
		{"relations", []string{"relations"}, "required: campaign"},
		{"relations-extra", []string{"relations", "c", "extra"},
			"unrecognized arguments: extra"},
		{"resemble", []string{"resemble", "c"}, "required: finding"},
		{"publish-both", []string{"publish"}, "required: campaign, --actor"},
		{"publish-actor", []string{"publish", "c"}, "required: --actor"},
		{"memory", []string{"memory", "--approve", "M"}, "required: campaign"},
		{"shared-extra", []string{"shared", "x"}, "unrecognized arguments: x"},
	}
	for _, tc := range cases {
		code, _, errS := run(t, tc.args...)
		if code != 2 {
			t.Fatalf("%s exit = %d, want 2", tc.name, code)
		}
		if !strings.Contains(errS, tc.wantSub) {
			t.Fatalf("%s stderr = %q, want %q", tc.name, errS, tc.wantSub)
		}
	}
}

func TestT28GlobalizeInvalidTier(t *testing.T) {
	code, _, errS := run(t, "globalize", "--actor", "op", "--tier", "bogus")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	want := globalizeUsage + "webv2 globalize: error: argument --tier: " +
		"invalid choice: 'bogus' (choose from 'root', 'global')\n"
	if errS != want {
		t.Fatalf("stderr:\n--- got ---\n%s--- want ---\n%s", errS, want)
	}
}

// ---- no-op reporting fixture (tests/test_noop_reporting.py) ----------------

// noopPolicy is that module's POLICY, with program overridden.
func noopPolicy(program string) validation.Value {
	return validation.VObj(
		kv("program", validation.VStr(program)),
		kv("program_url", validation.VStr("https://immunefi.com/acme")),
		kv("platform", validation.VStr("immunefi")),
		kv("chains", validation.VArr(validation.VStr("ethereum"))),
		kv("asset_weight_usd", validation.VInt(50000000)),
		kv("scope", validation.VArr(validation.VObj(
			kv("target", validation.VStr("Vault")),
			kv("kind", validation.VStr("contract"))))),
		kv("exclusions", validation.VArr()),
		kv("severity_rules", validation.VArr(validation.VObj(
			kv("severity", validation.VStr("critical")),
			kv("match", validation.VObj(
				kv("bug_classes", validation.VArr(validation.VStr("access-control"))),
				kv("require_invariant_violation", validation.VBool(true))))))),
		kv("poc_requirements", validation.VObj(
			kv("min_evidence_level", validation.VStr("E4")),
			kv("require_fork_repro", validation.VBool(false)))),
		kv("reporting", validation.VObj(
			kv("contact", validation.VStr("immunefi")),
			kv("required_fields", validation.VArr(validation.VStr("PoC"),
				validation.VStr("impact"))))))
}

// noopCamp is the `camp` fixture: Campaign.init(tmp_path, "noop-program")
// plus the autouse global-store isolation.
func noopCamp(t *testing.T) (string, string, *state.Campaign) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR",
		filepath.Join(root, "global-shared-memory"))
	// ensureSeams is a one-shot; a sibling test's cleanup may have reset the
	// shared-memory seam to the absent-store default, so re-install it (the
	// production wiring) before anything consults the store.
	ensureSeams()
	findings.SetSharedMemoryRows(sharedmem.LoadSharedMemory)
	findings.SetLearningAllMemory(learning.AllMemory)
	code, out, errS := run(t, "--root", root, "init", "--program",
		"noop-program")
	if code != 0 {
		t.Fatalf("init exit %d: %q", code, errS)
	}
	cid := initIDRe.FindStringSubmatch(out)[1]
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	return root, cid, c
}

// withPolicy is _with_policy.
func withPolicy(t *testing.T, c *state.Campaign, root string) {
	t.Helper()
	pp := filepath.Join(root, "policy.json")
	if _, err := bounty.SavePolicy(c, noopPolicy("noop-program"), &pp); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	doc, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(pp))
	if err := validation.WriteJson(c.StatePath, doc, "campaign_state"); err != nil {
		t.Fatal(err)
	}
}

// noopHypo is that module's hypo.
func noopHypo(t *testing.T, c *state.Campaign, title, status string) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr("mechanism described in detail here")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("contract", validation.VStr("Vault")),
			kv("function", validation.VStr("f"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.VArr(validation.VStr("withdraw_unbacked_assets"))),
			kv("required", validation.VArr()))),
		kv("economic_impact", validation.VObj(
			kv("blast_radius", validation.VStr("subset-of-users")))),
	), "code", "test", "")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	fid := objStr(f, "finding_id")
	if status != "" {
		if _, err := findings.Transition(c, fid, status, "test fixture", "",
			"", false); err != nil {
			t.Fatalf("transition %s: %v", status, err)
		}
	}
	return fid
}

// seedGlobalMemoryRow is conftest.seed_global_memory_row.
func seedGlobalMemoryRow(t *testing.T) {
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

// noopConfirm is that module's confirm.
func noopConfirm(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatalf("transition: %v", err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "pytest-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+fid[len(fid)-6:])),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("repro under sandbox")),
		kv("sandbox_profile", objAt(rec, "profile")),
		kv("artifact_id", objAt(rec, "exec_id")))
	if _, err := findings.AddEvidence(c, fid, item); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed", "ok"); err != nil {
		t.Fatalf("set critic verdict: %v", err)
	}
	seedGlobalMemoryRow(t)
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatalf("record memory check: %v", err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := objAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("status", validation.VStr("reproduced")),
		kv("tier_reached", validation.VStr("T3")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "gate", "", "",
		false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
}

// ---- publish no-op ---------------------------------------------------------

func TestPublishNoopNamesTheReasonAndTheCommand(t *testing.T) {
	root, cid, c := noopCamp(t)
	withPolicy(t, c, root)
	noopHypo(t, c, "not yet confirmed finding", "")
	code, out, errS := run(t, "--root", root, "publish", cid,
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	for _, want := range []string{
		"published 0 signature(s) and 0 approved memory row(s)",
		"nothing changed",
		"no CONFIRMED finding or CHAIN",
		"no human-approved memory row",
		"webv2 move",
		"webv2 memory",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestPublishThatAddsRowsKeepsTodaysOutput(t *testing.T) {
	root, cid, c := noopCamp(t)
	withPolicy(t, c, root)
	noopConfirm(t, c, noopHypo(t, c, "publishable finding", ""))
	code, out, errS := run(t, "--root", root, "publish", cid,
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out,
		"published 1 signature(s) and 0 approved memory row(s)") {
		t.Fatalf("output = %s", out)
	}
	if strings.Contains(out, "nothing changed") {
		t.Fatalf("output = %s", out)
	}
}

func TestPublishNoopWhenEverythingIsAlreadyPublished(t *testing.T) {
	root, cid, c := noopCamp(t)
	withPolicy(t, c, root)
	noopConfirm(t, c, noopHypo(t, c, "publishable finding", ""))
	code, out, errS := run(t, "--root", root, "publish", cid,
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	code, out, errS = run(t, "--root", root, "publish", cid,
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	for _, want := range []string{
		"published 0 signature(s) and 0 approved memory row(s)",
		"nothing changed",
		"already have a signature",
		"webv2 memory",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "webv2 move") {
		t.Fatalf("output = %s", out)
	}
}

// ---- memory no-op ----------------------------------------------------------

func TestMemoryNoRowsSaysSoAndNamesTheNextCommand(t *testing.T) {
	root, cid, _ := noopCamp(t)
	code, out, errS := run(t, "--root", root, "memory", cid)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "no rows") {
		t.Fatalf("output = %s", out)
	}
	if !strings.Contains(out, "webv2 ladder") || !strings.Contains(out, "disprove") {
		t.Fatalf("output = %s", out)
	}
}

func TestMemoryReapproveIsExplicitAndWritesNothing(t *testing.T) {
	root, cid, c := noopCamp(t)
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED",
		Pattern: "a disproved pattern that stays disproved"})
	if err != nil {
		t.Fatal(err)
	}
	mid := objStr(mem, "memory_id")
	code, out, errS := run(t, "--root", root, "memory", cid,
		"--approve", mid, "--by", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "approved "+mid) {
		t.Fatalf("output = %s", out)
	}
	rowPath := filepath.Join(c.MemoryDir, mid+".json")
	first, err := validation.ReadJson(rowPath)
	if err != nil {
		t.Fatal(err)
	}
	eventsBefore, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	code, out, errS = run(t, "--root", root, "memory", cid,
		"--approve", mid, "--by", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	for _, want := range []string{"nothing changed", "already human-approved",
		"webv2 publish " + cid} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	after, err := validation.ReadJson(rowPath)
	if err != nil {
		t.Fatal(err)
	}
	if objStr(after, "approved_at") != objStr(first, "approved_at") ||
		objStr(after, "approved_by") != objStr(first, "approved_by") {
		t.Fatalf("row was rewritten: %s", validation.CanonCompact(after))
	}
	eventsAfter, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(eventsAfter) != len(eventsBefore) {
		t.Fatalf("events %d -> %d (a no-op approve must not re-log "+
			"memory.approved)", len(eventsBefore), len(eventsAfter))
	}
}

func TestMemoryReapproveOfHeldOutRowStillRefuses(t *testing.T) {
	root, cid, c := noopCamp(t)
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED",
		Pattern: "a held-out row that must never promote"})
	if err != nil {
		t.Fatal(err)
	}
	mid := objStr(mem, "memory_id")
	rowPath := filepath.Join(c.MemoryDir, mid+".json")
	row, err := validation.ReadJson(rowPath)
	if err != nil {
		t.Fatal(err)
	}
	row.O = validation.SetOrAppend(row.O, "partition", validation.VStr("held-out"))
	row.O = validation.SetOrAppend(row.O, "promotion_status",
		validation.VStr("human-approved"))
	row.O = validation.SetOrAppend(row.O, "approved_by", validation.VStr("legacy-edit"))
	row.O = validation.SetOrAppend(row.O, "approved_at",
		validation.VStr("2026-09-08T00:00:00+00:00"))
	if err := validation.WriteJson(rowPath, row, "memory"); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "memory", cid,
		"--approve", mid, "--by", "operator")
	if code != 1 {
		t.Fatalf("exit %d, want 1 (out=%s err=%s)", code, out, errS)
	}
	if !strings.Contains(errS, "held-out") {
		t.Fatalf("stderr = %q", errS)
	}
	if strings.Contains(out, "nothing changed") || strings.Contains(out, "next:") {
		t.Fatalf("stdout = %s", out)
	}
	after, err := validation.ReadJson(rowPath)
	if err != nil {
		t.Fatal(err)
	}
	if objStr(after, "approved_by") != "legacy-edit" {
		t.Fatalf("row was rewritten: %s", validation.CanonCompact(after))
	}
}

func TestMemoryPromotedRowSaysAlreadyPromoted(t *testing.T) {
	root, cid, c := noopCamp(t)
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED",
		Pattern: "a row already promoted"})
	if err != nil {
		t.Fatal(err)
	}
	mid := objStr(mem, "memory_id")
	rowPath := filepath.Join(c.MemoryDir, mid+".json")
	row, err := validation.ReadJson(rowPath)
	if err != nil {
		t.Fatal(err)
	}
	row.O = validation.SetOrAppend(row.O, "promotion_status",
		validation.VStr("promoted"))
	row.O = validation.SetOrAppend(row.O, "approved_by", validation.VStr("legacy-edit"))
	row.O = validation.SetOrAppend(row.O, "approved_at",
		validation.VStr("2026-09-08T00:00:00+00:00"))
	if err := validation.WriteJson(rowPath, row, "memory"); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "memory", cid,
		"--approve", mid, "--by", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "already promoted") {
		t.Fatalf("output = %s", out)
	}
	if strings.Contains(out, "shared store") {
		t.Fatalf("output = %s", out)
	}
}

func TestMemoryListingUnchangedWithRows(t *testing.T) {
	root, cid, c := noopCamp(t)
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED",
		Pattern: "a listed pattern for the operator"})
	if err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "memory", cid)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	want := objStr(mem, "memory_id") +
		" [disproved/DISPROVED] promotion=pending"
	if !strings.Contains(out, want) {
		t.Fatalf("output = %s", out)
	}
	if strings.Contains(out, "no rows") {
		t.Fatalf("output = %s", out)
	}
}

// ---- happy paths -----------------------------------------------------------

func TestRelationsPrintsStoredEdges(t *testing.T) {
	root, cid, c := noopCamp(t)
	a := noopHypo(t, c, "edge finding one", "")
	b := noopHypo(t, c, "edge finding two", "")
	if _, err := relations.MintCausation(c, a, b, "operator", "attested"); err != nil {
		t.Fatalf("mint causation: %v", err)
	}
	code, out, errS := run(t, "--root", root, "relations", cid)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	for _, want := range []string{"edges: 1", "  caused_by (human-gated): 1",
		a + " -> " + b,
		"(anchor: attested) [actor operator]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	code, out, errS = run(t, "--root", root, "relations", cid, "--rebuild")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "re-derived deterministic edges: ") {
		t.Fatalf("output = %s", out)
	}
}

func TestResemblePrintsCapabilityDelta(t *testing.T) {
	root, cid, c := noopCamp(t)
	primitive := noopHypo(t, c, "confirmed primitive finding", "")
	noopConfirm(t, c, primitive)
	cand := noopHypo(t, c, "candidate finding", "POSSIBLE")
	code, out, errS := run(t, "--root", root, "resemble", cid, cand)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	for _, want := range []string{
		"candidate " + cand + " (class access-control, requires (none))",
		primitive + " [class-match] similarity=",
		"overlap=withdraw_unbacked_assets",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

// confirmLocal is noopConfirm with a campaign-LOCAL memory row for the
// memory check, so the (test-isolated) global tier stays untouched and the
// shared view is exactly what publish wrote.
func confirmLocal(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatalf("transition: %v", err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "pytest-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+fid[len(fid)-6:])),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("repro under sandbox")),
		kv("sandbox_profile", objAt(rec, "profile")),
		kv("artifact_id", objAt(rec, "exec_id")))
	if _, err := findings.AddEvidence(c, fid, item); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed", "ok"); err != nil {
		t.Fatalf("set critic verdict: %v", err)
	}
	bugClass := "logic-error"
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern:   "memory-check consult pattern",
		FindingID: &fid, BugClass: &bugClass})
	if err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(objAt(mem, "memory_id"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatalf("record memory check: %v", err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := objAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("status", validation.VStr("reproduced")),
		kv("tier_reached", validation.VStr("T3")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "gate", "", "",
		false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
}

func TestSharedPrintsBothTiersAndVerifies(t *testing.T) {
	root, cid, c := noopCamp(t)
	withPolicy(t, c, root)
	confirmLocal(t, c, noopHypo(t, c, "shared view finding", ""))
	code, out, errS := run(t, "--root", root, "publish", cid,
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("publish exit %d: %s%s", code, out, errS)
	}
	code, out, errS = run(t, "--root", root, "shared", "--verify")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	for _, want := range []string{
		"merged view: 1 signature(s), 0 approved memory row(s) (0 global-scope)",
		"  [root] " + filepath.Join(root, "shared-memory"),
		"      signatures: 1   memory: 0   global-scope: 0   records: 1",
		"  program: noop-program|immunefi|ethereum",
		"  integrity: PASS — 0 problem(s)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "[global]") || !strings.Contains(out, "(absent)") {
		t.Fatalf("output = %s", out)
	}
}

func TestGlobalizeRescopesTheRootTier(t *testing.T) {
	root, cid, c := noopCamp(t)
	withPolicy(t, c, root)
	confirmLocal(t, c, noopHypo(t, c, "globalize finding", ""))
	code, out, errS := run(t, "--root", root, "publish", cid,
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("publish exit %d: %s%s", code, out, errS)
	}
	code, out, errS = run(t, "--root", root, "globalize", "--actor", "operator",
		"--tier", "root")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	for _, want := range []string{
		": scope=global on 0 memory row(s) and 1 signature(s) [root tier, selector=*]",
		"store: " + filepath.Join(root, "shared-memory"),
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestGlobalizeMissingStoreFails(t *testing.T) {
	root := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR",
		filepath.Join(root, "global-shared-memory"))
	code, out, _ := run(t, "--root", root, "globalize", "--actor", "operator")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(out, "globalize failed: no global-tier store at ") ||
		!strings.Contains(out, "nothing to re-scope") {
		t.Fatalf("output = %s", out)
	}
}

func TestPublishMissingActorFails(t *testing.T) {
	root, cid, _ := noopCamp(t)
	code, out, _ := run(t, "--root", root, "publish", cid, "--actor", "")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(out, "publish failed: publish requires a recorded actor") {
		t.Fatalf("output = %s", out)
	}
}

// TestLadderDisproveQueuesMemoryThroughTheCLISeam is the D18 seam: with the
// real learning.queue_memory installed (ensureSeams -> wireT28Seams), a
// disproved rung must write a campaign memory row and log memory.queued —
// the reference's happy path (KNOWN_DIVERGENCES D18, now closed).
func TestLadderDisproveQueuesMemoryThroughTheCLISeam(t *testing.T) {
	c, root, fid := t23Campaign(t, "d18-seam")
	t23StartLadder(t, root, c.CampaignID, fid)
	rung := t23LifecycleAdd(t, root, c.CampaignID, fid)
	code, out, errS := run(t, "--root", root, "ladder", c.CampaignID,
		"disprove", fid, rung,
		"--reason", "the pool rejects 1 wei deposits (MIN_DEPOSIT)")
	if code != 0 {
		t.Fatalf("disprove exit %d: %q", code, errS)
	}
	if out != "rung "+rung+" (dust) disproved — negative memory queued "+
		"(the next campaign starts smarter)\n" {
		t.Fatalf("stdout = %q", out)
	}
	rows, err := learning.AllMemory(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("memory rows = %d", len(rows))
	}
	row := rows[0]
	if objStr(row, "kind") != "disproved" ||
		objStr(row, "status") != "DISPROVED" ||
		objStr(row, "promotion_status") != "pending" {
		t.Fatalf("row = %s", validation.CanonCompact(row))
	}
	wantPattern := "maximal-exploitation dead end: dust — dust the pool with " +
		"one wei"
	if objStr(row, "pattern") != wantPattern {
		t.Fatalf("pattern = %q", objStr(row, "pattern"))
	}
	if objStr(row, "evidence_summary") !=
		"the pool rejects 1 wei deposits (MIN_DEPOSIT)" {
		t.Fatalf("evidence_summary = %q", objStr(row, "evidence_summary"))
	}
	if objStr(objAt(row, "negative_mode"), "why_safe") !=
		"the pool rejects 1 wei deposits (MIN_DEPOSIT)" {
		t.Fatalf("negative_mode = %s",
			validation.CanonCompact(objAt(row, "negative_mode")))
	}
	if objStr(row, "finding_id") != fid {
		t.Fatalf("finding_id = %q", objStr(row, "finding_id"))
	}
	// the row is on disk under the campaign's memory dir, named MEM-*.json
	path := filepath.Join(c.MemoryDir, objStr(row, "memory_id")+".json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	types := []string{}
	for _, e := range events {
		types = append(types, objStr(e, "type"))
	}
	joined := strings.Join(types, ",")
	if !strings.Contains(joined, "memory.queued") ||
		!strings.Contains(joined, "ladder.rung_disproved") {
		t.Fatalf("event types = %s", joined)
	}
}
