package audit

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// objAt/objStr come from the audit package (this is an in-package test).
func arrStr(v validation.Value, key string) []string {
	var out []string
	for _, kv := range v.O {
		if kv.K == key && kv.V.Kind == validation.Arr {
			for _, item := range kv.V.A {
				out = append(out, item.S)
			}
		}
	}
	return out
}

func sectionNames(t *testing.T, report validation.Value) []string {
	t.Helper()
	var out []string
	sections := validation.ObjAt(report, "sections")
	for _, s := range sections.O {
		out = append(out, s.K)
	}
	return out
}

func reportOK(report validation.Value) bool {
	return validation.ObjAt(report, "ok").Kind == validation.Bool && validation.ObjAt(report, "ok").B
}

func sectionOKFlags(report validation.Value) map[string]bool {
	out := map[string]bool{}
	sections := validation.ObjAt(report, "sections")
	for _, s := range sections.O {
		out[s.K] = validation.ObjAt(s.V, "ok").Kind == validation.Bool && validation.ObjAt(s.V, "ok").B
	}
	return out
}

func initCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	Setup()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func readLogLines(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, ln := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

func writeLogLines(t *testing.T, c *state.Campaign, lines []string) {
	t.Helper()
	if err := os.WriteFile(c.EventsPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAuditCleanCampaignPasses(t *testing.T) {
	Setup()
	if n := SectionNames(); len(n) != 19 || n[16] != "v16_coverage" ||
		n[17] != "regression_suite" || n[18] != "exec_record_anchor" {
		t.Fatalf("sections not registered; SectionNames()=%v", n)
	}
	c := initCampaign(t)
	p := filepath.Join(c.ArtifactsDir, "note.md")
	if err := os.WriteFile(p, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterArtifact("other", p, "", nil); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if !reportOK(report) {
		t.Fatalf("clean campaign flagged: %v", sectionOKFlags(report))
	}
	// initCampaign is a bare state.Init: no price, no sandbox.exec event, so
	// the presence-gated price_table and exec_record_anchor do not render.
	want := []string{"event_log", "artifacts", "execs", "findings",
		"projection", "snapshots", "relations", "floor_policy",
		"stage_completions", "baselines", "invariant_verification",
		"sequence_coverage", "probe_surface", "unpriceable", "v16_coverage"}
	if got := sectionNames(t, report); !reflect.DeepEqual(got, want) {
		t.Fatalf("sections = %v, want %v", got, want)
	}
	flags := sectionOKFlags(report)
	for _, name := range want {
		if !flags[name] {
			t.Errorf("section %s not ok on clean campaign", name)
		}
	}
	if line := AuditSummaryLine(report); !strings.HasPrefix(line, "audit PASS: ") {
		t.Errorf("summary = %q, want audit PASS prefix", line)
	}
}

func TestAuditTamperedArtifactIsCaught(t *testing.T) {
	c := initCampaign(t)
	p := filepath.Join(c.ArtifactsDir, "note.md")
	if err := os.WriteFile(p, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterArtifact("other", p, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("attacker rewrote this\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if reportOK(report) {
		t.Fatalf("tampered artifact not flagged: %v", sectionOKFlags(report))
	}
	if !anyProblem(report, "content hash mismatch") {
		t.Errorf("no content hash mismatch problem; arts=%v", problemsOf(report, "artifacts"))
	}
}

func TestAuditMissingArtifactIsCaught(t *testing.T) {
	c := initCampaign(t)
	p := filepath.Join(c.ArtifactsDir, "gone.md")
	if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterArtifact("other", p, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if reportOK(report) {
		t.Fatalf("missing artifact not flagged")
	}
	if !anyProblem(report, "missing file") {
		t.Errorf("no missing-file problem; arts=%v", problemsOf(report, "artifacts"))
	}
}

// anyProblem reports whether the report has a problem containing `sub`.
func anyProblem(report validation.Value, sub string) bool {
	sections := validation.ObjAt(report, "sections")
	for _, s := range sections.O {
		for _, p := range arrStr(s.V, "problems") {
			if strings.Contains(p, sub) {
				return true
			}
		}
	}
	return false
}

// problemsOf returns the problems of one section.
func problemsOf(report validation.Value, section string) []string {
	sections := validation.ObjAt(report, "sections")
	for _, s := range sections.O {
		if s.K == section {
			return arrStr(s.V, "problems")
		}
	}
	return nil
}

func TestAuditTamperedEventLogIsCaught(t *testing.T) {
	c := initCampaign(t)
	if _, err := c.Log("t", nil, nil); err != nil {
		t.Fatal(err)
	}
	lines := readLogLines(t, c)
	if len(lines) < 2 {
		t.Fatalf("need >= 2 log lines, got %d", len(lines))
	}
	e0, _ := validation.ParseOrdered([]byte(lines[0]))
	e1, _ := validation.ParseOrdered([]byte(lines[1]))
	// Swap the seq fields (Task 7 tamper style).
	for i := range e0.O {
		if e0.O[i].K == "seq" {
			e0.O[i].V = validation.VInt(1)
		}
	}
	for i := range e1.O {
		if e1.O[i].K == "seq" {
			e1.O[i].V = validation.VInt(0)
		}
	}
	lines[0] = validation.CanonCompact(e0)
	lines[1] = validation.CanonCompact(e1)
	writeLogLines(t, c, lines)
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if reportOK(report) {
		t.Fatalf("tampered log not flagged: %v", sectionOKFlags(report))
	}
	if len(problemsOf(report, "event_log")) == 0 {
		t.Error("no event_log problems recorded")
	}
}

func TestAuditSchemaInvalidFindingIsCaught(t *testing.T) {
	c := initCampaign(t)
	if err := os.MkdirAll(c.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fid := "F-" + strings.Repeat("0", 12)
	body := `{"finding_id": "` + fid + `", "status": "NOT_A_REAL_STATUS"}`
	if err := os.WriteFile(filepath.Join(c.FindingsDir, fid+".json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if reportOK(report) {
		t.Fatalf("invalid finding not flagged: %v", sectionOKFlags(report))
	}
	if !anyProblem(report, "finding validation failed") {
		t.Errorf("no finding validation problem; findings=%v", problemsOf(report, "findings"))
	}
	// The problem is keyed by the filename.
	probs := problemsOf(report, "findings")
	found := false
	for _, p := range probs {
		if strings.HasPrefix(p, fid+".json: finding validation failed") {
			found = true
		}
	}
	if !found {
		t.Errorf("problem not keyed by filename; findings=%v", probs)
	}
}

// TestAuditProjectionDriftIsCaught: a phantom artifact in state with no
// artifact.registered log event must be flagged by the projection section.
func TestAuditProjectionDriftIsCaught(t *testing.T) {
	c := initCampaign(t)
	// A real artifact first: its artifact.registered event makes the
	// projection check active (Python runs only `if artifact_refs:`).
	real := filepath.Join(c.ArtifactsDir, "real.md")
	if err := os.WriteFile(real, []byte("real\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterArtifact("other", real, "", nil); err != nil {
		t.Fatal(err)
	}
	// Hand-edit the state file: add a phantom artifact row (schema-valid)
	// that has no matching artifact.registered event in the log.
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	phantom := validation.VObj(
		validation.KV{K: "artifact_id", V: validation.VStr("ART-phantomx1")},
		validation.KV{K: "kind", V: validation.VStr("other")},
		validation.KV{K: "path", V: validation.VStr("nowhere.txt")},
		validation.KV{K: "registered_at", V: validation.VStr("2020-01-01T00:00:00.000000+00:00")},
	)
	arts := validation.ObjAt(st, "artifacts")
	arts.A = append(arts.A, phantom)
	for i := range st.O {
		if st.O[i].K == "artifacts" {
			st.O[i].V = arts
		}
	}
	// Write the state back via the validation writer (re-validates).
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if reportOK(report) {
		t.Fatalf("projection drift not flagged: %v", sectionOKFlags(report))
	}
	if !anyProblem(report, "state lists artifact ART-phantomx1 with no artifact.registered event") {
		t.Errorf("no projection drift problem; projection=%v", problemsOf(report, "projection"))
	}
}

// TestAuditTamperedExecOutputIsCaught: an exec record with a real
// artifact hash, then mutate the output file; execs flags it.
func TestAuditTamperedExecOutputIsCaught(t *testing.T) {
	c := initCampaign(t)
	eid := "EXEC-aaaaaaaaaa"
	outDir := filepath.Join(c.ExecsDir, eid)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(outDir, "stdout.log")
	if err := os.WriteFile(stdout, []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sha, err := validation.Sha256File(stdout)
	if err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(eid)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "profile", V: validation.VStr("host-readonly")},
		validation.KV{K: "command", V: validation.VStr("true")},
		validation.KV{K: "policy_verdict", V: validation.VObj(
			validation.KV{K: "allowed", V: validation.VBool(true)})},
		validation.KV{K: "started_at", V: validation.VStr("2020-01-01T00:00:00.000000+00:00")},
		validation.KV{K: "artifact_hashes", V: validation.VObj(
			validation.KV{K: "stdout.log", V: validation.VStr(sha)})},
	)
	if err := validation.WriteJson(filepath.Join(outDir, "exec_record.json"), rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stdout, []byte("forged success\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if reportOK(report) {
		t.Fatalf("tampered exec output not flagged: %v", sectionOKFlags(report))
	}
	if !anyProblem(report, "stdout.log hash mismatch after execution") {
		t.Errorf("no exec hash mismatch; execs=%v", problemsOf(report, "execs"))
	}
}

// TestAuditRegisterExecThenMutateFile: a schema-valid exec record whose
// artifact_hash points at a real file, then mutate the file.
func TestAuditRegisterExecThenMutateFile(t *testing.T) {
	c := initCampaign(t)
	eid := "EXEC-bbbbbbbbbb"
	outDir := filepath.Join(c.ExecsDir, eid)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(outDir, "out.txt")
	if err := os.WriteFile(outFile, []byte("clean output\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sha, err := validation.Sha256File(outFile)
	if err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(eid)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "profile", V: validation.VStr("docker-networkless")},
		validation.KV{K: "command", V: validation.VStr("true")},
		validation.KV{K: "policy_verdict", V: validation.VObj(
			validation.KV{K: "allowed", V: validation.VBool(true)})},
		validation.KV{K: "started_at", V: validation.VStr("2020-01-01T00:00:00.000000+00:00")},
		validation.KV{K: "artifact_hashes", V: validation.VObj(
			validation.KV{K: "out.txt", V: validation.VStr(sha)})},
	)
	if err := validation.WriteJson(filepath.Join(outDir, "exec_record.json"), rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outFile, []byte("different\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if reportOK(report) {
		t.Fatalf("register-exec + mutate not flagged: %v", sectionOKFlags(report))
	}
	if !anyProblem(report, "out.txt hash mismatch after execution") {
		t.Errorf("no exec output hash mismatch; execs=%v", problemsOf(report, "execs"))
	}
}

// TestAuditSnapshotMutatedIsCaught: pin a plain directory, then mutate a
// pinned file; the snapshots section flags the content hash mismatch.
func TestAuditSnapshotMutatedIsCaught(t *testing.T) {
	c := initCampaign(t)
	target := filepath.Join(c.Root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := validation.VObj()
	snap, err := snapshot.PinSourceSnapshot(c, target, &cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	sid := validation.ObjStr(snap, "snapshot_id")
	if sid == "" {
		t.Fatalf("no snapshot_id from pin: %v", snap)
	}
	// Mutate a file inside the pinned copy (snapshot.json excluded from
	// the content hash, so mutate a real source file).
	pinnedDir := filepath.Join(c.Dir, "snapshots", sid)
	if err := os.WriteFile(filepath.Join(pinnedDir, "a.txt"), []byte("mutated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if reportOK(report) {
		t.Fatalf("mutated snapshot not flagged: %v", sectionOKFlags(report))
	}
	if !anyProblem(report, "content hash mismatch") {
		t.Errorf("no snapshot content hash problem; snapshots=%v", problemsOf(report, "snapshots"))
	}
}

// TestAuditSummaryLineFail: one artifact problem yields the exact
// "audit FAIL: artifacts=1 problem(s)" prefix.
func TestAuditSummaryLineFail(t *testing.T) {
	c := initCampaign(t)
	p := filepath.Join(c.ArtifactsDir, "note.md")
	if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterArtifact("other", p, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	line := AuditSummaryLine(report)
	if !strings.HasPrefix(line, "audit FAIL: event_log=0 problem(s), artifacts=1 problem(s)") {
		t.Errorf("summary = %q, want audit FAIL: event_log=0 problem(s), artifacts=1 problem(s) prefix", line)
	}
}

// TestAuditRegistryOrderPinned: the section registry exposes every ported
// section in Python's audit.py code order — all 14, sequence_coverage (12)
// between invariant_verification (11) and probe_surface (13) — with the
// presence-gated G4 eval section, the presence-gated r4 price_table
// reconciliation, and, appended last, the v1.6 record-coverage section
// (eval and price_table render conditionally; v16_coverage always renders).
// v1.6 Phase 0 appends the presence-gated regression_suite after it, and the
// v1.6 exec-record anchor is appended last of all (presence-gated on a
// campaign that holds any sandbox.exec / sandbox.exec.registered event).
func TestAuditRegistryOrderPinned(t *testing.T) {
	Setup()
	want := []string{"event_log", "artifacts", "execs", "findings",
		"projection", "snapshots", "relations", "floor_policy",
		"stage_completions", "baselines", "invariant_verification",
		"sequence_coverage", "probe_surface", "unpriceable", "eval",
		"price_table", "v16_coverage", "regression_suite",
		"exec_record_anchor"}
	if got := SectionNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SectionNames() = %v, want %v", got, want)
	}
}
