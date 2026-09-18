package cli

// cmd_artifact_prune_test.go: the operator's retirement tool (r27 F7). The
// registry is append-only and its growth knowingly unbounded (docs/
// MINIPROVER_INTEGRATION.md §10), so the verb that retires a row must
// exist, must record WHY, and must WARN — never refuse — when the row it
// retires is the evidence a live blessing cites. Refusing is the bind's
// discipline (the cite-guard); the operator's explicit act is not the
// bind's, and the burn that follows is the honest cost.
//
// The cited fixture is built exactly the way the mapper builds it: a
// report whose bytes re-derive the rung through harness.MapReport, the
// invariant slot, and the harness_run event that pins the report digest.
// That makes the PRE-prune audit green and the POST-prune audit red for
// the one reason under test — the retired row.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// t27CampaignRegister writes a file into the campaign root and registers
// it, returning the artifact id.
func t27CampaignRegister(t *testing.T, c *state.Campaign, name string) string {
	t.Helper()
	path := filepath.Join(c.Root, name)
	if err := os.WriteFile(path, []byte("report bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	aid, err := c.RegisterArtifact("report", path, "", snap)
	if err != nil {
		t.Fatal(err)
	}
	return aid
}

// t27CitedFixture registers a REPORT- row and lands the binding a live
// blessing would carry for iid: the invariant slot plus the harness_run
// event that pins the row's digest as its report_sha256. Returns the
// artifact id and the pinned digest.
func t27CitedFixture(t *testing.T, c *state.Campaign, iid, exec string) (string, string) {
	t.Helper()
	// r33 F4(b)/F5: a report rung's printed exec label must name the pin it
	// cites, and its kind must be the report kind — a fixture pairing a
	// scaffold kind with REPORT- provenance is a shape NO bind can write,
	// which is exactly what section 11 now burns. The label is therefore
	// derived from the pin, and the caller's argument is ignored.
	prop := validation.VObj(
		kv("outcome", validation.VStr("PROVEN")),
		kv("per_rule", validation.VObj(kv("inv_p", validation.VStr("PROVEN")))),
	)
	// r32: the audit re-derives the bind's published/review gates, so the
	// fixture must be a report a fresh bind would actually accept — it no
	// longer merely has to look like one.
	rep := validation.VObj(
		kv("schema_version", validation.VStr("1.0")),
		kv("published", validation.VBool(true)),
		kv("publish_problems", validation.VArr()),
		kv("review_independent", validation.VBool(true)),
		kv("capabilities_missing", validation.VArr()),
		kv("flags", validation.VObj(kv("loop_bound", validation.VInt(100)))),
		kv("property_outcomes", validation.VObj(kv("p", prop))),
		kv("review_findings", validation.VArr()),
	)
	path := filepath.Join(c.Root, "report.json")
	if err := validation.WriteJson(path, rep, ""); err != nil {
		t.Fatal(err)
	}
	aid, err := c.RegisterArtifact("report", path, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	row, err := c.Artifact(aid)
	if err != nil {
		t.Fatal(err)
	}
	sha := validation.ObjStr(row, "sha256")
	exec = harness.ReportExecLabel(sha)
	_ = exec
	// Derive the rung through the functions the audit re-derives with, so
	// the fixture is an honest bind rather than a shape that merely looks
	// like one.
	k, kStated, kOK, why := harness.BoundFromFlags(validation.ObjAt(rep, "flags"))
	if !kOK {
		t.Fatalf("fixture bound must be mappable: %s", why)
	}
	rung, summary, bk := harness.MapReport(validation.ObjStr(prop, "outcome"),
		validation.ObjAt(prop, "per_rule"), k, kStated)
	if bk == nil {
		t.Fatal("fixture must derive a bound")
	}
	model := validation.VObj(kv("invariants", validation.VArr(
		validation.VObj(
			kv("id", validation.VStr(iid)),
			kv("statement", validation.VStr("the report blesses this"))))))
	if _, err := invariants.SeedFromModel(c, model); err != nil {
		t.Fatal(err)
	}
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := validation.ObjAt(links, "invariants")
	e := validation.ObjAt(reg, iid)
	h := validation.VObj(
		kv("kind", validation.VStr(string(harness.ReportKind))),
		kv("rung", validation.VStr(rung)),
		kv("exec", validation.VStr(exec)),
		kv("bounded_k", validation.VInt(int64(*bk))),
		kv("summary", validation.VStr(summary)),
	)
	e.O = validation.SetOrAppend(e.O, "verification",
		validation.VObj(kv("harness", h)))
	reg.O = validation.SetOrAppend(reg.O, iid, e)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	data := validation.VObj(
		kv("invariant", validation.VStr(iid)),
		kv("kind", validation.VStr(string(harness.ReportKind))),
		kv("rung", validation.VStr(rung)),
		kv("exec", validation.VStr(exec)),
		kv("summary", validation.VStr(summary)),
		kv("bounded_k", validation.VInt(int64(*bk))),
		kv("property", validation.VStr("p")),
		kv("report_sha256", validation.VStr(sha)),
	)
	ref := iid
	if _, err := c.Log("harness_run", &ref, &data); err != nil {
		t.Fatal(err)
	}
	return aid, sha
}

// t27AuditSection runs `audit --json` and returns the exit code and the
// invariant_verification section.
func t27AuditSection(t *testing.T, root, cid string) (int, validation.Value) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if out == "" {
		t.Fatalf("audit printed no report (exit %d, stderr %q)", code, errS)
	}
	rep, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("audit --json did not parse: %v\n%s", err, out)
	}
	return code, validation.ObjAt(validation.ObjAt(rep, "sections"), "invariant_verification")
}

// t27PrunedEvent is the artifact.pruned event for aid.
func t27PrunedEvent(t *testing.T, c *state.Campaign, aid string) validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if validation.ObjStr(ev, "type") == "artifact.pruned" &&
			validation.ObjStr(ev, "ref") == aid {
			return ev
		}
	}
	t.Fatalf("no artifact.pruned event names %s", aid)
	return validation.VNull()
}

// TestArtifactPruneUncitedRow: the plain retirement — exit 0, the row gone
// from artifact-list, and the ledger carrying the reason.
func TestArtifactPruneUncitedRow(t *testing.T) {
	c, root := t15Campaign(t, "prune")
	aid := t27CampaignRegister(t, c, "old-report.json")
	code, out, errS := run(t, "--root", root, "artifact-prune", aid,
		"--reason", "superseded by the re-bind")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := aid + ": kind=report path=old-report.json\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
	if errS != "" {
		t.Fatalf("an uncited row must prune without a warning: %q", errS)
	}
	code, out, errS = run(t, "--root", root, "artifact-list", c.CampaignID)
	if code != 0 {
		t.Fatalf("artifact-list exit %d: %q", code, errS)
	}
	if strings.Contains(out, aid) {
		t.Fatalf("the retired row is still listed: %q", out)
	}
	ev := t27PrunedEvent(t, c, aid)
	if got := validation.ObjStr(validation.ObjAt(ev, "data"), "reason"); got != "superseded by the re-bind" {
		t.Fatalf("data.reason = %q, want the operator's reason", got)
	}
}

// TestArtifactPruneJSON: --json prints the retired row with the reason it
// was retired for, in the sibling --json shape (indent-2 ASCII).
func TestArtifactPruneJSON(t *testing.T) {
	c, root := t15Campaign(t, "prune")
	aid := t27CampaignRegister(t, c, "old.json")
	code, out, errS := run(t, "--root", root, "artifact-prune", aid,
		"--reason", "nothing cites it", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json output does not parse: %v\n%s", err, out)
	}
	if got["artifact_id"] != aid || got["kind"] != "report" ||
		got["path"] != "old.json" || got["reason"] != "nothing cites it" {
		t.Fatalf("--json object = %v", got)
	}
}

// TestArtifactPruneCitedRowWarnsAndBurnsTheRung is the contract's sharp
// edge: the row a live blessing cites is NOT protected from the operator —
// it warns on stderr, prunes anyway, and the audit's own re-derivation then
// names the missing evidence and qualifies the rung (UNBACKED).
func TestArtifactPruneCitedRowWarnsAndBurnsTheRung(t *testing.T) {
	c, root := t15Campaign(t, "prune")
	aid, sha := t27CitedFixture(t, c, "INV-3", "REPORT-9")
	wantRun := "INV-3: PROVEN-BOUNDED (" + string(harness.ReportKind) +
		", k=100, " + harness.ReportExecLabel(sha) + ")"
	// PRE: the binding is honest — the store holds the cited bytes, so the
	// section is green and the rung prints unqualified.
	code, sec := t27AuditSection(t, root, c.CampaignID)
	if code != 0 || !validation.ObjAt(sec, "ok").B {
		t.Fatalf("fixture must start green: exit %d, section %s", code,
			validation.CanonCompact(sec))
	}
	runs := validation.ObjAt(sec, "harness_runs")
	if len(runs.A) != 1 || runs.A[0].S != wantRun {
		t.Fatalf("pre-prune harness_runs = %s",
			validation.CanonCompact(runs))
	}
	code, out, errS := run(t, "--root", root, "artifact-prune", aid,
		"--reason", "the report is stale")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != aid+": kind=report path=report.json\n" {
		t.Fatalf("stdout %q", out)
	}
	for _, want := range []string{"WARNING", aid, "INV-3", "UNBACKED"} {
		if !strings.Contains(errS, want) {
			t.Fatalf("stderr must name %q: %q", want, errS)
		}
	}
	// POST: section 11 re-derives against the registry, finds nothing that
	// holds the pinned bytes, and says so — and the line a consumer reads
	// carries the qualifier.
	code, sec = t27AuditSection(t, root, c.CampaignID)
	if code != 1 {
		t.Fatalf("audit must exit 1 once the cited row is retired: %d", code)
	}
	if validation.ObjAt(sec, "ok").B {
		t.Fatalf("section 11 must burn: %s", validation.CanonCompact(sec))
	}
	joined := ""
	for _, p := range validation.ObjAt(sec, "problems").A {
		joined += p.S + "\n"
	}
	if !strings.Contains(joined, "no registry artifact holds the report bytes") ||
		!strings.Contains(joined, sha[:12]) {
		t.Fatalf("the burn must name the exact state observed: %q", joined)
	}
	runs = validation.ObjAt(sec, "harness_runs")
	if len(runs.A) != 1 {
		t.Fatalf("harness_runs = %s", validation.CanonCompact(runs))
	}
	if !strings.HasSuffix(runs.A[0].S, " (UNBACKED)") {
		t.Fatalf("an unbacked blessing must be qualified: %q", runs.A[0].S)
	}
}

// TestArtifactPruneMissingIDExits2: the id is required, and an explicitly
// empty one is missing too.
func TestArtifactPruneMissingIDExits2(t *testing.T) {
	_, root := t15Campaign(t, "prune")
	want := artifactPruneUsage + "webv2 artifact-prune: error: the " +
		"following arguments are required: artifact_id\n"
	code, out, errS := run(t, "--root", root, "artifact-prune",
		"--reason", "why")
	if code != 2 || errS != want || out != "" {
		t.Fatalf("missing id: exit %d, stdout %q, stderr\n%q\nwant\n%q",
			code, out, errS, want)
	}
	code, out, errS = run(t, "--root", root, "artifact-prune", "",
		"--reason", "why")
	if code != 2 || out != "" ||
		!strings.Contains(errS, "artifact_id must not be empty") {
		t.Fatalf("empty id: exit %d, stdout %q, stderr %q", code, out, errS)
	}
}

// TestArtifactPruneMissingReasonExits2: the ledger must record WHY, so a
// missing or blank reason is a usage error, not a default.
func TestArtifactPruneMissingReasonExits2(t *testing.T) {
	c, root := t15Campaign(t, "prune")
	aid := t27CampaignRegister(t, c, "old.json")
	want := artifactPruneUsage + "webv2 artifact-prune: error: the " +
		"following arguments are required: --reason\n"
	code, out, errS := run(t, "--root", root, "artifact-prune", aid)
	if code != 2 || errS != want || out != "" {
		t.Fatalf("missing reason: exit %d, stdout %q, stderr\n%q\nwant\n%q",
			code, out, errS, want)
	}
	code, out, errS = run(t, "--root", root, "artifact-prune", aid,
		"--reason", "   ")
	if code != 2 || out != "" ||
		!strings.Contains(errS, "--reason must not be empty") {
		t.Fatalf("blank reason: exit %d, stdout %q, stderr %q", code, out, errS)
	}
	// The refused attempts must not have retired anything.
	code, out, errS = run(t, "--root", root, "artifact-list", c.CampaignID)
	if code != 0 || !strings.Contains(out, aid) {
		t.Fatalf("a refused prune must not touch the row (exit %d): %q %q",
			code, out, errS)
	}
}

// TestArtifactPruneUnknownIDExits2: an id no campaign holds is a usage
// error naming the id — in a workspace with campaigns and in one without.
func TestArtifactPruneUnknownIDExits2(t *testing.T) {
	_, root := t15Campaign(t, "prune")
	for _, r := range []string{root, mkroot(t)} {
		code, out, errS := run(t, "--root", r, "artifact-prune",
			"ART-nope1234", "--reason", "why")
		if code != 2 || out != "" {
			t.Fatalf("root %q: exit %d, stdout %q, stderr %q", r, code, out,
				errS)
		}
		if !strings.Contains(errS, "unknown artifact 'ART-nope1234'") {
			t.Fatalf("root %q: stderr must name the id: %q", r, errS)
		}
	}
}

// TestArtifactPruneAmbiguousIDRefuses: one id in two campaigns is
// reachable only by a hand-edited registry pair, and the verb refuses to
// guess which row the operator meant (exit 2, both campaigns named).
func TestArtifactPruneAmbiguousIDRefuses(t *testing.T) {
	c1, root := t15Campaign(t, "prune")
	aid := t27CampaignRegister(t, c1, "old.json")
	c2, err := state.Open(root, initOne(t, root))
	if err != nil {
		t.Fatal(err)
	}
	row, err := c1.Artifact(aid)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c2.State()
	if err != nil {
		t.Fatal(err)
	}
	arts := validation.ObjAt(st, "artifacts")
	arts.A = append(arts.A, row)
	st.O = validation.SetOrAppend(st.O, "artifacts", arts)
	if err := c2.SaveState(st); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-prune", aid,
		"--reason", "why")
	if code != 2 || out != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errS)
	}
	for _, want := range []string{"two campaigns", c1.CampaignID,
		c2.CampaignID} {
		if !strings.Contains(errS, want) {
			t.Fatalf("stderr must name %q: %q", want, errS)
		}
	}
	// Nothing was retired by the refusal.
	if _, err := c1.Artifact(aid); err != nil {
		t.Fatalf("the refusal must not touch the first row: %v", err)
	}
}

// t28ExecRecord writes one EXEC ledger row whose input_hashes and
// artifact_hashes pin the given file-name -> sha256 pairs (nil = the map is
// absent). Self-contained on purpose: the harness bind's own fixture lives
// in a file this round does not own.
func t28ExecRecord(t *testing.T, c *state.Campaign, execID string,
	inputs, artifacts map[string]string) {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	if err := os.WriteFile(stdout, []byte("{\"verdict\":\"PROVEN\"}\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		kv("exec_id", validation.VStr(execID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("profile", validation.VStr("minicertora")),
		kv("finding_id", validation.VNull()),
		kv("artifact_id", validation.VNull()),
		kv("command", validation.VStr("minicertora V.sol INV.mspec "+
			"--loop-bound 4")),
		kv("policy_verdict", validation.VObj(
			kv("allowed", validation.VBool(true)),
			kv("violations", validation.VArr()))),
		kv("origin", validation.VStr("locally-executed")),
		kv("reported_by", validation.VNull()),
		kv("started_at", validation.VStr("2026-09-11T05:06:07+00:00")),
		kv("finished_at", validation.VStr("2026-09-11T05:06:07+00:00")),
		kv("exit_status", validation.VInt(0)),
		kv("stdout_path", validation.VStr(stdout)),
		kv("stderr_path", validation.VStr(filepath.Join(dir,
			"stderr.log"))),
	)
	for key, m := range map[string]map[string]string{
		"input_hashes": inputs, "artifact_hashes": artifacts} {
		if m == nil {
			continue
		}
		kvs := make([]validation.KV, 0, len(m))
		for k, v := range m {
			kvs = append(kvs, kv(k, validation.VStr(v)))
		}
		rec.O = validation.SetOrAppend(rec.O, key, validation.VObj(kvs...))
	}
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
}

// t28ScaffoldRow is the live registry row for INV-1's minicertora scaffold
// (the row whose bytes an EXEC rung hashes as its input), by id and sha.
func t28ScaffoldRow(t *testing.T, c *state.Campaign) (string, string) {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range validation.ObjAt(st, "artifacts").A {
		if strings.HasSuffix(validation.ObjStr(row, "path"), "INV.mspec") {
			return validation.ObjStr(row, "artifact_id"), validation.ObjStr(row, "sha256")
		}
	}
	t.Fatal("the scaffold registered no INV.mspec row")
	return "", ""
}

// t28ExecRungEvent logs the harness_run event a minicertora EXEC-rung bind
// writes: the rung, the invariant and the EXEC it names — and NO
// report_sha256 (an EXEC rung's evidence is the hashed scaffold, not a
// report file), so the report arm alone can never explain a warning.
func t28ExecRungEvent(t *testing.T, c *state.Campaign, iid, execID string) {
	t.Helper()
	ref := iid
	data := validation.VObj(
		kv("invariant", validation.VStr(iid)),
		kv("kind", validation.VStr(string(harness.ReportKind))),
		kv("rung", validation.VStr("proved-bounded")),
		kv("exec", validation.VStr(execID)),
		kv("summary", validation.VStr("proved bounded (k=4)")),
		kv("bounded_k", validation.VInt(4)),
	)
	if _, err := c.Log("harness_run", &ref, &data); err != nil {
		t.Fatal(err)
	}
}

// TestR28ExecPinnedRowWarnsOnPrune is the audited N1: the scaffold row is
// cited by a live minicertora EXEC-rung bind — the harness_run event names
// EXEC-x, and EXEC-x's record pins the row's sha256 in input_hashes — and
// the prune verb retired it with EMPTY stderr, while the usage line and the
// RUNBOOK promise the warning whenever a live bind cites the row. The
// warning must name the artifact and the invariant, and the prune must
// still happen.
func TestR28ExecPinnedRowWarnsOnPrune(t *testing.T) {
	c, root := mcCamp(t, "r28-n1")
	aid, sha := t28ScaffoldRow(t, c)
	t28ExecRecord(t, c, "EXEC-0000000042",
		map[string]string{"INV.mspec": sha}, nil)
	t28ExecRungEvent(t, c, "INV-1", "EXEC-0000000042")
	code, out, errS := run(t, "--root", root, "artifact-prune", aid,
		"--reason", "the scaffold was re-authored")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	for _, want := range []string{"WARNING", aid, "INV-1", "UNBACKED"} {
		if !strings.Contains(errS, want) {
			t.Fatalf("stderr must name %q: %q", want, errS)
		}
	}
	if !strings.HasPrefix(out, aid+": ") {
		t.Fatalf("stdout must print the retired row: %q", out)
	}
	// Pruned anyway: the operator's act is not gated.
	if _, err := c.Artifact(aid); err == nil {
		t.Fatalf("the row must be retired despite the warning")
	}
}

// TestR28ExecArtifactHashesArmWarns: the second map of the same arm — a
// produced artifact_hashes entry pinning the row is the same citation.
func TestR28ExecArtifactHashesArmWarns(t *testing.T) {
	c, root := mcCamp(t, "r28-n1b")
	aid, sha := t28ScaffoldRow(t, c)
	t28ExecRecord(t, c, "EXEC-0000000043", nil,
		map[string]string{"INV.mspec": sha})
	t28ExecRungEvent(t, c, "INV-1", "EXEC-0000000043")
	code, _, errS := run(t, "--root", root, "artifact-prune", aid,
		"--reason", "superseded")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	for _, want := range []string{"WARNING", aid, "INV-1"} {
		if !strings.Contains(errS, want) {
			t.Fatalf("stderr must name %q: %q", want, errS)
		}
	}
}

// TestR28ExecCitationNeedsALiveEvent pins the boundary of the new arm: a
// pin alone is not a citation. An exec whose record pins the row is silent
// when NO harness_run event names it (the ledger row exists, nothing bound
// it), and an event that names an exec whose record does NOT pin the row is
// silent too — otherwise every artifact an unrelated run touched would warn.
func TestR28ExecCitationNeedsALiveEvent(t *testing.T) {
	c, root := mcCamp(t, "r28-n1c")
	aid, sha := t28ScaffoldRow(t, c)
	// (a) the pin exists, no event names that exec.
	t28ExecRecord(t, c, "EXEC-0000000044",
		map[string]string{"INV.mspec": sha}, nil)
	code, _, errS := run(t, "--root", root, "artifact-prune", aid,
		"--reason", "nothing bound it")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("an unbound pin must not warn: %q", errS)
	}
	// (b) the event names an exec whose record pins a DIFFERENT digest.
	c2, root2 := mcCamp(t, "r28-n1d")
	aid2, _ := t28ScaffoldRow(t, c2)
	t28ExecRecord(t, c2, "EXEC-0000000045",
		map[string]string{"INV.mspec": strings.Repeat("0", 64)}, nil)
	t28ExecRungEvent(t, c2, "INV-1", "EXEC-0000000045")
	code, _, errS = run(t, "--root", root2, "artifact-prune", aid2,
		"--reason", "the run hashed different bytes")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("an event over a different digest must not warn about "+
			"this row: %q", errS)
	}
}
