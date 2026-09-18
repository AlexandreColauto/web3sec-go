package cli

// zz_r34_test.go — round 34, F3: `artifact-register` did not honour the
// RUNBOOK's HARD RULE that A PATH HOLDS ONE REGISTRY ROW.
//
// RUNBOOK.md §"Hard rules for the operator" (assets/runbook/RUNBOOK.md:
// 1645-1650):
//
//	Sanctioned mutation of a registered artifact goes through the refresh
//	path (`artifact-register` re-registers). A path holds **one** registry
//	row: re-registering it under a different `--kind` migrates that row
//	(the refresh event records `kind_migrated: old→new`) and prunes any
//	ghost rows at the same path.
//
// The verb called state.RegisterArtifact — the APPEND primitive — so
// re-registering a registered path minted a SECOND row (an OTH- and a REP-
// row for one path), while state.RegisterOrRefresh (migrate + prune ghosts,
// the D3 law the RUNBOOK states) was reached only from report.go and
// cmd_verify_autoprove.go. The tests below run the verb twice over one path,
// through the real CLI, and assert the anchor's shape: one row, the row's id
// preserved, the kind migrated, the refresh event naming kind_migrated, and
// the first-registration stdout bytes unchanged.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// r34ArtifactRows is the campaign's registry projection.
func r34ArtifactRows(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjAt(st, "artifacts").A
}

// r34LastEvent is the campaign's newest event.
func r34LastEvent(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("fixture: the campaign holds no events")
	}
	return events[len(events)-1]
}

// r34Id is the id on the verb's success line.
func r34Id(t *testing.T, out string) string {
	t.Helper()
	line := strings.SplitN(out, "\n", 2)[0]
	id, _, ok := strings.Cut(line, ":")
	if !ok || id == "" {
		t.Fatalf("success line = %q", line)
	}
	return id
}

// r34ListPaths counts the artifact-list lines naming p (the operator-facing
// view of the registry).
func r34ListPaths(t *testing.T, root, cid, p string) (int, string) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "artifact-list", cid)
	if code != 0 {
		t.Fatalf("artifact-list exit %d: %q", code, errS)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if strings.Contains(line, p) {
			n++
		}
	}
	return n, out
}

// TestR34ArtifactRegisterReRegisterKeepsOneRow is the auditor's repro: two
// `artifact-register` invocations over ONE path, the second under a different
// --kind. Before the fix the second minted a new REP- row next to the OTH-
// row (artifact-list: two lines for one path), and no artifact.refreshed
// event was ever written — the RUNBOOK's law was simply not the verb's.
func TestR34ArtifactRegisterReRegisterKeepsOneRow(t *testing.T) {
	c, root := t15Campaign(t, "artifact-register-r34-migrate")
	path := filepath.Join(c.Root, "dump.json")
	if err := os.WriteFile(path, []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register",
		c.CampaignID, path)
	if code != 0 || errS != "" {
		t.Fatalf("first register exit %d err %q", code, errS)
	}
	id1 := r34Id(t, out)
	rows := r34ArtifactRows(t, c)
	if len(rows) != 1 {
		t.Fatalf("rows after the first register: %d", len(rows))
	}
	// The sanctioned mutation of the registered file, then the verb's
	// re-registration under its real kind.
	if err := os.WriteFile(path, []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS = run(t, "--root", root, "artifact-register",
		c.CampaignID, path, "--kind", "report")
	if code != 0 || errS != "" {
		t.Fatalf("re-register exit %d err %q", code, errS)
	}
	if !strings.HasPrefix(out, id1+": kind=report path="+path+"\n") {
		t.Fatalf("re-register minted a new row instead of refreshing %s: "+
			"%q", id1, out)
	}
	rows = r34ArtifactRows(t, c)
	if len(rows) != 1 {
		t.Fatalf("A PATH HOLDS ONE REGISTRY ROW: rows at %s = %d (%s)",
			path, len(rows), validation.CanonCompact(validation.VArr(rows...)))
	}
	if got := validation.ObjStr(rows[0], "artifact_id"); got != id1 {
		t.Fatalf("row id = %q, want the registered row %s", got, id1)
	}
	if got := validation.ObjStr(rows[0], "kind"); got != "report" {
		t.Fatalf("migrated kind = %q, want report", got)
	}
	if got := validation.ObjStr(rows[0], "sha256"); got != validation.Sha256Hex(
		[]byte("v2\n")) {
		t.Fatalf("re-register must re-hash the file: sha = %q", got)
	}
	if got := validation.ObjAt(rows[0], "refresh_count"); got.Kind != validation.Int ||
		got.I != 1 {
		t.Fatalf("refresh_count = %s, want 1", validation.CanonCompact(got))
	}
	ev := r34LastEvent(t, c)
	if got := validation.ObjStr(ev, "type"); got != "artifact.refreshed" {
		t.Fatalf("last event = %q, want artifact.refreshed", got)
	}
	d := validation.ObjAt(ev, "data")
	if got := validation.ObjStr(d, "kind_migrated"); got != "other→report" {
		t.Fatalf("kind_migrated = %q, want other→report", got)
	}
	if got := validation.ObjStr(d, "reason"); got != "re-registered (content may have "+
		"changed)" {
		t.Fatalf("refresh reason = %q", got)
	}
	if n, listOut := r34ListPaths(t, root, c.CampaignID, "dump.json"); n != 1 {
		t.Fatalf("artifact-list shows %d rows for one path:\n%s", n, listOut)
	}
}

// TestR34ArtifactRegisterSameKindReRegisterRefreshes is the same law without
// a kind change: re-registering the SAME path under the SAME kind refreshes
// the row in place (no ghost, no second id, no kind_migrated key), which is
// what makes the refresh path the sanctioned mutation the RUNBOOK names.
func TestR34ArtifactRegisterSameKindReRegisterRefreshes(t *testing.T) {
	c, root := t15Campaign(t, "artifact-register-r34-refresh")
	path := filepath.Join(c.Root, "notes.md")
	if err := os.WriteFile(path, []byte("n1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register",
		c.CampaignID, path, "--kind", "poc")
	if code != 0 || errS != "" {
		t.Fatalf("register exit %d err %q", code, errS)
	}
	id1 := r34Id(t, out)
	if err := os.WriteFile(path, []byte("n2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS = run(t, "--root", root, "artifact-register",
		c.CampaignID, path, "--kind", "poc")
	if code != 0 || errS != "" {
		t.Fatalf("re-register exit %d err %q", code, errS)
	}
	if !strings.HasPrefix(out, id1+": kind=poc path="+path+"\n") {
		t.Fatalf("same-kind re-register must refresh %s: %q", id1, out)
	}
	rows := r34ArtifactRows(t, c)
	if len(rows) != 1 {
		t.Fatalf("rows after same-kind re-register: %d", len(rows))
	}
	if got := validation.ObjAt(rows[0], "refresh_count"); got.Kind != validation.Int ||
		got.I != 1 {
		t.Fatalf("refresh_count = %s, want 1", validation.CanonCompact(got))
	}
	ev := r34LastEvent(t, c)
	if got := validation.ObjStr(ev, "type"); got != "artifact.refreshed" {
		t.Fatalf("last event = %q, want artifact.refreshed", got)
	}
	if got := validation.ObjAt(validation.ObjAt(ev, "data"), "kind_migrated"); got.Kind !=
		validation.Null {
		t.Fatalf("same-kind refresh must not record kind_migrated: %s",
			validation.CanonCompact(ev))
	}
}

// TestR34ArtifactRegisterPrunesGhostsAtThePath pins the second half of the
// RUNBOOK sentence: "…and prunes any ghost rows at the same path". Two rows
// at one path — the shape the append primitive left behind — must collapse to
// one when the verb re-registers the path, with an artifact.pruned event
// naming the retired row.
func TestR34ArtifactRegisterPrunesGhostsAtThePath(t *testing.T) {
	c, root := t15Campaign(t, "artifact-register-r34-ghosts")
	path := filepath.Join(c.Root, "report.md")
	if err := os.WriteFile(path, []byte("r1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	// The old verb's own primitive, twice: the two-ghost shape the D3
	// supersession story describes (report.md registered as "other", then as
	// "report", one row per registration).
	ghostA, err := c.RegisterArtifact("other", path, "", snap)
	if err != nil {
		t.Fatal(err)
	}
	ghostB, err := c.RegisterArtifact("poc", path, "", snap)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register",
		c.CampaignID, path, "--kind", "report")
	if code != 0 || errS != "" {
		t.Fatalf("re-register exit %d err %q", code, errS)
	}
	rows := r34ArtifactRows(t, c)
	if len(rows) != 1 {
		t.Fatalf("ghost rows must be pruned: rows = %d (%s)", len(rows),
			validation.CanonCompact(validation.VArr(rows...)))
	}
	if got := validation.ObjStr(rows[0], "kind"); got != "report" {
		t.Fatalf("surviving kind = %q, want report", got)
	}
	if got := validation.ObjStr(rows[0], "artifact_id"); got != ghostA && got != ghostB {
		t.Fatalf("surviving row %q is neither registered ghost", got)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	pruned := map[string]bool{}
	for _, ev := range events {
		if validation.ObjStr(ev, "type") == "artifact.pruned" {
			// The retired row's id is the event's REF (PruneArtifact logs
			// artifact.pruned with the id as the ref, the row's kind/path
			// and the reason in data).
			pruned[validation.ObjStr(ev, "ref")] = true
		}
	}
	if !pruned[ghostA] && !pruned[ghostB] {
		t.Fatalf("the pruned ghost must have an artifact.pruned event: %s",
			validation.CanonCompact(validation.VArr(events...)))
	}
	if strings.Contains(out, "REP-") {
		t.Fatalf("the verb must reuse the registry row, not mint: %q", out)
	}
}

// TestR34ArtifactRegisterFreshShapeUnchanged is the contract guard: the
// RUNBOOK documents the register VERB and the existing tests pin its stdout
// for a path that is NOT yet registered (two lines: the success line and the
// immutability notice). Re-registration must not have rewritten that shape.
func TestR34ArtifactRegisterFreshShapeUnchanged(t *testing.T) {
	c, root := t15Campaign(t, "artifact-register-r34-fresh")
	path := filepath.Join(c.Root, "check.md")
	if err := os.WriteFile(path, []byte("checked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register",
		c.CampaignID, path, "--kind", "other")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout\n%q\nwant the success line plus one notice", out)
	}
	if !strings.HasPrefix(lines[0], "OTH-") {
		t.Fatalf("first line = %q", lines[0])
	}
	want := "note: registered artifacts are immutable — to revise, register " +
		"a new artifact (the old one stays for provenance)"
	if lines[1] != want {
		t.Fatalf("fresh-register notice\n%q\nwant\n%q", lines[1], want)
	}
}

// ---------------------------------------------------------------------------
// F1's end-to-end half: the same forged campaign through the AUDIT verb (the
// finding's own repro — "audit exit 0, problems [], TWO blessing lines").
// ---------------------------------------------------------------------------

// r34ReportBody is reports/report.json keyed by the EMPTY title: the byte a
// bind can never pair with an --property, because the verb refuses the empty
// title before it opens the report.
const r34ReportBody = `{"schema_version": "1.0", "published": true, ` +
	`"publish_problems": [], "review_independent": true, ` +
	`"capabilities_missing": [], ` +
	`"flags": {"loop_bound": 4, "path_cap": 64, "timeout_ms": 30000}, ` +
	`"property_outcomes": {"": {"outcome": "PROVEN", ` +
	`"per_rule": {"inv_1": "PROVEN"}}}, "review_findings": []}` + "\n"

// r34BlankTitleCampaign builds the auditor's repro with the campaign's OWN
// writers (RegisterOrRefresh, SaveLinks, Log), so the chain and the
// display/ledger backstop are valid and the ONLY thing wrong is the title: a
// registered report keyed "", and INV-1/INV-2 slot+event pairs claiming that
// one proof under the blank title.
func r34BlankTitleCampaign(t *testing.T, program string) (*state.Campaign,
	string) {
	t.Helper()
	c, root := t15Campaign(t, program)
	t15SeedInvariant(t, c, "INV-1", "total always covers sum(payouts)")
	t15SeedInvariant(t, c, "INV-2", "shares always sum to one")
	raw := []byte(r34ReportBody)
	dir := filepath.Join(c.ArtifactsDir, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sha := validation.Sha256Hex(raw)
	p := filepath.Join(dir, "report-"+sha+".json")
	if err := os.WriteFile(p, raw, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterOrRefresh("harness", p, "r34 fixture", nil,
		"r34 fixture"); err != nil {
		t.Fatal(err)
	}
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := validation.ObjAt(links, "invariants")
	for _, iid := range []string{"INV-1", "INV-2"} {
		rung := validation.VStr(harness.RungProvedBounded)
		summary := validation.VStr("autoproved bounded (k=4, 1 rules)")
		label := validation.VStr(harness.ReportExecLabel(sha))
		h := validation.VObj(
			kvT("kind", validation.VStr(string(harness.ReportKind))),
			kvT("rung", rung),
			kvT("exec", label),
			kvT("bounded_k", validation.VInt(4)),
			kvT("summary", summary),
			kvT("proof", validation.VNull()),
		)
		e := validation.ObjAt(reg, iid)
		if e.Kind != validation.Obj {
			t.Fatalf("fixture: no %s in links", iid)
		}
		e.O = validation.SetOrAppend(e.O, "verification",
			validation.VObj(kvT("harness", h)))
		reg.O = validation.SetOrAppend(reg.O, iid, e)
		data := validation.VObj(
			kvT("kind", validation.VStr(string(harness.ReportKind))),
			kvT("rung", rung),
			kvT("exec", label),
			kvT("invariant", validation.VStr(iid)),
			kvT("summary", summary),
			kvT("bounded_k", validation.VInt(4)),
			kvT("proof_sha256", validation.VStr(validation.Sha256Hex(
				[]byte(validation.CanonCompact(validation.ObjAt(h, "proof")))))),
			kvT("report_sha256", validation.VStr(sha)),
			kvT("property", validation.VStr("")),
		)
		ref := iid
		if _, err := c.Log("harness_run", &ref, &data); err != nil {
			t.Fatal(err)
		}
	}
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	return c, root
}

// TestR34BlankPropertyAuditBurnsEndToEnd is F1 at the operator's door: the
// audit verb must exit non-zero with section 11 not-ok, naming the empty
// attribution and the collision, and neither forged row may display an
// unqualified blessing. Before the fix this exact campaign audited exit 0
// with problems [] and two "PROVEN-BOUNDED (miniprover, k=4, REPORT-…)"
// lines (observed at the section level in zz_r34_test.go: ok=true,
// problems=[]).
func TestR34BlankPropertyAuditBurnsEndToEnd(t *testing.T) {
	c, root := r34BlankTitleCampaign(t, "r34-blank-title-e2e")
	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	zzR32bAssertBurned(t, code, ok, joined, runs, "no bind can write")
	if !strings.Contains(joined, "already bound to INV-1") {
		t.Fatalf("the one-proof-one-row rail must run for the blank title "+
			"too: %q", joined)
	}
	rendered := 0
	for _, r := range runs.A {
		if r.Kind == validation.Str &&
			strings.Contains(r.S, "PROVEN-BOUNDED") {
			rendered++
		}
	}
	if rendered != 2 {
		t.Fatalf("both forged rows must render (qualified): %s",
			validation.CanonCompact(runs))
	}
}
