package cli

// zz_r32b_test.go — r32b F1/F2/F3 end to end, bind vs audit.
//
// The three findings are all in the REPORT rung and the audit's absence
// handling. Each repro below starts from a REAL bind (stdout pinned), then
// forges ONLY the bytes/marks the finding names, through the campaign's own
// writers (RegisterOrRefresh, Log, SaveLinks) so the chain and the state
// mirror stay valid and the ONLY thing wrong is the finding's mutation:
//
//   F1 — the bind's FIVE run-level gates (published, publish_problems,
//        review_error, the review_findings SHAPE, SUSPECT attribution) were
//        never re-derived by section 11, which called harness.MapReport
//        directly. A content-address-consistent replacement of the stored
//        report copy whose only difference is a SUSPECT finding (or
//        published:false) therefore audited GREEN while a fresh bind of
//        those very bytes exits 2. The audit's property lookup also folded
//        case/space where the bind is exact-only, so a forged event naming
//        "P1" for a report keyed "p1" re-derived instead of burning.
//   F2 — deleting ONE field (report_sha256) from the last harness_run event
//        switched the whole report rail off (recheckRegistryEvidence's
//        `dig == ""` early return): the run displayed as a backed blessing
//        with no registry lookup and no re-derivation at all.
//   F3 — blanking ONE field (exec, or kind) in the stored slot dropped the
//        invariant with no line AND no problem: harnessRunLine returned
//        ok=false and BOTH backing checks lived inside that branch.
//
// Every test asserts on section 11 itself (via zzR29bAudit, shared with the
// r29b bind-vs-audit file), never merely on the audit's exit code — an
// unrelated section going red must not be able to make these pass.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// zzR32bBody renders reports/report.json with the fields the five gates read
// exposed as parameters (the honest body is the control; the auditor's repro
// moves exactly one of them).
func zzR32bBody(prop string, published bool, problems, findings string) string {
	pub := "true"
	if !published {
		pub = "false"
	}
	return `{"schema_version": "1.0", "published": ` + pub + `, ` +
		`"publish_problems": ` + problems + `, ` +
		`"review_independent": true, "capabilities_missing": [], ` +
		`"flags": {"loop_bound": 4, "path_cap": 64, "timeout_ms": 30000}, ` +
		`"property_outcomes": {"` + prop + `": {"outcome": "PROVEN", ` +
		`"per_rule": {"inv_1": "PROVEN"}}}, ` +
		`"review_findings": ` + findings + `}` + "\n"
}

func zzR32bWrite(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// zzR32bBindHonest binds the body and pins the bind's own stdout (the rung
// line the audit will later have to re-derive).
func zzR32bBindHonest(t *testing.T, root string, c *state.Campaign,
	prop, body string) {
	t.Helper()
	rep := zzR32bWrite(t, body)
	code, out, errS := apVerify(t, root, c, "--property", prop,
		"--report", rep)
	if code != 0 {
		t.Fatalf("honest bind exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "INV-1: proved-bounded") ||
		!strings.Contains(out, "(k=4, 1 rules)") {
		t.Fatalf("honest bind stdout = %q", out)
	}
}

// zzR32bLastEvent is the LAST harness_run event data for INV-1 — the record
// the audit treats as the truth.
func zzR32bLastEvent(t *testing.T, c *state.Campaign,
	iid string) validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := validation.VNull()
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_run" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(ev, "data"), "invariant") == iid {
			last = validation.ObjAt(ev, "data")
		}
	}
	if last.Kind != validation.Obj {
		t.Fatalf("no harness_run event for %s", iid)
	}
	return last
}

func zzR32bLand(t *testing.T, c *state.Campaign, iid string,
	data validation.Value) {
	t.Helper()
	ref := iid
	if _, err := c.Log("harness_run", &ref, &data); err != nil {
		t.Fatal(err)
	}
}

// zzR32bRepinLast lands a copy of the last harness_run event with one key set.
func zzR32bRepinLast(t *testing.T, c *state.Campaign, iid, key string,
	v validation.Value) {
	t.Helper()
	forged := zzR32bLastEvent(t, c, iid)
	forged.O = validation.SetOrAppend(forged.O, key, v)
	zzR32bLand(t, c, iid, forged)
}

// zzR32bDropKey lands a copy of the last harness_run event with one key
// REMOVED (the F2 mutation: absence, not a different value).
func zzR32bDropKey(t *testing.T, c *state.Campaign, iid, key string) {
	t.Helper()
	last := zzR32bLastEvent(t, c, iid)
	forged := validation.VObj()
	for _, kv := range last.O {
		if kv.K == key {
			continue
		}
		forged.O = append(forged.O, kv)
	}
	if len(forged.O) == 0 {
		t.Fatal("fixture: the forged event lost every field")
	}
	zzR32bLand(t, c, iid, forged)
}

// zzR32bForgeCopy writes raw as a NEW content-addressed store row (the shape
// cli.storeReportCopy publishes), then re-pins the last harness_run event to
// its digest. The registry row hashes exactly the bytes it names, the event
// rides the chain, and the slot keeps the same rung/exec/summary/bounded_k —
// so nothing but the report bytes behind the pin has moved.
func zzR32bForgeCopy(t *testing.T, c *state.Campaign, raw []byte) string {
	t.Helper()
	dir := filepath.Join(c.ArtifactsDir, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sha := validation.Sha256Hex(raw)
	p := filepath.Join(dir, "report-"+sha+".json")
	if err := os.WriteFile(p, raw, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterOrRefresh("harness", p,
		"r32b forged report copy", nil, "r32b forged report copy"); err != nil {
		t.Fatal(err)
	}
	zzR32bRepinLast(t, c, "INV-1", "report_sha256", validation.VStr(sha))
	return sha
}

// zzR32bSetSlotField rewrites one field of INV-1's stored
// verification.harness (the slot the audit's display line reads).
func zzR32bSetSlotField(t *testing.T, c *state.Campaign, key, val string) {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := validation.ObjAt(links, "invariants")
	entry := validation.ObjAt(reg, "INV-1")
	ver := validation.ObjAt(entry, "verification")
	h := validation.ObjAt(ver, "harness")
	if h.Kind != validation.Obj {
		t.Fatal("no verification.harness to edit")
	}
	h.O = validation.SetOrAppend(h.O, key, validation.VStr(val))
	ver.O = validation.SetOrAppend(ver.O, "harness", h)
	entry.O = validation.SetOrAppend(entry.O, "verification", ver)
	reg.O = validation.SetOrAppend(reg.O, "INV-1", entry)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
}

// zzR32bAssertBurned is the shared burn assertion: section 11 must be not-ok
// (with the audit non-zero), the problem text must name wantText, and every
// harness_runs line still rendered must be qualified UNBACKED.
func zzR32bAssertBurned(t *testing.T, code int, ok bool, joined string,
	runs validation.Value, wantText string) {
	t.Helper()
	if code == 0 || ok {
		t.Fatalf("section 11 must burn over the forged report: exit %d "+
			"ok=%v problems=%q runs=%s", code, ok, joined,
			validation.CanonCompact(runs))
	}
	if !strings.Contains(joined, wantText) {
		t.Fatalf("the burn must name %q, got %q", wantText, joined)
	}
	for _, r := range runs.A {
		if r.Kind == validation.Str && !strings.HasSuffix(r.S, " (UNBACKED)") {
			t.Fatalf("a burned rung must not print unqualified: %q", r.S)
		}
	}
}

// zzR32bHonestControl binds and asserts the unqualified pinned line + a green
// section 11 — the "must not burn an honest one" half of every finding.
func zzR32bHonestControl(t *testing.T, root string, c *state.Campaign) {
	t.Helper()
	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	if code != 0 || !ok {
		t.Fatalf("an honest report rung must audit green: exit %d ok=%v "+
			"problems=%q runs=%s", code, ok, joined,
			validation.CanonCompact(runs))
	}
	if runs.Kind != validation.Arr || len(runs.A) != 1 ||
		!strings.HasPrefix(runs.A[0].S,
			"INV-1: PROVEN-BOUNDED (miniprover, k=4, REPORT-") {
		t.Fatalf("honest line = %s", validation.CanonCompact(runs))
	}
	if s := validation.CanonCompact(runs); strings.Contains(s, "UNBACKED") {
		t.Fatalf("no qualifier on the backed path: %s", s)
	}
}

// TestZZR32bSuspectReportCopyBurns is F1's SUSPECT repro: the stored copy is
// replaced by bytes that re-derive the SAME rung (PROVEN, k=4, 1 rule) and
// differ only in review_findings:[{property:"p1",verdict:"SUSPECT"}]. A fresh
// bind of those bytes is refused by the SUSPECT gate ("the rung is refused");
// before the fix the audit of the forged campaign exited 0 with
// invariant_verification=0 problem(s) and printed the unqualified blessing.
func TestZZR32bSuspectReportCopyBurns(t *testing.T) {
	c, root := mcCamp(t, "r32b-f1-suspect")
	honest := zzR32bBody("p1", true, `[]`, `[]`)
	zzR32bBindHonest(t, root, c, "p1", honest)
	zzR32bHonestControl(t, root, c)

	// The auditor's mutation: the same bytes with a SUSPECT finding added.
	forged := strings.Replace(honest, `"review_findings": []`,
		`"review_findings": [{"property": "p1", "verdict": "SUSPECT", `+
			`"reason": "rule is vacuous: it can never fail"}]`, 1)
	if forged == honest {
		t.Fatal("fixture drift: review_findings not found")
	}
	// The forged bytes must re-derive the same rung the event claims, or the
	// burn could come from the mapping instead of the gate.
	if !strings.Contains(forged, "PROVEN") {
		t.Fatal("fixture: forged body lost the PROVEN rollup")
	}
	zzR32bForgeCopy(t, c, []byte(forged))

	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	zzR32bAssertBurned(t, code, ok, joined, runs, "SUSPECT")
	if !strings.Contains(joined, "suspect") {
		t.Fatalf("the burn must name the SUSPECT gate, got %q", joined)
	}
}

// TestZZR32bUnpublishedReportCopyBurns is F1's second repro: published:false
// next to a non-empty publish_problems (the prover's own veto). MapReport
// still derives the very same rung, so the gate is the only thing that can
// refuse these bytes — and it must.
func TestZZR32bUnpublishedReportCopyBurns(t *testing.T) {
	cases := []struct {
		name     string
		pub      bool
		problems string
		want     string
	}{
		{"unpublished with problems", false,
			`["rule inv_1 unverifiable"]`, "publish_problems"},
		{"unpublished without problems", false, `[]`, "published"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, root := mcCamp(t, "r32b-f1-"+strings.ReplaceAll(tc.name, " ", "-"))
			honest := zzR32bBody("p1", true, `[]`, `[]`)
			zzR32bBindHonest(t, root, c, "p1", honest)
			zzR32bHonestControl(t, root, c)

			zzR32bForgeCopy(t, c,
				[]byte(zzR32bBody("p1", tc.pub, tc.problems, `[]`)))

			code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
			zzR32bAssertBurned(t, code, ok, joined, runs, tc.want)
		})
	}
}

// TestZZR32bFoldEqualPropertyNameBurns is F1's lookup half: the audit's
// autoproveProp folded case/space while the bind's fieldOf is EXACT-only. A
// forged event naming "P1" for a report keyed "p1" used to re-derive and
// bless; the bind refuses those very (bytes, name) with "is not in this run
// ... exact-match only".
func TestZZR32bFoldEqualPropertyNameBurns(t *testing.T) {
	c, root := mcCamp(t, "r32b-f1-fold-name")
	zzR32bBindHonest(t, root, c, "p1", zzR32bBody("p1", true, `[]`, `[]`))
	zzR32bHonestControl(t, root, c)

	// Only the EVENT's property name moves — the report bytes, the digest,
	// the rung, the summary and the bound all stay honest.
	zzR32bRepinLast(t, c, "INV-1", "property", validation.VStr("P1"))

	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	zzR32bAssertBurned(t, code, ok, joined, runs, "P1")
}

// TestZZR32bNonSuspectFindingUnaffected is the honest control F1 needs: a
// report whose review DID run and DID leave a finding — verdict "ok" — is
// not a suspect flag and must bind and audit exactly as before.
func TestZZR32bNonSuspectFindingUnaffected(t *testing.T) {
	c, root := mcCamp(t, "r32b-f1-ok-finding")
	body := zzR32bBody("p1", true, `[]`,
		`[{"property": "p1", "verdict": "ok", "reason": "no issues found"}]`)
	zzR32bBindHonest(t, root, c, "p1", body)
	zzR32bHonestControl(t, root, c)
}

// TestZZR32bAbsentPinBurns is F2's repro: delete report_sha256 from the
// harness_run event (the row and the bytes stay exactly where they were).
// Before the fix recheckRegistryEvidence returned "" on the empty digest,
// so no registry lookup and NO re-derivation happened and the run displayed
// unqualified; now the absent pin is named and the rung burns.
func TestZZR32bAbsentPinBurns(t *testing.T) {
	c, root := mcCamp(t, "r32b-f2-absent-pin")
	zzR32bBindHonest(t, root, c, "p1", zzR32bBody("p1", true, `[]`, `[]`))
	zzR32bHonestControl(t, root, c)

	zzR32bDropKey(t, c, "INV-1", "report_sha256")

	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	zzR32bAssertBurned(t, code, ok, joined, runs, "no report_sha256")
}

// TestZZR32bAbsentPinAndPrunedRowStillBurns is the rest of F2's repro: the
// row is pruned and every store copy deleted as well. The burn must still
// name the ABSENT PIN — the reason is the missing pin, not the missing row.
func TestZZR32bAbsentPinAndPrunedRowStillBurns(t *testing.T) {
	c, root := mcCamp(t, "r32b-f2-absent-pin-pruned")
	zzR32bBindHonest(t, root, c, "p1", zzR32bBody("p1", true, `[]`, `[]`))

	// Prune every registered harness artifact row (the repro pruned the row
	// and deleted the store copies).
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range validation.ObjAt(st, "artifacts").A {
		if validation.ObjStr(row, "kind") != "harness" {
			continue
		}
		if _, err := c.PruneArtifact(validation.ObjStr(row, "artifact_id"),
			"r32b repro: prune the pinned report row"); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(c.ArtifactsDir, "reports")); err != nil {
		t.Fatal(err)
	}
	zzR32bDropKey(t, c, "INV-1", "report_sha256")

	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	zzR32bAssertBurned(t, code, ok, joined, runs, "no report_sha256")
}

// TestZZR32bBlankedFieldBurns is F3's repro: one empty string in the slot.
// Before the fix harnessRunLine returned ok=false and BOTH backing checks
// lived inside that branch, so the invariant simply vanished from
// harness_runs with NO problem ("audit PASS"). Only a rung-less slot may be
// skipped silently; a stated rung with a blank required field must burn,
// naming the field.
func TestZZR32bBlankedFieldBurns(t *testing.T) {
	cases := []struct {
		field string
		want  string
	}{
		{"exec", "exec"},
		{"kind", "kind"},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			c, root := mcCamp(t, "r32b-f3-blank-"+tc.field)
			zzR32bBindHonest(t, root, c, "p1", zzR32bBody("p1", true,
				`[]`, `[]`))
			zzR32bHonestControl(t, root, c)

			// The auditor's mutation: the slot AND the event lose the field.
			zzR32bSetSlotField(t, c, tc.field, "")
			zzR32bRepinLast(t, c, "INV-1", tc.field, validation.VStr(""))

			code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
			zzR32bAssertBurned(t, code, ok, joined, runs, tc.want)
		})
	}
}

// TestZZR32bRungLessSlotStaysSilent is the sanctioned skip: a slot that
// states NO rung is not a run this section can read, so it must not burn an
// otherwise honest campaign. (The rung is the claim; without it there is
// nothing to back.)
func TestZZR32bRungLessSlotStaysSilent(t *testing.T) {
	c, root := mcCamp(t, "r32b-f3-no-rung")
	zzR32bBindHonest(t, root, c, "p1", zzR32bBody("p1", true, `[]`, `[]`))
	zzR32bSetSlotField(t, c, "rung", "")
	zzR32bRepinLast(t, c, "INV-1", "rung", validation.VStr(""))

	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	if code != 0 || !ok {
		t.Fatalf("a rung-less slot must be skipped, not burned: exit %d "+
			"ok=%v problems=%q runs=%s", code, ok, joined,
			validation.CanonCompact(runs))
	}
	if runs.Kind == validation.Arr && len(runs.A) != 0 {
		t.Fatalf("a rung-less slot must contribute no line: %s",
			validation.CanonCompact(runs))
	}
}
