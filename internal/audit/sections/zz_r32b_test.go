package sections

// zz_r32b_test.go — section 11, rung-level unit repro for r32b F1/F2/F3.
//
// These drive InvariantVerification directly (no CLI) over a campaign that
// holds a REAL registered report artifact and the slot+event pair a report
// bind writes. Each test moves exactly one thing the finding names and
// asserts on section 11's OWN problems — before the fix every one of them
// rendered ok=true with an unqualified blessing.
//
// The end-to-end bind-vs-audit pairs (bind stdout pinned, then the campaign
// forged through its own writers) live in internal/cli/zz_r32b_test.go.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// zzR32bBody is reports/report.json with the fields the five gates read
// exposed as parameters.
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

// zzR32bRegister writes body as a harness artifact inside the campaign (the
// same content-addressed shape cli.storeReportCopy publishes) and returns
// its sha256.
func zzR32bRegister(t *testing.T, c *state.Campaign, body string) string {
	t.Helper()
	dir := filepath.Join(c.ArtifactsDir, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := []byte(body)
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])
	p := filepath.Join(dir, "report-"+sha+".json")
	if err := os.WriteFile(p, raw, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterOrRefresh("harness", p, "r32b fixture", nil,
		"r32b fixture"); err != nil {
		t.Fatal(err)
	}
	return sha
}

// zzR32bSlot is the verification.harness object a report bind writes for a
// proved-bounded rung (MapReport's own summary text).
func zzR32bSlot(sha string) validation.Value {
	return validation.VObj(
		KV("kind", validation.VStr("miniprover")),
		KV("rung", validation.VStr(harness.RungProvedBounded)),
		KV("exec", validation.VStr("REPORT-"+sha[:12])),
		KV("bounded_k", validation.VInt(4)),
		KV("summary",
			validation.VStr("autoproved bounded (k=4, 1 rules)")),
		KV("proof", validation.VNull()),
	)
}

// zzR32bEvent lands the harness_run event the bind writes for that slot.
func zzR32bEvent(t *testing.T, c *state.Campaign, iid string,
	h validation.Value, sha, prop string) {
	t.Helper()
	dig := sha256.Sum256([]byte(validation.CanonCompact(
		objAt(h, "proof"))))
	data := validation.VObj(
		KV("kind", validation.VStr(objStr(h, "kind"))),
		KV("rung", validation.VStr(objStr(h, "rung"))),
		KV("exec", validation.VStr(objStr(h, "exec"))),
		KV("invariant", validation.VStr(iid)),
		KV("summary", validation.VStr(objStr(h, "summary"))),
		KV("bounded_k", objAt(h, "bounded_k")),
		KV("proof_sha256", validation.VStr(hexText(dig))),
		KV("report_sha256", validation.VStr(sha)),
		KV("property", validation.VStr(prop)),
		KV("review_independent", validation.VBool(true)),
	)
	ref := iid
	if _, err := c.Log("harness_run", &ref, &data); err != nil {
		t.Fatal(err)
	}
}

// zzR32bDropEventKey lands a copy of the LAST harness_run event for iid with
// one key REMOVED (F2's mutation is absence, not a different value).
func zzR32bDropEventKey(t *testing.T, c *state.Campaign, iid, key string) {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := validation.VNull()
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		if objStr(objAt(ev, "data"), "invariant") == iid {
			last = objAt(ev, "data")
		}
	}
	if last.Kind != validation.Obj {
		t.Fatalf("no harness_run event for %s", iid)
	}
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
	ref := iid
	if _, lerr := c.Log("harness_run", &ref, &forged); lerr != nil {
		t.Fatal(lerr)
	}
}

// zzR32bCampaign is a campaign holding INV-3 with a report-bound blessing:
// a registered report artifact (the pinned bytes), the slot, and the
// matching event (report_sha256 pinned to the artifact's digest).
func zzR32bCampaign(t *testing.T, body, prop string) (*state.Campaign,
	validation.Value, string) {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	harnessLinks(t, c, nil) // seeds INV-3 and INV-4, no harness field
	sha := zzR32bRegister(t, c, body)
	h := zzR32bSlot(sha)
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	e := objAt(reg, "INV-3")
	e.O = validation.SetOrAppend(e.O, "verification",
		validation.VObj(KV("harness", h)))
	reg.O = validation.SetOrAppend(reg.O, "INV-3", e)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	zzR32bEvent(t, c, "INV-3", h, sha, prop)
	return c, h, sha
}

func zzR32bProblems(v validation.Value) string {
	joined := ""
	for _, p := range objAt(v, "problems").A {
		joined += p.S
	}
	return joined
}

// zzR32bWantBurn asserts section 11 burned and named the gate/missing thing.
func zzR32bWantBurn(t *testing.T, v validation.Value, want string) {
	t.Helper()
	if objAt(v, "ok").B {
		t.Fatalf("section 11 must burn: %s", validation.CanonCompact(v))
	}
	joined := zzR32bProblems(v)
	if !strings.Contains(joined, want) {
		t.Fatalf("the burn must name %q, got %q", want, joined)
	}
	for _, r := range objAt(v, "harness_runs").A {
		if r.Kind == validation.Str && !strings.HasSuffix(r.S, " (UNBACKED)") {
			t.Fatalf("a burned rung must not print unqualified: %q", r.S)
		}
	}
}

// TestZZR32bPinnedReportSuspectBurns is F1's SUSPECT repro at the section
// level: the pinned report bytes re-derive the SAME rung the event claims
// and differ only by a SUSPECT finding. The bind refuses those bytes; the
// audit used to bless them.
func TestZZR32bPinnedReportSuspectBurns(t *testing.T) {
	body := zzR32bBody("p1", true, `[]`,
		`[{"property": "p1", "verdict": "SUSPECT", `+
			`"reason": "rule is vacuous: it can never fail"}]`)
	c, _, _ := zzR32bCampaign(t, body, "p1")
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	zzR32bWantBurn(t, v, "SUSPECT")
}

// TestZZR32bPinnedReportUnpublishedBurns is F1's published:false repro: the
// prover's own veto list and the not-published flag are bind gates that
// MapReport cannot see, so only a re-derivation of the gates can refuse.
func TestZZR32bPinnedReportUnpublishedBurns(t *testing.T) {
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
			body := zzR32bBody("p1", tc.pub, tc.problems, `[]`)
			c, _, _ := zzR32bCampaign(t, body, "p1")
			v, err := InvariantVerification(c)
			if err != nil {
				t.Fatal(err)
			}
			zzR32bWantBurn(t, v, tc.want)
		})
	}
}

// TestZZR32bPinnedReportAbsentPinBurns is F2 at the section level: the
// registry row and the bytes stay exactly where they were, and only the
// event's report_sha256 is gone. Absence of the pin is not a licence to
// skip the rail — the burn must name the absent pin.
func TestZZR32bPinnedReportAbsentPinBurns(t *testing.T) {
	c, _, sha := zzR32bCampaign(t, zzR32bBody("p1", true, `[]`, `[]`),
		"p1")
	if sha == "" {
		t.Fatal("fixture drift: no digest")
	}
	// The row and the bytes stay exactly where they were: only the event's
	// report_sha256 is GONE (absent, not empty).
	zzR32bDropEventKey(t, c, "INV-3", "report_sha256")
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	zzR32bWantBurn(t, v, "no report_sha256")
}

// TestZZR32bPinnedReportFoldEqualNameBurns is F1's lookup half: the event
// names "P1" for a report keyed "p1". The bind's lookup is EXACT-only (it
// refuses with "is not in this run ... exact-match only"), so the audit's
// fold fallback re-derived a mapping the bind could never have made.
func TestZZR32bPinnedReportFoldEqualNameBurns(t *testing.T) {
	c, _, _ := zzR32bCampaign(t, zzR32bBody("p1", true, `[]`, `[]`),
		"P1")
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	zzR32bWantBurn(t, v, "P1")
}

// TestZZR32bHonestPinnedReportStaysGreen is F1's control: a report whose
// review ran and left a NON-suspect finding binds and audits exactly as
// before — no churn on the honest path.
func TestZZR32bHonestPinnedReportStaysGreen(t *testing.T) {
	body := zzR32bBody("p1", true, `[]`,
		`[{"property": "p1", "verdict": "ok", `+
			`"reason": "no issues found"}]`)
	c, h, _ := zzR32bCampaign(t, body, "p1")
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(v, "ok").B {
		t.Fatalf("an honest pinned report must stay green: %s",
			validation.CanonCompact(v))
	}
	runs := objAt(v, "harness_runs")
	if runs.Kind != validation.Arr || len(runs.A) != 1 ||
		runs.A[0].S != "INV-3: PROVEN-BOUNDED (miniprover, k=4, "+
			objStr(h, "exec")+")" {
		t.Fatalf("honest line = %s", validation.CanonCompact(runs))
	}
	if s := validation.CanonCompact(v); strings.Contains(s, "UNBACKED") {
		t.Fatalf("no qualifier on the backed path: %s", s)
	}
}

// TestZZR32bBlankSlotFieldBurnsNamingIt is F3 at the section level: a slot
// that STATES a rung while kind or exec is blank must burn those bytes,
// naming the field. Before the fix harnessRunLine returned ok=false and the
// whole invariant vanished with no line and no problem.
func TestZZR32bBlankSlotFieldBurnsNamingIt(t *testing.T) {
	for _, field := range []string{"exec", "kind"} {
		t.Run(field, func(t *testing.T) {
			c, _, _ := zzR32bCampaign(t,
				zzR32bBody("p1", true, `[]`, `[]`), "p1")
			// Honest control first: the untouched slot is green.
			if v, err := InvariantVerification(c); err != nil {
				t.Fatal(err)
			} else if !objAt(v, "ok").B {
				t.Fatalf("control must be green: %s",
					validation.CanonCompact(v))
			}
			zzR32bBlankSlot(t, c, "INV-3", field)
			v, err := InvariantVerification(c)
			if err != nil {
				t.Fatal(err)
			}
			zzR32bWantBurn(t, v, field)
		})
	}
}

// TestZZR32bNoRungSlotStaysSilent is the sanctioned skip: without a rung
// there is no claim to back, so the entry contributes no line and no
// problem. (Every other required-field blank must burn.)
func TestZZR32bNoRungSlotStaysSilent(t *testing.T) {
	c, _, _ := zzR32bCampaign(t, zzR32bBody("p1", true, `[]`, `[]`),
		"p1")
	zzR32bBlankSlot(t, c, "INV-3", "rung")
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(v, "ok").B {
		t.Fatalf("a rung-less slot must not burn: %s",
			validation.CanonCompact(v))
	}
	if runs := objAt(v, "harness_runs"); runs.Kind == validation.Arr &&
		len(runs.A) != 0 {
		t.Fatalf("a rung-less slot must contribute no line: %s",
			validation.CanonCompact(runs))
	}
}

// zzR32bSetEventKey lands a copy of the LAST harness_run event for iid with
// one key REPLACED (the stored slot is left alone) — the shape F3's adjacent
// arm needs: the slot keeps the field, the event loses it.
func zzR32bSetEventKey(t *testing.T, c *state.Campaign, iid, key string,
	v validation.Value) {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := validation.VNull()
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		if objStr(objAt(ev, "data"), "invariant") == iid {
			last = objAt(ev, "data")
		}
	}
	if last.Kind != validation.Obj {
		t.Fatalf("no harness_run event for %s", iid)
	}
	forged := last
	forged.O = validation.SetOrAppend(forged.O, key, v)
	ref := iid
	if _, lerr := c.Log("harness_run", &ref, &forged); lerr != nil {
		t.Fatal(lerr)
	}
}

// TestZZR32bEventKindBlankBurns is F3's adjacent arm: the SLOT states the
// kind (so a line renders and both backing checks do run) while the last
// harness_run event carries NO kind. The kind is the provenance the display
// prints and what selects the mapper, so an event without it backs nothing —
// and harnessRungBacked's `want == "" || got == ""` skip used to read that
// blank as "nothing to compare". Same field-level-blank class as F3, closed
// with it.
func TestZZR32bEventKindBlankBurns(t *testing.T) {
	c, _, _ := zzR32bCampaign(t, zzR32bBody("p1", true, `[]`, `[]`), "p1")
	zzR32bSetEventKey(t, c, "INV-3", "kind", validation.VStr(""))
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	zzR32bWantBurn(t, v, "names no kind")
}

// zzR32bBlankSlot rewrites one field of INV-<id>'s stored
// verification.harness to the empty string.
func zzR32bBlankSlot(t *testing.T, c *state.Campaign, iid, field string) {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	e := objAt(reg, iid)
	ver := objAt(e, "verification")
	h := objAt(ver, "harness")
	if h.Kind != validation.Obj {
		t.Fatal("no verification.harness to edit")
	}
	h.O = validation.SetOrAppend(h.O, field, validation.VStr(""))
	ver.O = validation.SetOrAppend(ver.O, "harness", h)
	e.O = validation.SetOrAppend(e.O, "verification", ver)
	reg.O = validation.SetOrAppend(reg.O, iid, e)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
}
