package sections

// zz_r33_test.go — section 11, round 33: the four rails the audit never
// re-derived, at the section level (no CLI).
//
//	F2  ONE PROOF, TWO ROWS. The bind refuses a second invariant claiming a
//	    property an earlier event already holds (cli.verifyAutoprove's
//	    autoprovePropertyHolder keys on the folded property title alone).
//	    Section 11 had no such rail, so a chain-valid campaign whose INV-4
//	    slot+event simply copies INV-3's proven report pair rendered TWO
//	    blessing lines over ONE proof. The rail here keys on the same folded
//	    property and burns the LATER row, naming the row that bound it first.
//	F3  THE schema_version GATE. The verb refuses a report whose
//	    schema_version is not 1.x (and one that has none); section 11 pinned
//	    such a report happily. Now the gate IS the shared decision
//	    (harness.DecideReportSchema, DecideReport's first gate) and the burn
//	    names the state.
//	F4  EXEC PROVENANCE. (a) a label the exec ledger does not hold, (b) a
//	    REPORT-<digest12> label that does not name the pinned bytes.
//	F5  A REPORT RUNG WEARING AN EXEC KIND: a REPORT- provenance whose kind
//	    is halmos/forge-fuzz/minicertora names a captured stdout no mapper
//	    read.
//
// Every mutation below moves exactly ONE thing away from a real report bind
// (the fixture shape of zz_r32b_test.go), and each finding has its honest
// control next to it: the bytes that a bind could have written must stay
// green, including the first claimant of a collided pair.

import (
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// r33Body is reports/report.json keyed by one or more property titles, each
// PROVEN over the single rule inv_1 (so the binding's MapReport summary is
// "autoproved bounded (k=4, 1 rules)" whatever the title).
func r33Body(props ...string) string {
	var b strings.Builder
	b.WriteString(`{"schema_version": "1.0", "published": true, ` +
		`"publish_problems": [], "review_independent": true, ` +
		`"capabilities_missing": [], ` +
		`"flags": {"loop_bound": 4, "path_cap": 64, "timeout_ms": 30000}, ` +
		`"property_outcomes": {`)
	for i, p := range props {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(`"` + p + `": {"outcome": "PROVEN", ` +
			`"per_rule": {"inv_1": "PROVEN"}}`)
	}
	b.WriteString(`}, "review_findings": []}` + "\n")
	return b.String()
}

// r33Rewire points iid's stored slot and its LAST harness_run event at the
// pinned report, naming prop — the exact (slot, event) pair a report bind
// writes for one invariant, built through the campaign's own writers so the
// chain and the display/ledger backstop stay valid. Only the fields the
// caller then mutates are non-bind-shaped.
func r33Rewire(t *testing.T, c *state.Campaign, iid, sha, prop, kind,
	exec string) validation.Value {
	t.Helper()
	h := validation.VObj(
		KV("kind", validation.VStr(kind)),
		KV("rung", validation.VStr(harness.RungProvedBounded)),
		KV("exec", validation.VStr(exec)),
		KV("bounded_k", validation.VInt(4)),
		KV("summary",
			validation.VStr("autoproved bounded (k=4, 1 rules)")),
		KV("proof", validation.VNull()),
	)
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := validation.ObjAt(links, "invariants")
	e := validation.ObjAt(reg, iid)
	if e.Kind != validation.Obj {
		t.Fatalf("fixture: no %s in links", iid)
	}
	e.O = validation.SetOrAppend(e.O, "verification",
		validation.VObj(KV("harness", h)))
	reg.O = validation.SetOrAppend(reg.O, iid, e)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	zzR32bEvent(t, c, iid, h, sha, prop)
	return h
}

// r33Problems joins section 11's problem texts.
func r33Problems(v validation.Value) string {
	return zzR32bProblems(v)
}

// r33Runs joins the rendered harness_runs lines.
func r33Runs(v validation.Value) string {
	out := ""
	for _, r := range validation.ObjAt(v, "harness_runs").A {
		if r.Kind == validation.Str {
			out += r.S + "\n"
		}
	}
	return out
}

// r33LineFor is the rendered line for iid ("" when the invariant renders
// none).
func r33LineFor(v validation.Value, iid string) string {
	for _, r := range validation.ObjAt(v, "harness_runs").A {
		if r.Kind == validation.Str && strings.HasPrefix(r.S, iid+":") {
			return r.S
		}
	}
	return ""
}

// r33Audit runs section 11 over the campaign.
func r33Audit(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// r33WantBurn asserts the section refused, naming every fragment, and that
// the NAMED line (only) is qualified UNBACKED — the first claimant of a
// collided pair must keep its unqualified blessing.
func r33WantBurn(t *testing.T, v validation.Value, unbackedIID string,
	frags ...string) {
	t.Helper()
	if validation.ObjAt(v, "ok").B {
		t.Fatalf("section 11 must burn: %s", validation.CanonCompact(v))
	}
	joined := r33Problems(v)
	for _, frag := range frags {
		if !strings.Contains(joined, frag) {
			t.Fatalf("the burn must name %q, got %q", frag, joined)
		}
	}
	if unbackedIID == "" {
		return
	}
	if line := r33LineFor(v, unbackedIID); !strings.HasSuffix(line,
		" (UNBACKED)") {
		t.Fatalf("%s's line must be qualified UNBACKED: %q",
			unbackedIID, line)
	}
}

// TestR33ReportDuplicateRowBurns is F2's plain repro: INV-4's slot and event
// are a byte-for-byte copy of INV-3's proven report pair (same pin, same
// property, same rung/summary/bound). Re-binding those bytes for INV-4 exits
// 2 at the verb ("property p1 was already bound to INV-3 … one property's
// proof binds one invariant"); before this rail section 11 printed TWO
// unqualified blessing lines and exited 0.
func TestR33ReportDuplicateRowBurns(t *testing.T) {
	c, _, sha := zzR32bCampaign(t, r33Body("p1"), "p1")
	if v := r33Audit(t, c); !validation.ObjAt(v, "ok").B {
		t.Fatalf("control: the honest single row must be green: %s",
			validation.CanonCompact(v))
	}
	honest := r33LineFor(r33Audit(t, c), "INV-3")
	if !strings.Contains(honest, "INV-3: PROVEN-BOUNDED (miniprover") ||
		strings.Contains(honest, "UNBACKED") {
		t.Fatalf("control line = %q", honest)
	}
	// The only thing wrong in the campaign: a second row claims the pair.
	r33Rewire(t, c, "INV-4", sha, "p1",
		string(harness.ReportKind), harness.ReportExecLabel(sha))

	v := r33Audit(t, c)
	r33WantBurn(t, v, "INV-4", "INV-4", "already bound to INV-3",
		"one property's proof binds one invariant")
	// The FIRST claimant keeps its rung, unqualified: only the later row is
	// the forged one.
	if line := r33LineFor(v, "INV-3"); strings.Contains(line, "UNBACKED") {
		t.Fatalf("the first claimant must keep its blessing: %q", line)
	}
}

// TestR33ReportFoldEqualDuplicateRowBurns is F2's fold-equal variant: the
// report carries BOTH "p1" and "P1" (so the later row's name resolves
// exactly and every other rail passes) and the two rows name different
// spellings of the same folded title. The bind's holder scan folds
// (harness.SamePropertyName), so this is the same collision; the audit must
// fold too.
func TestR33ReportFoldEqualDuplicateRowBurns(t *testing.T) {
	c, _, sha := zzR32bCampaign(t, r33Body("p1", "P1"), "p1")
	if v := r33Audit(t, c); !validation.ObjAt(v, "ok").B {
		t.Fatalf("control: one row is honest: %s",
			validation.CanonCompact(v))
	}
	r33Rewire(t, c, "INV-4", sha, "P1",
		string(harness.ReportKind), harness.ReportExecLabel(sha))
	v := r33Audit(t, c)
	r33WantBurn(t, v, "INV-4", "already bound to INV-3")
}

// TestR33ReportDuplicateControlsStayGreen is F2's honest-control half. The
// rail's KEY is the bind's key, so the controls are the shapes the bind's own
// holder scan accepts:
//
//   - two DIFFERENT properties from the same report are two proofs (a second
//     claim of p2 collides with nothing);
//   - the SAME invariant re-claiming its own property — a newer report for
//     the same title, the re-bind the verb discloses with a warning — is a
//     REFRESH, because the bind's holder scan returns the first holder and
//     refuses only a DIFFERENT one.
//
// The cross-pin case is deliberately NOT a control here: the bind refuses it
// (its scan reads the property and nothing else — measured at the verb in
// internal/cli/zz_r33_test.go), so the audit must burn it too, and
// TestR33CrossPinDuplicateBurns pins that.
func TestR33ReportDuplicateControlsStayGreen(t *testing.T) {
	t.Run("two properties from one report", func(t *testing.T) {
		c, _, sha := zzR32bCampaign(t, r33Body("p1", "p2"), "p1")
		r33Rewire(t, c, "INV-4", sha, "p2",
			string(harness.ReportKind), harness.ReportExecLabel(sha))
		v := r33Audit(t, c)
		if !validation.ObjAt(v, "ok").B {
			t.Fatalf("two properties of one report must both bless: %s",
				validation.CanonCompact(v))
		}
		runs := r33Runs(v)
		if !strings.Contains(runs, "INV-3: PROVEN-BOUNDED") ||
			!strings.Contains(runs, "INV-4: PROVEN-BOUNDED") {
			t.Fatalf("both rows must render: %q", runs)
		}
	})
	t.Run("the same invariant re-claims its own property", func(t *testing.T) {
		c, _, shaA := zzR32bCampaign(t, r33Body("p1"), "p1")
		// A newer report for the SAME property, bound to the SAME row.
		shaB := zzR32bRegister(t, c, strings.Replace(
			r33Body("p1"), `"path_cap": 64`, `"path_cap": 65`, 1))
		if shaB == shaA {
			t.Fatal("fixture drift: the two reports must differ")
		}
		r33Rewire(t, c, "INV-3", shaB, "p1",
			string(harness.ReportKind), harness.ReportExecLabel(shaB))
		v := r33Audit(t, c)
		if !validation.ObjAt(v, "ok").B {
			t.Fatalf("a refresh of one's own proof is not a collision: %s",
				validation.CanonCompact(v))
		}
	})
}

// TestR33CrossPinDuplicateBurns is the rail's KEY pin, and the reason the
// key is the property and not (pin, property): the bind's holder scan reads
// the property title ALONE, so "the same property over a different report"
// is still "already bound" at the verb (cli.zz_r33_test.go observes that
// refusal with its exact sentence). An audit keyed on the pin would bless
// exactly the duplicate attribution the bind refuses — F2's forgery with one
// byte of the report changed.
func TestR33CrossPinDuplicateBurns(t *testing.T) {
	c, _, shaA := zzR32bCampaign(t, r33Body("p1"), "p1")
	shaB := zzR32bRegister(t, c, strings.Replace(
		r33Body("p1"), `"path_cap": 64`, `"path_cap": 65`, 1))
	if shaB == shaA {
		t.Fatal("fixture drift: the two reports must differ")
	}
	r33Rewire(t, c, "INV-4", shaB, "p1",
		string(harness.ReportKind), harness.ReportExecLabel(shaB))
	v := r33Audit(t, c)
	r33WantBurn(t, v, "INV-4", "already bound to INV-3")
}

// TestR33PinnedReportSchemaStateBurns is F3: the pinned bytes carry a
// schema_version the verb refuses ("2.0") or no readable one at all, while
// the rung claims a miniprover blessing. The bind refuses those exact bytes
// with "report schema_version … is not understood"; the audit used to bless
// them because DecideReport never read the field.
func TestR33PinnedReportSchemaStateBurns(t *testing.T) {
	base := r33Body("p1")
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"2.0", strings.Replace(base, `"schema_version": "1.0", `,
			`"schema_version": "2.0", `, 1),
			[]string{"schema_version", "'2.0'", "is not understood"}},
		{"absent", strings.Replace(base, `"schema_version": "1.0", `,
			"", 1),
			[]string{"schema_version", "ABSENT (pre-1.0 report)"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.body == base {
				t.Fatal("fixture drift: the mutation did not apply")
			}
			c, _, _ := zzR32bCampaign(t, tc.body, "p1")
			v := r33Audit(t, c)
			r33WantBurn(t, v, "INV-3", append(tc.want,
				"a fresh bind of these very bytes is refused")...)
		})
	}
	// Controls: the 1.x family stays green, patch form included.
	for _, sv := range []string{"1.0", "1.0.3"} {
		t.Run("control "+sv, func(t *testing.T) {
			c, _, _ := zzR32bCampaign(t, strings.Replace(base,
				`"schema_version": "1.0"`, `"schema_version": "`+sv+`"`,
				1), "p1")
			if v := r33Audit(t, c); !validation.ObjAt(v, "ok").B {
				t.Fatalf("schema_version %s must bind and audit: %s", sv,
					validation.CanonCompact(v))
			}
		})
	}
}

// TestR33ReportExecProvenanceBurns is F4: the provenance LABEL is not
// re-derived. (a) an EXEC- id the ledger does not hold, (b) a REPORT- label
// whose digest prefix is not the pinned report's. Both rode to a green audit
// and printed themselves as the witness.
func TestR33ReportExecProvenanceBurns(t *testing.T) {
	t.Run("exec the ledger does not hold", func(t *testing.T) {
		c, _, sha := zzR32bCampaign(t, r33Body("p1"), "p1")
		const ghost = "EXEC-99999999-nope"
		r33Rewire(t, c, "INV-3", sha, "p1", string(harness.ReportKind),
			ghost)
		v := r33Audit(t, c)
		r33WantBurn(t, v, "INV-3", ghost,
			"which the exec ledger does not hold")
	})
	t.Run("label does not name the pinned bytes", func(t *testing.T) {
		c, _, sha := zzR32bCampaign(t, r33Body("p1"), "p1")
		r33Rewire(t, c, "INV-3", sha, "p1", string(harness.ReportKind),
			"REPORT-000000000000")
		v := r33Audit(t, c)
		r33WantBurn(t, v, "INV-3", "REPORT-000000000000", sha,
			harness.ReportExecLabel(sha))
	})
}

// TestR33ReportRungWearingAnExecKindBurns is F5: a REPORT- provenance whose
// kind is one of the exec-shaped kinds. The report bind writes
// harness.ReportKind on both the slot and the event, and the mapper exercised
// by that provenance is MapReport over the pinned bytes — a halmos claim is a
// captured stdout nothing read. The honest control (the bind's own kind)
// stays green in every other test in this file.
func TestR33ReportRungWearingAnExecKindBurns(t *testing.T) {
	for _, kind := range []string{"halmos", "forge-fuzz", "minicertora"} {
		t.Run(kind, func(t *testing.T) {
			c, _, sha := zzR32bCampaign(t, r33Body("p1"), "p1")
			r33Rewire(t, c, "INV-3", sha, "p1", kind,
				harness.ReportExecLabel(sha))
			v := r33Audit(t, c)
			r33WantBurn(t, v, "INV-3", kind,
				string(harness.ReportKind),
				"no mapper produced this pairing")
		})
	}
}

// TestR33HonestReportRungStaysGreen is the shared honest control for F3/F4/F5
// on the SECTION side: the byte shape a real report bind writes (kind
// miniprover, REPORT-<digest12>, 1.x schema, registered bytes) audits green
// with an unqualified line. Every rail above is a mutation OF this shape.
func TestR33HonestReportRungStaysGreen(t *testing.T) {
	c, h, _ := zzR32bCampaign(t, r33Body("p1"), "p1")
	v := r33Audit(t, c)
	if !validation.ObjAt(v, "ok").B {
		t.Fatalf("the honest report rung must stay green: %s",
			validation.CanonCompact(v))
	}
	want := "INV-3: PROVEN-BOUNDED (miniprover, k=4, " +
		validation.ObjStr(h, "exec") + ")"
	if got := r33LineFor(v, "INV-3"); got != want {
		t.Fatalf("honest line = %q, want %q", got, want)
	}
}
