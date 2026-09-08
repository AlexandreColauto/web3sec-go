// unpriceable_test.go ports tests/test_unpriceable_impact.py::
// test_audit_clean_after_decision_and_catches_a_hand_edit plus the two other
// drift shapes section 14 catches: a priceable=false the log never recorded,
// and a projection whose latest impact decision is a priced record.
package audit

import (
	"fmt"
	"testing"

	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

const (
	unpCeiling = "capacity basis: the sink is an address[255] test constant — " +
		"no live liquidity bounds it"
	unpReason = "the sink is a test fixture, so any USD figure would be " +
		"invented precision, not a measurement"
	unpActor = "operator"
)

// unpFinding ingests one hypothesis and returns its finding id.
func unpFinding(t *testing.T, c *state.Campaign) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		validation.KV{K: "title", V: validation.VStr(
			"Attacker skews the oracle and borrows unbacked funds")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("oracle-manipulation")},
			validation.KV{K: "description", V: validation.VStr(
				"the spot price read lets the attacker trade against its own quote")},
		)},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()},
		)},
	), "economic", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return objStr(f, "finding_id")
}

// unpSection returns the unpriceable section of an audit report.
func unpSection(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	return objAt(objAt(report, "sections"), "unpriceable")
}

// TestAuditUnpriceableCleanThenCatchesAHandEdit is the Python test: a
// recorded decision keeps the audit green; a priceable=false whose ceiling
// the log disagrees with is a hand-edited projection and fails it.
func TestAuditUnpriceableCleanThenCatchesAHandEdit(t *testing.T) {
	Setup()
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := initCampaign(t)
	fid := unpFinding(t, c)
	if _, err := risk.RecordUnpriceable(c, fid, unpCeiling, unpReason,
		unpActor); err != nil {
		t.Fatal(err)
	}
	sec := unpSection(t, c)
	if !objAt(sec, "ok").B {
		t.Fatalf("unpriceable section not ok: %s", validation.DumpIndented(sec))
	}
	if got := objAt(sec, "checked"); got.Kind != validation.Int || got.I != 1 {
		t.Errorf("checked = %v; want 1", got)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if !reportOK(report) {
		t.Fatalf("clean campaign flagged: %v", sectionOKFlags(report))
	}

	// a priceable=false the log never recorded is a hand-edited projection
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ii, err := objIndex(&f.O, "economic_impact")
	if err != nil {
		t.Fatal(err)
	}
	f.O[ii].V.O = setKey(f.O[ii].V.O, "ceiling",
		validation.VStr("a ceiling nobody recorded"))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	sec = unpSection(t, c)
	if objAt(sec, "ok").B {
		t.Fatalf("hand-edited ceiling not flagged: %s",
			validation.DumpIndented(sec))
	}
	want := "finding " + fid + " records ceiling " +
		validation.PyReprStr("a ceiling nobody recorded") +
		" but the log's last finding.unpriceable event cites " +
		validation.PyReprStr(unpCeiling) + " — projection drifted from the log"
	if got := unpProblems(t, sec); len(got) != 1 || got[0] != want {
		t.Errorf("problems = %v\nwant [%s]", got, want)
	}
	report, err = AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if reportOK(report) {
		t.Error("report still ok after the hand edit")
	}
}

// TestAuditUnpriceableCatchesADecisionWithNoEvent: a priceable=false the log
// never recorded at all — the state file hand-edited — is flagged as
// hand-edited, not as drift.
func TestAuditUnpriceableCatchesADecisionWithNoEvent(t *testing.T) {
	Setup()
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := initCampaign(t)
	fid := unpFinding(t, c)
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = append(f.O, validation.KV{K: "economic_impact", V: validation.VObj(
		validation.KV{K: "priceable", V: validation.VBool(false)},
		validation.KV{K: "ceiling", V: validation.VStr(unpCeiling)},
	)})
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	sec := unpSection(t, c)
	want := "finding " + fid + " records economic_impact.priceable=false " +
		"with no finding.unpriceable event — the decision was hand-edited"
	if got := unpProblems(t, sec); len(got) != 1 || got[0] != want {
		t.Errorf("problems = %v\nwant [%s]", got, want)
	}
}

// TestAuditUnpriceableCatchesAStaleProjection: the log's latest impact
// decision is a priced record, so a priceable=false beside it is drift.
func TestAuditUnpriceableCatchesAStaleProjection(t *testing.T) {
	Setup()
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := initCampaign(t)
	fid := unpFinding(t, c)
	if _, err := risk.RecordEconomicImpact(c, fid, validation.VInt(1000),
		validation.VNull(), validation.VNull()); err != nil {
		t.Fatal(err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ii, err := objIndex(&f.O, "economic_impact")
	if err != nil {
		t.Fatal(err)
	}
	f.O[ii].V.O = setKey(f.O[ii].V.O, "priceable", validation.VBool(false))
	f.O[ii].V.O = setKey(f.O[ii].V.O, "ceiling", validation.VStr(unpCeiling))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	sec := unpSection(t, c)
	want := "finding " + fid + " records economic_impact.priceable=false " +
		"but the log's latest impact decision is a priced " +
		"finding.impact_recorded — projection drifted from the log"
	if got := unpProblems(t, sec); len(got) != 1 || got[0] != want {
		t.Errorf("problems = %v\nwant [%s]", got, want)
	}
}

// unpProblems is the section's problems array as strings.
func unpProblems(t *testing.T, section validation.Value) []string {
	t.Helper()
	var out []string
	for _, p := range objAt(section, "problems").A {
		out = append(out, p.S)
	}
	return out
}

// objIndex is the object field's index (the test edits the finding in place,
// the way a hand edit would).
func objIndex(o *[]validation.KV, key string) (int, error) {
	for i := range *o {
		if (*o)[i].K == key {
			return i, nil
		}
	}
	return 0, fmt.Errorf("no field %s", key)
}

// setKey mirrors Python dict assignment on an ordered object.
func setKey(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, validation.KV{K: key, V: v})
}
