package risk

// IMPROVEMENTS E5 — the victim-perspective recoverability factor.
//
// The morph-campaign evidence: G-02 (onDropMessage safeTransfer-not-mint)
// scored 4.0 medium while the gold band is high, because the formula had no
// dimension for "the victim can never get their funds back". These tests pin
// the new weight, the rationale line, the byte-identical guarantee for
// findings that never classified recoverability, and the record/clear API.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

// TestValidatedRiskReversibilityVectors pins the weight table end to end on
// the G-02 shape: subset-of-users blast (3.0), E0 evidence (0.0),
// unprivileged attacker (+1.0) = 4.0 medium baseline, exactly the
// pre-E5 "defaults" vector.
func TestValidatedRiskReversibilityVectors(t *testing.T) {
	base := validation.VObj() // subset-of-users / E0 / unprivileged = 4.0
	cases := []struct {
		name string
		f    validation.Value
		want string
	}{
		{"absent-field-unchanged", base,
			`{"band": "medium", "rationale": "blast_radius(subset-of-users)=3.0; ` +
				`evidence(E0)=+0.0; unprivileged-attacker +1.0", "score": 4.0}`},
		{"irreversible",
			validation.VObj(kv("risk", validation.VObj(
				kv("reversibility", validation.VStr("irreversible"))))),
			`{"band": "high", "rationale": "blast_radius(subset-of-users)=3.0; ` +
				`evidence(E0)=+0.0; unprivileged-attacker +1.0; ` +
				`reversibility(irreversible) +3.0", "score": 7.0}`},
		{"trusted-party",
			validation.VObj(kv("risk", validation.VObj(
				kv("reversibility", validation.VStr("trusted-party"))))),
			`{"band": "medium", "rationale": "blast_radius(subset-of-users)=3.0; ` +
				`evidence(E0)=+0.0; unprivileged-attacker +1.0; ` +
				`reversibility(trusted-party) +2.0", "score": 6.0}`},
		{"reversible-explicit",
			validation.VObj(kv("risk", validation.VObj(
				kv("reversibility", validation.VStr("reversible"))))),
			`{"band": "medium", "rationale": "blast_radius(subset-of-users)=3.0; ` +
				`evidence(E0)=+0.0; unprivileged-attacker +1.0; ` +
				`reversibility(reversible) +0.0", "score": 4.0}`},
		{"unrecognized-value-never-silently-weights",
			validation.VObj(kv("risk", validation.VObj(
				kv("reversibility", validation.VStr("banana"))))),
			`{"band": "medium", "rationale": "blast_radius(subset-of-users)=3.0; ` +
				`evidence(E0)=+0.0; unprivileged-attacker +1.0; ` +
				`reversibility(banana) +0.0 (unrecognized)", "score": 4.0}`},
	}
	for _, c := range cases {
		got, err := ValidatedRisk(c.f)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if canon(t, got) != c.want {
			t.Errorf("%s: %s; want %s", c.name, canon(t, got), c.want)
		}
	}
}

// TestValidatedRiskG02Regression is the morph-campaign gold check: the
// onDropMessage finding's exact component breakdown must land in the high
// band once the victim-perspective irreversibility is classified.
func TestValidatedRiskG02Regression(t *testing.T) {
	f := validation.VObj(
		kv("economic_impact", validation.VObj(
			kv("blast_radius", validation.VStr("subset-of-users")))),
		kv("risk", validation.VObj(
			kv("reversibility", validation.VStr("irreversible")))),
	)
	got, err := ValidatedRisk(f)
	if err != nil {
		t.Fatal(err)
	}
	if band := validation.ObjAt(got, "band").S; band != "high" {
		t.Errorf("G-02 band = %q; want high", band)
	}
	if score := validation.ObjAt(got, "score").F; score < 6.5 {
		t.Errorf("G-02 score = %v; want >= 6.5", score)
	}
}

// TestRecordReversibility pins the API: classify → recalibrate → event →
// clear → recalibrate → event, with the stored field following the decision.
func TestRecordReversibility(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)

	out, err := RecordReversibility(c, fid, "irreversible")
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(out, "risk"), "reversibility"); got != "irreversible" {
		t.Errorf("stored reversibility = %q", got)
	}
	v := validation.ObjAt(validation.ObjAt(out, "risk"), "validated")
	if band := validation.ObjStr(v, "band"); band != "high" {
		t.Errorf("band = %q; want high (4.0 + 3.0)", band)
	}
	if score := validation.ObjAt(v, "score").F; score != 7.0 {
		t.Errorf("score = %v; want 7.0", score)
	}

	// The decision is an event, not a silent field mutation.
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var setEv, calEv int
	for _, e := range evs {
		switch validation.ObjStr(e, "type") {
		case "finding.reversibility_set":
			setEv++
			if validation.ObjStr(e, "ref") != fid {
				t.Errorf("set event ref = %q; want %q", validation.ObjStr(e, "ref"), fid)
			}
		case "finding.calibrated":
			calEv++
		}
	}
	if setEv != 1 || calEv != 1 {
		t.Errorf("events: reversibility_set=%d calibrated=%d; want 1/1",
			setEv, calEv)
	}

	// "none" clears the classification and the weight goes with it.
	out, err = RecordReversibility(c, fid, "none")
	if err != nil {
		t.Fatal(err)
	}
	if _, had := fieldAt(validation.ObjAt(out, "risk"), "reversibility"); had {
		t.Error("clear must pop the reversibility field")
	}
	if band := validation.ObjStr(validation.ObjAt(validation.ObjAt(out, "risk"), "validated"), "band"); band != "medium" {
		t.Errorf("band after clear = %q; want medium", band)
	}
}

// TestRecordReversibilityInvalid rejects values outside the closed set.
func TestRecordReversibilityInvalid(t *testing.T) {
	c := riskCamp(t)
	fid := ingest(t, c)
	_, err := RecordReversibility(c, fid, "unrecoverable-ish")
	if err == nil {
		t.Fatal("expected an error for an unknown mode")
	}
	if !strings.Contains(err.Error(), "reversibility must be one of") {
		t.Errorf("error = %q; want the closed-set message", err.Error())
	}
	// A failed call must leave the finding untouched.
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if _, had := fieldAt(validation.ObjAt(f, "risk"), "reversibility"); had {
		t.Error("failed record must not write the field")
	}
}
