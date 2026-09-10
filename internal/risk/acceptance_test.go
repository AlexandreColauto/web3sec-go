package risk

// acceptance_test.go: the A3 deterministic acceptance score. Pinned by
// exact weights (a weight drift would silently re-rank every campaign),
// monotonicity (adding proof must never demote), the disqualification
// semantics, and the ranking/cap invariants report and rank both rely on.

import (
	"testing"

	"websec/internal/validation"
)

// accKV/accObj are the test-local builders (the package's kv is unexported
// to other packages, but this test lives here — reuse the real ones).
func accFinding(mutate func(*validation.Value)) validation.Value {
	f := validation.VObj(
		kvR("finding_id", validation.VStr("F-a1")),
		kvR("title", validation.VStr("t")),
		kvR("evidence", validation.VArr()),
	)
	v := &f
	mutate(v)
	return f
}

func kvR(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// withRisk appends a risk sub-object field (validated band / reversibility).
func setBand(f *validation.Value, band string) {
	validated := validation.VObj(
		kvR("score", validation.VFloat(7.5)),
		kvR("band", validation.VStr(band)),
	)
	*f = withKeyR(*f, "risk", validation.VObj(kvR("validated", validated)))
}

func setReversibility(f *validation.Value, rv string) {
	riskObj := orObj(objAt(*f, "risk"))
	riskObj.O = setOrAppendR(riskObj.O, "reversibility", validation.VStr(rv))
	(*f).O = setOrAppendR((*f).O, "risk", riskObj)
}

func setEvidence(f *validation.Value, level string) {
	*f = withKeyR(*f, "evidence", validation.VArr(validation.VObj(
		kvR("evidence_id", validation.VStr("EV-1")),
		kvR("level", validation.VStr(level)),
		kvR("type", validation.VStr("manual")),
		kvR("description", validation.VStr("test evidence")))))
}

func setCritic(f *validation.Value, verdict string) {
	*f = withKeyR(*f, "verification", validation.VObj(
		kvR("critic_verdict", validation.VStr(verdict))))
}

func setAck(f *validation.Value) {
	*f = withKeyR(*f, "dedup_meta", validation.VObj(
		kvR("in_code_ack", validation.VObj(
			kvR("file", validation.VStr("src/V.sol")),
			kvR("line", validation.VInt(42)),
			kvR("phrase", validation.VStr("todo")),
			kvR("window", validation.VStr("12")),
		))))
}

func setAcceptedRisk(f *validation.Value) {
	*f = withKeyR(*f, "bounty", validation.VObj(
		kvR("accepted_risk", validation.VObj(
			kvR("pattern", validation.VStr("reentrancy")),
			kvR("kind", validation.VStr("accepted-risk")),
		))))
}

func withKeyR(f validation.Value, key string, v validation.Value) validation.Value {
	f.O = setOrAppendR(f.O, key, v)
	return f
}

func setOrAppendR(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, validation.KV{K: key, V: v})
}

func TestAcceptanceExactWeights(t *testing.T) {
	// Every component at once: critical 3.0 + E5 2.5 + confirmed 1.5
	// + irreversible 1.0 = 8.0, no demotions.
	f := accFinding(func(v *validation.Value) {
		setBand(v, "critical")
		setEvidence(v, "E5")
		setCritic(v, "confirmed")
		setReversibility(v, "irreversible")
	})
	s, dq := AcceptanceScore(f)
	if dq {
		t.Fatal("confirmed must not disqualify")
	}
	if s != 3.0+2.5+1.5+1.0 {
		t.Fatalf("score = %v, want 8.0", s)
	}
}

func TestAcceptanceDemotions(t *testing.T) {
	base := func() (validation.Value, float64) {
		f := accFinding(func(v *validation.Value) {
			setBand(v, "high")   // 2.0
			setEvidence(v, "E4") // 2.0
		})
		return f, 4.0
	}
	f, want := base()
	if s, _ := AcceptanceScore(f); s != want {
		t.Fatalf("base = %v, want %v", s, want)
	}
	setAck(&f)
	if s, dq := AcceptanceScore(f); s != want-1.0 || dq {
		t.Fatalf("ack = %v, want %v", s, want-1.0)
	}
	setAcceptedRisk(&f)
	if s, _ := AcceptanceScore(f); s != want-3.0 {
		t.Fatalf("ack+risk = %v, want %v", s, want-3.0)
	}
}

func TestAcceptanceClampsAtZero(t *testing.T) {
	// disproved (-2.0) on a bare finding (0) must clamp at 0 and disqualify.
	f := accFinding(func(v *validation.Value) {
		setCritic(v, "disproved")
	})
	s, dq := AcceptanceScore(f)
	if s != 0 || !dq {
		t.Fatalf("score=%v dq=%v, want 0/true", s, dq)
	}
}

// TestAcceptanceCriticVocabulary pins the score to the REAL critic_verdict
// enum (the finding schema is the vocabulary oracle): confirmed is the only
// positive, disproved the only active refutation (and the only
// disqualification), every other recorded verdict is worth exactly 0 and
// never disqualifies.
func TestAcceptanceCriticVocabulary(t *testing.T) {
	for _, verdict := range []string{"pending", "possible",
		"informational", "duplicate", "out_of_scope"} {
		f := accFinding(func(v *validation.Value) {
			setBand(v, "high")
			setCritic(v, verdict)
		})
		if s, dq := AcceptanceScore(f); s != 2.0 || dq {
			t.Fatalf("%s: score=%v dq=%v, want 2.0/false", verdict, s, dq)
		}
	}
	f := accFinding(func(v *validation.Value) {
		setBand(v, "high")
		setCritic(v, "confirmed")
	})
	if s, dq := AcceptanceScore(f); s != 3.5 || dq {
		t.Fatalf("confirmed: score=%v dq=%v, want 3.5/false", s, dq)
	}
}

func TestAcceptanceMonotonic(t *testing.T) {
	// adding proof must never demote: E0 < E4, confirmed raises, a
	// non-committal verdict (possible) holds, demotions lower.
	mk := func(evidence, critic string, demote bool) float64 {
		f := accFinding(func(v *validation.Value) {
			setBand(v, "high")
			if evidence != "" {
				setEvidence(v, evidence)
			}
			if critic != "" {
				setCritic(v, critic)
			}
			if demote {
				setAck(v)
			}
		})
		s, _ := AcceptanceScore(f)
		return s
	}
	s0 := mk("", "", false)
	s1 := mk("E4", "", false)
	s2 := mk("E4", "confirmed", false)
	s3 := mk("E4", "possible", false)
	s4 := mk("E4", "confirmed", true)
	if !(s0 < s1 && s1 < s2 && s1 == s3 && s2 > s4) {
		t.Fatalf("monotonicity violated: %v %v %v %v %v",
			s0, s1, s2, s3, s4)
	}
}

func TestAcceptanceBareFindingIsZero(t *testing.T) {
	f := accFinding(func(v *validation.Value) {})
	s, dq := AcceptanceScore(f)
	if s != 0 || dq {
		t.Fatalf("bare = %v/%v, want 0/false", s, dq)
	}
}

func TestAcceptanceRankingOrder(t *testing.T) {
	hi := accFinding(func(v *validation.Value) {
		v.O = setOrAppendR(v.O, "finding_id", validation.VStr("F-hi"))
		setBand(v, "critical")
		setEvidence(v, "E7")
	})
	lo := accFinding(func(v *validation.Value) {
		v.O = setOrAppendR(v.O, "finding_id", validation.VStr("F-lo"))
		setBand(v, "low")
	})
	dq := accFinding(func(v *validation.Value) {
		v.O = setOrAppendR(v.O, "finding_id", validation.VStr("F-dq"))
		setBand(v, "critical") // highest band, but disproved
		setCritic(v, "disproved")
	})
	got := AcceptanceRanking([]validation.Value{lo, dq, hi}, "acceptance")
	if len(got) != 3 || idR(got[0]) != "F-hi" || !got[2].Disqualified {
		t.Fatalf("order = %v", idsR(got))
	}
	// severity key: same order here (critical first), and dq still last
	got = AcceptanceRanking([]validation.Value{hi, dq, lo}, "severity")
	if idR(got[0]) != "F-hi" || !got[2].Disqualified {
		t.Fatalf("severity order = %v", idsR(got))
	}
}

func TestAcceptanceRankingTieBreak(t *testing.T) {
	a := accFinding(func(v *validation.Value) {
		v.O = setOrAppendR(v.O, "finding_id", validation.VStr("F-aa"))
		setBand(v, "high")
	})
	b := accFinding(func(v *validation.Value) {
		v.O = setOrAppendR(v.O, "finding_id", validation.VStr("F-bb"))
		setBand(v, "high")
	})
	got := AcceptanceRanking([]validation.Value{b, a}, "acceptance")
	if idR(got[0]) != "F-aa" {
		t.Fatalf("tie must break by id: %v", idsR(got))
	}
}

func TestAcceptanceTopKCap(t *testing.T) {
	var fs []validation.Value
	for i := 0; i < 12; i++ {
		fs = append(fs, accFinding(func(v *validation.Value) {
			v.O = setOrAppendR(v.O, "finding_id", validation.VStr(
				"F-x"+string(rune('0'+i%10))+string(rune('a'+i/10))))
			setBand(v, "medium")
		}))
	}
	got, capped := AcceptanceTopK(AcceptanceRanking(fs, "acceptance"), 5)
	if len(got) != 5 || !capped {
		t.Fatalf("cap: got %d capped=%v, want 5/true", len(got), capped)
	}
	got, capped = AcceptanceTopK(AcceptanceRanking(fs, "acceptance"), 20)
	if len(got) != 12 || capped {
		t.Fatalf("uncapped: got %d capped=%v, want 12/false", len(got), capped)
	}
	// default K when 0
	got, capped = AcceptanceTopK(AcceptanceRanking(fs, "acceptance"), 0)
	if len(got) != 10 || !capped {
		t.Fatalf("default: got %d capped=%v, want 10/true", len(got), capped)
	}
}

func TestCorroborationBonus(t *testing.T) {
	base := accFinding(func(f *validation.Value) {
		setCritic(f, "confirmed")
	})
	s0, _ := AcceptanceScore(base)
	withCorr := accFinding(func(f *validation.Value) {
		setCritic(f, "confirmed")
		*f = withKeyR(*f, "dedup_meta", validation.VObj(
			kvR("corroborated_by", validation.VStr("F-9"))))
	})
	s1, _ := AcceptanceScore(withCorr)
	if s1-s0 != 0.5 {
		t.Fatalf("corroboration must add exactly 0.5: %v -> %v", s0, s1)
	}
	// non-string garbage never fires (schema prevents it; the score is still
	// the last line of defense):
	junk := accFinding(func(f *validation.Value) {
		setCritic(f, "confirmed")
		*f = withKeyR(*f, "dedup_meta", validation.VObj(
			kvR("corroborated_by", validation.VBool(true))))
	})
	if s, _ := AcceptanceScore(junk); s != s0 {
		t.Fatal("only a string corroborated_by counts")
	}
}

func idsR(got []AcceptanceEntry) []string {
	out := []string{}
	for _, e := range got {
		out = append(out, orStr(objAt(e.Finding, "finding_id")))
	}
	return out
}

func idR(e AcceptanceEntry) string { return orStr(objAt(e.Finding, "finding_id")) }
