package risk

// acceptance_test.go: the A3 deterministic acceptance score. Pinned by
// exact weights (a weight drift would silently re-rank every campaign),
// monotonicity (adding proof must never demote), the disqualification
// semantics, and the ranking/cap invariants report and rank both rely on.

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"websec/internal/findings"
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

// setMitigation records a T13-shape mitigation_present: a JSON-encoded
// STRING (dedup_meta is string-valued) built by the real MitigRecord so
// the fixture carries the production shape, not a hand-rolled guess. It
// MERGES into dedup_meta (setAck replaces the whole object, so a second
// withKeyR would wipe the ack — stacking fixtures need the merge).
func setMitigation(f *validation.Value) {
	dm := orObj(objAt(*f, "dedup_meta"))
	dm.O = setOrAppendR(dm.O, "mitigation_present",
		validation.VStr(findings.MitigRecord("cei-order", "src/Escrow.sol",
			23, "last write at L23 precedes call at L26")))
	(*f).O = setOrAppendR((*f).O, "dedup_meta", dm)
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

// TestAcceptanceMitigationDemotion pins the G5 soundness-layer demotion:
// a T13 mitigation_present record demotes exactly 1.0, sets the
// presence-pattern fields (MitigationDemoted + the pattern string), and
// never disqualifies. Garbage shapes (non-JSON, pattern-less JSON, a
// non-string value) must not move the score.
func TestAcceptanceMitigationDemotion(t *testing.T) {
	base := func() validation.Value {
		return accFinding(func(v *validation.Value) {
			setBand(v, "high")   // 2.0
			setEvidence(v, "E4") // 2.0
		})
	}
	if s, _ := AcceptanceScore(base()); s != 4.0 {
		t.Fatalf("base = %v, want 4.0", s)
	}
	f := base()
	setMitigation(&f)
	e := Acceptance(f)
	if e.Score != 3.0 {
		t.Fatalf("mitigation = %v, want 3.0", e.Score)
	}
	if e.Disqualified {
		t.Fatal("mitigation demotes; it never disqualifies")
	}
	if !e.MitigationDemoted || e.Mitigation != "cei-order" {
		t.Fatalf("fields = %v/%q, want true/cei-order",
			e.MitigationDemoted, e.Mitigation)
	}
	// stacking with the ack demotion: -1 (ack) -1 (mitigation).
	g := base()
	setAck(&g)
	setMitigation(&g)
	if s, _ := AcceptanceScore(g); s != 2.0 {
		t.Fatalf("ack+mitigation = %v, want 2.0", s)
	}
	// all three demotions on the full block: 4.0 -1 -2 -1 = 0.0 exactly.
	h := base()
	setAck(&h)
	setAcceptedRisk(&h)
	setMitigation(&h)
	he := Acceptance(h)
	if he.Score != 0.0 {
		t.Fatalf("ack+risk+mitigation = %v, want 0.0", he.Score)
	}
	if !he.AckDemoted || !he.RiskDemoted || !he.MitigationDemoted {
		t.Fatalf("all three flags must fire: %#v", he)
	}
	if he.Mitigation != "cei-order" {
		t.Fatalf("Mitigation = %q, want cei-order", he.Mitigation)
	}
	// garbage shapes never fire.
	for name, rec := range map[string]validation.Value{
		"non-json":   validation.VStr("not json at all"),
		"no-pattern": validation.VStr(`{"file":"src/Escrow.sol"}`),
		"non-string": validation.VObj(kvR("pattern",
			validation.VStr("cei-order"))),
	} {
		j := base()
		j = withKeyR(j, "dedup_meta", validation.VObj(
			kvR("mitigation_present", rec)))
		if je := Acceptance(j); je.Score != 4.0 || je.MitigationDemoted ||
			je.Mitigation != "" {
			t.Fatalf("%s: moved the entry: %#v", name, je)
		}
	}
}

// TestAcceptanceMitigationClampsAtZero pins the floor with demotions that
// overshoot: low (0.5) -1 (ack) -2 (risk) -1 (mitigation) clamps to 0
// with all three demotion fields visible.
func TestAcceptanceMitigationClampsAtZero(t *testing.T) {
	f := accFinding(func(v *validation.Value) {
		setBand(v, "low") // 0.5
	})
	setAck(&f)
	setAcceptedRisk(&f)
	setMitigation(&f)
	e := Acceptance(f)
	if e.Score != 0 {
		t.Fatalf("clamped = %v, want 0", e.Score)
	}
	if !e.AckDemoted || !e.RiskDemoted || !e.MitigationDemoted ||
		e.Mitigation != "cei-order" {
		t.Fatalf("clamped entry must show all three demotions: %#v", e)
	}
}

// TestAcceptanceEntryJSONOmitsMitigationWhenZero is the byte-law check:
// the default entry carries no mitigation keys in ANY rendering, and the
// keys ARE present with the right values when the term fires.
func TestAcceptanceEntryJSONOmitsMitigationWhenZero(t *testing.T) {
	raw, err := json.Marshal(Acceptance(priorFinding()))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"mitigation_demoted", "mitigation"} {
		if _, ok := m[k]; ok {
			t.Fatalf("demotion-free entry renders key %q: %s", k, raw)
		}
	}
	f := priorFinding()
	setMitigation(&f)
	raw, err = json.Marshal(Acceptance(f))
	if err != nil {
		t.Fatal(err)
	}
	m = nil
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["mitigation_demoted"] != true {
		t.Fatalf("fired entry missing mitigation_demoted: %s", raw)
	}
	if m["mitigation"] != "cei-order" {
		t.Fatalf("mitigation = %v, want cei-order: %s", m["mitigation"], raw)
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

func TestTriagerOutlookFactor(t *testing.T) {
	base := accFinding(func(f *validation.Value) { setCritic(f, "confirmed") })
	s0, _ := AcceptanceScore(base)
	setOutlook := func(f *validation.Value, outcome string) {
		*f = withKeyR(*f, "verification", validation.VObj(
			kvR("critic_verdict", validation.VStr("confirmed")),
			kvR("triager_outlook", validation.VObj(
				kvR("outcome", validation.VStr(outcome)),
				kvR("reason", validation.VStr("policy pays critical; fork PoC"))))))
	}
	likely := accFinding(func(f *validation.Value) { setOutlook(f, "likely") })
	unlikely := accFinding(func(f *validation.Value) { setOutlook(f, "unlikely") })
	uncertain := accFinding(func(f *validation.Value) { setOutlook(f, "uncertain") })
	if s, _ := AcceptanceScore(likely); s-s0 != 0.5 {
		t.Fatalf("likely: +%v", s-s0)
	}
	if s, _ := AcceptanceScore(unlikely); s0-s != 0.5 {
		t.Fatalf("unlikely: %v", s-s0)
	}
	if s, _ := AcceptanceScore(uncertain); s != s0 {
		t.Fatal("uncertain must be score-neutral")
	}
	// Outlook NEVER disqualifies:
	if _, d := AcceptanceScore(unlikely); d {
		t.Fatal("outlook is not a refutation")
	}
	// clamp at 0 still holds with unlikely on a bare hypothesis (no critic
	// verdict: setOutlook writes a confirmed critic, which would offset the
	// -0.5 and never reach the floor — the finding must be genuinely bare).
	bare := accFinding(func(f *validation.Value) {
		*f = withKeyR(*f, "verification", validation.VObj(
			kvR("triager_outlook", validation.VObj(
				kvR("outcome", validation.VStr("unlikely")),
				kvR("reason", validation.VStr("policy pays critical; fork PoC"))))))
	})
	if s, _ := AcceptanceScore(bare); s != 0 {
		t.Fatalf("clamped: %v", s)
	}
}

func TestOutlookEnumSync(t *testing.T) {
	// 1) score table keys == findings.TriagerOutlooks()
	for _, o := range findings.TriagerOutlooks() {
		if _, ok := wAcceptanceOutlook[o]; !ok {
			t.Fatalf("outlook %q missing from the score table", o)
		}
	}
	if len(wAcceptanceOutlook) != len(findings.TriagerOutlooks()) {
		t.Fatal("score table carries an outcome the enum does not")
	}
	// 2) the finding schema's enum == findings.TriagerOutlooks()
	raw, err := validation.ReadSchemaFile("finding")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	tout := objAt(objAt(objAt(objAt(objAt(doc, "properties"),
		"verification"), "properties"), "triager_outlook"), "properties")
	enums := objAt(objAt(tout, "outcome"), "enum").A
	var got []string
	for _, e := range enums {
		got = append(got, e.S)
	}
	if strings.Join(got, ",") != strings.Join(findings.TriagerOutlooks(), ",") {
		t.Fatalf("schema enum %v drifted from TriagerOutlooks() %v", got,
			findings.TriagerOutlooks())
	}
}

func TestCombinedFactors(t *testing.T) {
	// confirmed(+1.5) + critical band(+3.0) + E4 evidence(wLevel["E4"])
	// + corroborated(+0.5) + outlook likely(+0.5) == exact sum, no cap.
	f := accFinding(func(f *validation.Value) {
		setBand(f, "critical")
		setEvidence(f, "E4")
		*f = withKeyR(*f, "dedup_meta", validation.VObj(
			kvR("corroborated_by", validation.VStr("F-t"))))
		*f = withKeyR(*f, "verification", validation.VObj(
			kvR("critic_verdict", validation.VStr("confirmed")),
			kvR("triager_outlook", validation.VObj(
				kvR("outcome", validation.VStr("likely")),
				kvR("reason", validation.VStr("policy pays critical; fork PoC"))))))
	})
	score, dq := AcceptanceScore(f)
	if dq {
		t.Fatal("not disqualified")
	}
	want := 1.5 + 3.0 + wLevel["E4"] + 0.5 + 0.5
	if score != want {
		t.Fatalf("additivity broken: got %v want %v", score, want)
	}
	// floor clamp with BOTH demotions and outlook unlikely on a bare
	// finding: -1 (ack) -2 (accepted-risk) -0.5 (unlikely) -> exactly 0.
	b := accFinding(func(f *validation.Value) {
		setAck(f)
		*f = withKeyR(*f, "bounty", validation.VObj(
			kvR("accepted_risk", validation.VObj())))
		*f = withKeyR(*f, "verification", validation.VObj(
			kvR("triager_outlook", validation.VObj(
				kvR("outcome", validation.VStr("unlikely")),
				kvR("reason", validation.VStr("policy excludes this scope"))))))
	})
	if sc, _ := AcceptanceScore(b); sc != 0 {
		t.Fatalf("floor clamp: %v", sc)
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

// ---- G3 wPrior: policy-gated OFF beside the outlook nudge ----
//
// The brief's worked example says rate .8 n 20 vs global .5 ⇒ +0.3; the
// VERBATIM law it also states gives 2*(.8-.5)*min(1,20/30) = 0.4 (and no
// float expression in .8/.5 is ever "exact"). The formula is law, the
// example is arithmetic drift — TestAcceptancePriorTerm pins the formula's
// value (with the op order the code uses, so the equality is bitwise) and
// documents the real magnitude; the exact-arithmetic subcase proves the
// determinism the "exact" demand was after.

func setClassR(f *validation.Value, class string) {
	*f = withKeyR(*f, "root_cause", validation.VObj(
		kvR("class", validation.VStr(class)),
		kvR("description", validation.VStr("prior fixture mechanism"))))
}

// priorFinding is a fully-loaded finding (every pre-G3 block fires) with
// a class the test priors know.
func priorFinding() validation.Value {
	return accFinding(func(v *validation.Value) {
		setBand(v, "high")
		setEvidence(v, "E4")
		setCritic(v, "confirmed")
		setClassR(v, "oracle-manipulation")
	})
}

func TestAcceptanceWithPriorsNilIsIdentical(t *testing.T) {
	// Every block on: severity + evidence + critic + outlook + both
	// demotions + corroboration + reversibility — plus the bare and the
	// disqualified shapes. Nil priors must be Acceptance, field for
	// field (there is no Factors map on the entry — the struct IS the
	// surface, so DeepEqual over the whole entry is the stronger check).
	full := priorFinding()
	setAck(&full)
	setAcceptedRisk(&full)
	full = withKeyR(full, "dedup_meta", validation.VObj(
		kvR("in_code_ack", objAt(objAt(full, "dedup_meta"), "in_code_ack")),
		kvR("corroborated_by", validation.VStr("F-t"))))
	full = withKeyR(full, "verification", validation.VObj(
		kvR("critic_verdict", validation.VStr("confirmed")),
		kvR("triager_outlook", validation.VObj(
			kvR("outcome", validation.VStr("likely")),
			kvR("reason", validation.VStr("policy pays critical; fork PoC"))))))
	setReversibility(&full, "irreversible")
	dq := accFinding(func(v *validation.Value) {
		setBand(v, "critical")
		setCritic(v, "disproved")
		setClassR(v, "oracle-manipulation")
	})
	for i, f := range []validation.Value{
		accFinding(func(v *validation.Value) {}),
		priorFinding(),
		full,
		dq,
	} {
		a, b := Acceptance(f), AcceptanceWithPriors(f, nil, Prior{})
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("finding %d: nil priors != Acceptance:\n%#v\n%#v", i, a, b)
		}
		// An empty-but-non-nil map (a store with no rows for the class)
		// is the same no-op: lookup misses, nothing is set.
		c := AcceptanceWithPriors(f, map[string]Prior{}, Prior{})
		if !reflect.DeepEqual(a, c) {
			t.Fatalf("finding %d: empty priors != Acceptance", i)
		}
	}
}

func TestAcceptancePriorTerm(t *testing.T) {
	f := priorFinding()
	// Variables, NOT constants: Go folds constant expressions at
	// arbitrary precision, which rounds differently than the runtime
	// float64 ops the code performs. Variables force the same runtime
	// evaluation — same values, same op order, bitwise equality.
	rate, glob, n := 0.8, 0.5, 20.0
	priors := map[string]Prior{
		"oracle-manipulation": {Class: "oracle-manipulation", Rate: rate, N: int(n)},
	}
	global := Prior{Class: "global", Rate: glob, N: 100}
	base := Acceptance(f)
	got := AcceptanceWithPriors(f, priors, global)
	// the verbatim law, same op order as the code (bitwise equality):
	want := 2 * (rate - glob) * math.Min(1, n/30)
	if !(want > 0.39 && want < 0.41) {
		t.Fatalf("law value = %v, want ~0.4 (the brief's +0.3 is drift)", want)
	}
	// Bitwise: the code adds the term LAST, so got.Score must equal
	// base.Score + want under the same op order (a-b != term in floats —
	// the subtraction is not the addition's inverse — so compare the sum).
	if got.Score != base.Score+want {
		t.Fatalf("score = %v, want base %v + law %v", got.Score, base.Score, want)
	}
	if got.PriorFactor != want {
		t.Fatalf("PriorFactor = %v, want %v", got.PriorFactor, want)
	}
	if got.Prior == "" || got.Prior != priors["oracle-manipulation"].Render() {
		t.Fatalf("Prior = %q, want the Render() line", got.Prior)
	}
	if base.PriorFactor != 0 || base.Prior != "" {
		t.Fatal("the plain path must leave the prior fields zero")
	}
	// exact-arithmetic subcase: 2*(0.75-0.5)*min(1,15/30) = 0.25 exactly.
	exact := map[string]Prior{
		"oracle-manipulation": {Class: "oracle-manipulation", Rate: 0.75, N: 15},
	}
	eg := AcceptanceWithPriors(f, exact, global)
	if eg.Score != base.Score+0.25 {
		t.Fatalf("exact score = %v, want base + 0.25", eg.Score)
	}
	if eg.PriorFactor != 0.25 {
		t.Fatalf("exact PriorFactor = %v, want 0.25", eg.PriorFactor)
	}
}

func TestAcceptancePriorGateOuts(t *testing.T) {
	f := priorFinding()
	base := Acceptance(f)
	global := Prior{Class: "global", Rate: 0.5, N: 100}
	cases := map[string]map[string]Prior{
		// a fallback prior carries the global's number, not the
		// class's: it must never move the score.
		"fallback": {"oracle-manipulation": {
			Class: "oracle-manipulation", Rate: 0.8, N: 20,
			Fallback: true, GlobalN: 100}},
		// thinner than DefaultMinN (10): no number to stand on.
		"thin-n5": {"oracle-manipulation": {
			Class: "oracle-manipulation", Rate: 0.8, N: 5}},
		"thin-n9": {"oracle-manipulation": {
			Class: "oracle-manipulation", Rate: 0.8, N: 9}},
		// a class the store never saw: nothing to carry.
		"unknown": {"reentrancy": {
			Class: "reentrancy", Rate: 0.8, N: 20}},
	}
	for name, priors := range cases {
		got := AcceptanceWithPriors(f, priors, global)
		if !reflect.DeepEqual(got, base) {
			t.Fatalf("%s: gated-out prior moved the entry: %#v", name, got)
		}
	}
	// the thickness boundary itself: n == DefaultMinN fires.
	atMin := map[string]Prior{"oracle-manipulation": {
		Class: "oracle-manipulation", Rate: 0.8, N: DefaultMinN}}
	got := AcceptanceWithPriors(f, atMin, global)
	if got.Score == base.Score || got.PriorFactor == 0 || got.Prior == "" {
		t.Fatalf("n == DefaultMinN must fire: %#v", got)
	}
}

func TestAcceptancePriorClamp(t *testing.T) {
	f := priorFinding()
	base := Acceptance(f)
	// 2*(0-0.5)*min(1,30/30) = -1.0 ⇒ exactly -0.5.
	neg := map[string]Prior{"oracle-manipulation": {
		Class: "oracle-manipulation", Rate: 0, N: 30}}
	global := Prior{Class: "global", Rate: 0.5, N: 100}
	got := AcceptanceWithPriors(f, neg, global)
	if got.PriorFactor != -0.5 {
		t.Fatalf("clamped PriorFactor = %v, want exactly -0.5", got.PriorFactor)
	}
	if d := got.Score - base.Score; d != -0.5 {
		t.Fatalf("clamped delta = %v, want exactly -0.5", d)
	}
	// 2*(1-0)*min(1,40/30) = 2.0 ⇒ exactly +0.5.
	pos := map[string]Prior{"oracle-manipulation": {
		Class: "oracle-manipulation", Rate: 1, N: 40}}
	got = AcceptanceWithPriors(f, pos, Prior{Class: "global"})
	if got.PriorFactor != 0.5 {
		t.Fatalf("clamped PriorFactor = %v, want exactly +0.5", got.PriorFactor)
	}
}

func TestAcceptanceEntryJSONOmitsPriorWhenZero(t *testing.T) {
	// Policy-off byte check: the default entry carries no prior keys in
	// ANY rendering — encoding/json here (omitempty), the " +prior"
	// marker in scoreCell/rankScore (presence-gated the AckDemoted way).
	raw, err := json.Marshal(Acceptance(priorFinding()))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"prior_factor", "prior"} {
		if _, ok := m[k]; ok {
			t.Fatalf("policy-off entry renders key %q: %s", k, raw)
		}
	}
	// ... and the keys ARE present with the right values when the term fires.
	priors := map[string]Prior{
		"oracle-manipulation": {Class: "oracle-manipulation", Rate: 0.8, N: 20},
	}
	global := Prior{Class: "global", Rate: 0.5, N: 100}
	raw, err = json.Marshal(AcceptanceWithPriors(priorFinding(), priors, global))
	if err != nil {
		t.Fatal(err)
	}
	m = nil
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["prior_factor"]; !ok {
		t.Fatalf("fired entry missing prior_factor: %s", raw)
	}
	if m["prior"] != priors["oracle-manipulation"].Render() {
		t.Fatalf("prior = %v, want the Render() line", m["prior"])
	}
}

// TestAcceptanceMitigationAndRiskNeverShareAField is law half (a),
// acceptance side: a finding with BOTH dedup_meta.mitigation_present AND
// bounty.accepted_risk shows BOTH factors (score −3: −2 policy, −1
// soundness), and the two records share no field beyond the coincidental
// NAME "pattern" — the mitigation JSON carries no policy key, the
// accepted-risk object carries no soundness key (file/line/evidence).
// (The NAME "pattern" is legitimately used by both layers; the
// separation is at the OBJECT level — dedup_meta vs bounty — which is
// what this test pins.)
func TestAcceptanceMitigationAndRiskNeverShareAField(t *testing.T) {
	base := func() validation.Value {
		return accFinding(func(v *validation.Value) {
			setBand(v, "high")   // 2.0
			setEvidence(v, "E4") // 2.0
		})
	}
	f := base()
	setAcceptedRisk(&f)
	setMitigation(&f)
	e := Acceptance(f)
	if e.Score != 1.0 {
		t.Fatalf("risk+mitigation = %v, want 1.0 (4.0 −2 −1)", e.Score)
	}
	if e.Disqualified {
		t.Fatal("neither layer dismisses")
	}
	if !e.MitigationDemoted || !e.RiskDemoted {
		t.Fatalf("both factors must show: %#v", e)
	}
	if e.Mitigation != "cei-order" {
		t.Fatalf("Mitigation = %q, want cei-order", e.Mitigation)
	}
	// Field level: the mitigation JSON string carries no policy key.
	var m map[string]string
	ms := objStr(orObj(objAt(f, "dedup_meta")), "mitigation_present")
	if err := json.Unmarshal([]byte(ms), &m); err != nil {
		t.Fatalf("mitigation_present must decode: %v", err)
	}
	for _, banned := range []string{"url", "reference_url", "cites",
		"reference", "note", "kind", "excluded_by"} {
		if _, ok := m[banned]; ok {
			t.Errorf("mitigation JSON carries policy key %q", banned)
		}
	}
	// Field level: the accepted-risk object carries no soundness key.
	ar := objAt(orObj(objAt(f, "bounty")), "accepted_risk")
	for _, banned := range []string{"file", "line", "evidence",
		"mitigation_present"} {
		if _, ok := fieldAtR(ar, banned); ok {
			t.Errorf("accepted_risk record carries soundness key %q",
				banned)
		}
	}
}

// fieldAtR is the test-local field probe (mirrors the package's unexported
// field lookup over a validation object).
func fieldAtR(v validation.Value, key string) (validation.Value, bool) {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}
