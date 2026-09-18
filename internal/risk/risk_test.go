package risk

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// PORT-NOTE tests/test_risk_amplifiers.py::test_playbook_schema_accepts_amplifiers
// and ::test_shipped_playbook_tags exercise webv2.playbooks (unported) and the
// playbook schema; they are listed as unresolved.
// PORT-NOTE tests/test_budget.py has no function that calls risk./pricing.
// (every test drives costs/pipeline/orchestrator) — nothing portable.
// PORT-NOTE tests/test_metrics.py has no function that calls risk./pricing.
// — nothing portable.

// kv is the vet-clean keyed KV constructor for this package's tests.
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// riskCamp is the `camp` fixture for the campaign-backed risk functions: a
// fresh campaign (no pinned snapshot needed — source reads "unpinned").
func riskCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// hypoPayload is the minimal ingest payload (conftest-style).
func hypoPayload(over ...validation.KV) validation.Value {
	base := validation.VObj(
		kv("title", validation.VStr(
			"Flash-loan push of the TWAP lets a redeemer exit above NAV")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("description", validation.VStr(
				"TWAP window exceeds the manipulation horizon")),
		)),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
	)
	for _, o := range over {
		base.O = validation.SetOrAppend(base.O, o.K, o.V)
	}
	return base
}

// ingest is the fixture: one hypothesis ingested into a fresh campaign.
func ingest(t *testing.T, c *state.Campaign, over ...validation.KV) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, hypoPayload(over...), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjAt(f, "finding_id").S
}

func floatPtr(f float64) *float64 { return &f }

func strPtr(s string) *string { return &s }

func canon(t *testing.T, v validation.Value) string {
	t.Helper()
	return validation.CanonSpaced(v)
}

// ---- prior_risk / validation_cost / amplifier_bonus -----------------------

func TestPriorRiskVectors(t *testing.T) {
	cases := []struct {
		bugClass            string
		reach, fork, analog bool
		invariant           *string
		capital             *float64
		want                string
	}{
		{"access-control", true, false, true, strPtr("INV-1"), floatPtr(2_000_000),
			`{"factors": ["base(access-control)=0.9", "unprivileged-reachable +0.1", ` +
				`"historical-analog +0.08", "tied-to-invariant +0.05", ` +
				`"high-capital-requirement -0.05"], "score": 1.0}`},
		{"mystery-class", false, true, false, nil, nil,
			`{"factors": ["base(mystery-class)=0.4", "fork-state-dependent +0.02"], ` +
				`"score": 0.42}`},
		{"reentrancy", false, false, false, nil, floatPtr(1_000_000),
			`{"factors": ["base(reentrancy)=0.7"], "score": 0.7}`},
		{"economic-invariant", true, true, true, strPtr(""), floatPtr(5_000_000),
			`{"factors": ["base(economic-invariant)=0.7", "unprivileged-reachable +0.1", ` +
				`"historical-analog +0.08", "high-capital-requirement -0.05", ` +
				`"fork-state-dependent +0.02"], "score": 0.85}`},
	}
	for _, c := range cases {
		got := PriorRisk(c.bugClass, c.reach, c.fork, c.analog, c.invariant,
			c.capital)
		if canon(t, got) != c.want {
			t.Errorf("PriorRisk(%q) = %s; want %s", c.bugClass, canon(t, got),
				c.want)
		}
		if got.O[0].K != "score" || got.O[1].K != "factors" {
			t.Fatalf("key order = %s", canon(t, got))
		}
	}
}

func TestValidationCostTable(t *testing.T) {
	cases := []struct {
		class     string
		fork, sym bool
		want      string
	}{
		{"bridge-message", false, false, "expensive"},
		{"cross-chain-replay", false, false, "expensive"},
		{"logic-error", true, false, "expensive"},
		{"economic-invariant", false, false, "standard"},
		{"oracle-manipulation", false, false, "standard"},
		{"logic-error", false, true, "standard"},
		{"logic-error", false, false, "cheap"},
		{"access-control", false, false, "cheap"},
	}
	for _, c := range cases {
		if got := ValidationCost(c.class, c.fork, c.sym); got != c.want {
			t.Errorf("ValidationCost(%q, %v, %v) = %q; want %q", c.class,
				c.fork, c.sym, got, c.want)
		}
	}
	if got := ValidationCost("bridge-message", false, true); got != "expensive" {
		t.Errorf("fork clause must win: %q", got)
	}
}

// test_amplifier_bonus_math (tests/test_risk_amplifiers.py).
func TestAmplifierBonusMath(t *testing.T) {
	detected := validation.VObj(
		kv("oracle", validation.VArr(validation.VStr("x#y"))),
		kv("flash-loan", validation.VArr(validation.VStr("x#z"))),
	)
	bonus, hits := AmplifierBonus([]string{"oracle", "flash-loan", "bridge"},
		detected)
	if bonus != 1.0 {
		t.Errorf("bonus = %v; want 1.0 (capped)", bonus)
	}
	if strings.Join(hits, ",") != "flash-loan,oracle" {
		t.Errorf("hits = %v; want [flash-loan oracle]", hits)
	}
	bonus, hits = AmplifierBonus([]string{"bridge"}, detected)
	if bonus != 0.0 || len(hits) != 0 {
		t.Errorf("AmplifierBonus(bridge) = (%v, %v); want (0, [])", bonus, hits)
	}
}

func TestAmplifierBonusEmptyInputs(t *testing.T) {
	bonus, hits := AmplifierBonus(nil, validation.VNull())
	if bonus != 0.0 || hits == nil || len(hits) != 0 {
		t.Errorf("nil inputs = (%v, %#v); want (0, [])", bonus, hits)
	}
	bonus, hits = AmplifierBonus([]string{"a", "b", "c", "d", "e"},
		validation.VObj(kv("a", validation.VArr()), kv("b", validation.VArr()),
			kv("c", validation.VArr()), kv("d", validation.VArr()),
			kv("e", validation.VArr())))
	if bonus != 1.0 || len(hits) != 5 {
		t.Errorf("cap = (%v, %v); want (1.0, 5 hits)", bonus, len(hits))
	}
}

// ---- validated_risk -------------------------------------------------------

func TestValidatedRiskVectors(t *testing.T) {
	cases := []struct {
		name string
		f    validation.Value
		want string
	}{
		{"defaults", validation.VObj(),
			`{"band": "medium", "rationale": "blast_radius(subset-of-users)=3.0; ` +
				`evidence(E0)=+0.0; unprivileged-attacker +1.0", "score": 4.0}`},
		{"solvency-extractable",
			validation.VObj(kv("economic_impact", validation.VObj(
				kv("blast_radius", validation.VStr("protocol-solvency")),
				kv("extractable_usd", validation.VInt(5_000_000))))),
			`{"band": "critical", "rationale": "blast_radius(protocol-solvency)=7.0; ` +
				`evidence(E0)=+0.0; unprivileged-attacker +1.0; ` +
				`extractable($5,000,000) +0.7", "score": 8.7}`},
		{"half-even-usd",
			validation.VObj(kv("economic_impact", validation.VObj(
				kv("extractable_usd", validation.VFloat(99_999.5))))),
			`{"band": "medium", "rationale": "blast_radius(subset-of-users)=3.0; ` +
				`evidence(E0)=+0.0; unprivileged-attacker +1.0; ` +
				`extractable($100,000) +0.2", "score": 4.2}`},
		{"zero-rounds-down",
			validation.VObj(kv("economic_impact", validation.VObj(
				kv("extractable_usd", validation.VFloat(0.5))))),
			`{"band": "medium", "rationale": "blast_radius(subset-of-users)=3.0; ` +
				`evidence(E0)=+0.0; unprivileged-attacker +1.0; ` +
				`extractable($0) +0.2", "score": 4.2}`},
		{"null-blast",
			validation.VObj(kv("economic_impact", validation.VObj(
				kv("blast_radius", validation.VNull()),
				kv("extractable_usd", validation.VInt(1))))),
			`{"band": "low", "rationale": "blast_radius(None)=2.0; ` +
				`evidence(E0)=+0.0; unprivileged-attacker +1.0; ` +
				`extractable($1) +0.2", "score": 3.2}`},
		{"privileged",
			validation.VObj(kv("attacker", validation.VObj(
				kv("required_privileges", validation.VArr(
					validation.VStr("owner")))))),
			`{"band": "low", "rationale": "blast_radius(subset-of-users)=3.0; ` +
				`evidence(E0)=+0.0; privileged (1) +0", "score": 3.0}`},
		{"e7",
			validation.VObj(kv("evidence", validation.VArr(
				validation.VObj(kv("level", validation.VStr("E7")))))),
			`{"band": "high", "rationale": "blast_radius(subset-of-users)=3.0; ` +
				`evidence(E7)=+3.0; unprivileged-attacker +1.0", "score": 7.0}`},
		{"clamp",
			validation.VObj(
				kv("economic_impact", validation.VObj(
					kv("blast_radius", validation.VStr("bridge-canonical")))),
				kv("attacker", validation.VObj(
					kv("required_privileges", validation.VArr(
						validation.VStr("a"), validation.VStr("b"))))),
				kv("evidence", validation.VArr(
					validation.VObj(kv("level", validation.VStr("E5"))),
					validation.VObj(kv("level", validation.VStr("E3")))))),
			`{"band": "critical", "rationale": "blast_radius(bridge-canonical)=8.0; ` +
				`evidence(E5)=+2.5; privileged (2) +0", "score": 10.0}`},
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

// test_validated_risk_bands (tests/test_chain_engine.py).
func TestValidatedRiskBands(t *testing.T) {
	c := riskCamp(t)
	fid := ingest(t, c)
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "economic_impact", validation.VObj(
		kv("blast_radius", validation.VStr("protocol-solvency")),
		kv("extractable_usd", validation.VInt(5_000_000))))
	hi, err := ValidatedRisk(f)
	if err != nil {
		t.Fatal(err)
	}
	if band := validation.ObjAt(hi, "band").S; band != "critical" && band != "high" {
		t.Errorf("band = %q; want critical|high", band)
	}
	if score := validation.ObjAt(hi, "score").F; score < 6.5 {
		t.Errorf("score = %v; want >= 6.5", score)
	}
	lo := validation.Value{Kind: validation.Obj, O: append([]validation.KV(nil), f.O...)}
	lo.O = validation.SetOrAppend(lo.O, "economic_impact", validation.VObj(
		kv("blast_radius", validation.VStr("single-user")),
		kv("extractable_usd", validation.VInt(100))))
	lo.O = validation.SetOrAppend(lo.O, "attacker", validation.VObj(
		kv("profile", validation.VStr("EOA")),
		kv("capabilities", validation.VArr()),
		kv("required_privileges", validation.VArr(validation.VStr("governor")))))
	loOut, err := ValidatedRisk(lo)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(loOut, "score").F >= validation.ObjAt(hi, "score").F {
		t.Errorf("single-user score %v must be < %v", validation.ObjAt(loOut, "score").F,
			validation.ObjAt(hi, "score").F)
	}
}

// ---- economic_risk / bounty_score ----------------------------------------

func TestEconomicRiskVectors(t *testing.T) {
	notes := "max_loss_usd recorded on economic_impact; extractable is bounded " +
		"by on-chain liquidity, not by the theoretical exposure"
	got := EconomicRisk(validation.VInt(1000), validation.VInt(1_000_000),
		validation.VInt(3))
	if validation.ObjAt(got, "leverage_ratio").F != 333333.333 {
		t.Errorf("leverage = %v; want 333333.333", validation.ObjAt(got, "leverage_ratio").F)
	}
	if validation.ObjAt(got, "notes").S != notes {
		t.Errorf("notes = %q", validation.ObjAt(got, "notes").S)
	}
	// ints stay ints (Python passes the caller's values straight through).
	if canon(t, got) != `{"capital_required_usd": 3, "extractable_usd": 1000000, `+
		`"leverage_ratio": 333333.333, "notes": "`+notes+`"}` {
		t.Errorf("ints = %s", canon(t, got))
	}
	got = EconomicRisk(validation.VNull(), validation.VNull(), validation.VNull())
	if canon(t, got) != `{"capital_required_usd": null, "extractable_usd": null, `+
		`"leverage_ratio": null, "notes": "`+notes+`"}` {
		t.Errorf("all-None = %s", canon(t, got))
	}
	got = EconomicRisk(validation.VNull(), validation.VInt(1000), validation.VInt(0))
	if validation.ObjAt(got, "leverage_ratio").Kind != validation.Null {
		t.Errorf("zero capital must not divide: %s", canon(t, got))
	}
	if canon(t, validation.ObjAt(got, "extractable_usd")) != "1000" {
		t.Errorf("extractable = %s", canon(t, validation.ObjAt(got, "extractable_usd")))
	}
	got = EconomicRiskFloat(floatPtr(1000), floatPtr(1_000_000), floatPtr(3))
	if canon(t, got) != `{"capital_required_usd": 3.0, "extractable_usd": 1000000.0, `+
		`"leverage_ratio": 333333.333, "notes": "`+notes+`"}` {
		t.Errorf("float form = %s", canon(t, got))
	}
}

func TestBountyScoreVectors(t *testing.T) {
	eight := validation.VObj(kv("validated", validation.VObj(
		kv("score", validation.VInt(8)))))
	cases := []struct {
		name     string
		risk     validation.Value
		eligible *bool
		bonus    float64
		want     float64
	}{
		{"eligible", eight, boolPtr(true), 0, 8.0},
		{"ineligible-capped", eight, boolPtr(false), 0, 4.0},
		{"none-eligibility", validation.VObj(), nil, 0, 0.0},
		{"amplifier", validation.VObj(
			kv("validated", validation.VObj(kv("score", validation.VFloat(5.0)))),
			kv("economic", validation.VObj(kv("extractable_usd", validation.VInt(0))))),
			boolPtr(true), 0.5, 5.5},
		{"econ-bonus", validation.VObj(
			kv("validated", validation.VObj(kv("score", validation.VInt(3)))),
			kv("economic", validation.VObj(
				kv("extractable_usd", validation.VInt(250_000))))),
			boolPtr(true), 0, 4.0},
		{"clamped", eight, boolPtr(true), 5.0, 10.0},
	}
	for _, c := range cases {
		if got := BountyScore(c.risk, c.eligible, c.bonus); got != c.want {
			t.Errorf("%s: BountyScore = %v; want %v", c.name, got, c.want)
		}
	}
	if BountyScore(eight, boolPtr(false), 0) >= BountyScore(eight, boolPtr(true), 0) {
		t.Error("ineligible must sort below eligible")
	}
}

// test_bounty_score_accepts_amplifier_bonus (tests/test_risk_amplifiers.py).
func TestBountyScoreAcceptsAmplifierBonus(t *testing.T) {
	risk := validation.VObj(
		kv("validated", validation.VObj(kv("score", validation.VFloat(5.0)))),
		kv("economic", validation.VObj(kv("extractable_usd", validation.VInt(0)))))
	base := BountyScore(risk, boolPtr(true), 0)
	boosted := BountyScore(risk, boolPtr(true), 0.5)
	if boosted != 5.5 {
		t.Errorf("boosted = %v; want 5.5", boosted)
	}
	if boosted != validation.PythonRound(minF(10.0, base+0.5), 2) {
		t.Errorf("boosted %v != round(min(10, %v+0.5), 2)", boosted, base)
	}
}

// test_prior_risk_decision_rule (tests/test_chain_engine.py) — the
// planner.decision_rule half needs webv2.planner (unported); only the
// bounty_score half is portable.
func TestPriorRiskDecisionRuleBountyHalf(t *testing.T) {
	eight := validation.VObj(kv("validated", validation.VObj(
		kv("score", validation.VInt(8)))))
	if !(BountyScore(eight, boolPtr(true), 0) > BountyScore(eight, boolPtr(false), 0)) {
		t.Error("eligibility True must score above False")
	}
	if got := BountyScore(eight, boolPtr(false), 0); got != 4.0 {
		t.Errorf("ineligible score = %v; want the 4.0 cap", got)
	}
}

// ---- impact_vector --------------------------------------------------------

func TestImpactVectorVectors(t *testing.T) {
	cases := []struct {
		name string
		f    validation.Value
		want string
	}{
		{"defaults", validation.VObj(),
			`{"asset_exposure": "none", "insolvency_risk": "low", ` +
				`"privilege_class": "unprivileged", "recoverability": "unknown", ` +
				`"score": 4.5}`},
		{"lt-100k",
			validation.VObj(kv("economic_impact", validation.VObj(
				kv("extractable_usd", validation.VInt(50_000))))),
			`{"asset_exposure": "lt_100k", "insolvency_risk": "low", ` +
				`"privilege_class": "unprivileged", "recoverability": "unknown", ` +
				`"score": 5.5}`},
		{"gt-10m",
			validation.VObj(kv("economic_impact", validation.VObj(
				kv("extractable_usd", validation.VInt(50_000_000))))),
			`{"asset_exposure": "gt_10m", "insolvency_risk": "low", ` +
				`"privilege_class": "unprivileged", "recoverability": "unknown", ` +
				`"score": 10.5}`},
		{"role",
			validation.VObj(kv("attacker", validation.VObj(
				kv("required_privileges", validation.VArr(
					validation.VStr("DEFAULT_ADMIN_ROLE")))))),
			`{"asset_exposure": "none", "insolvency_risk": "low", ` +
				`"privilege_class": "role", "recoverability": "unknown", ` +
				`"score": 2.5}`},
		{"semi-privileged",
			validation.VObj(kv("attacker", validation.VObj(
				kv("required_privileges", validation.VArr(validation.VStr(
					"keeper-set via governance queue slot 3")))))),
			`{"asset_exposure": "none", "insolvency_risk": "low", ` +
				`"privilege_class": "semi-privileged", ` +
				`"recoverability": "unknown", "score": 3.0}`},
		{"recoverable-high",
			validation.VObj(kv("attacker", validation.VObj(
				kv("capital_profile", validation.VObj(
					kv("recoverable_usd", validation.VInt(10_000)),
					kv("irrecoverable_cost_usd", validation.VInt(0))))))),
			`{"asset_exposure": "none", "insolvency_risk": "low", ` +
				`"privilege_class": "unprivileged", "recoverability": "high", ` +
				`"score": 4.0}`},
		{"recoverable-low",
			validation.VObj(kv("attacker", validation.VObj(
				kv("capital_profile", validation.VObj(
					kv("recoverable_usd", validation.VInt(0)),
					kv("irrecoverable_cost_usd", validation.VInt(5))))))),
			`{"asset_exposure": "none", "insolvency_risk": "low", ` +
				`"privilege_class": "unprivileged", "recoverability": "low", ` +
				`"score": 6.0}`},
		{"drain",
			validation.VObj(kv("root_cause", validation.VObj(
				kv("description", validation.VStr(
					"drains the entire liquidity pool"))))),
			`{"asset_exposure": "none", "insolvency_risk": "high", ` +
				`"privilege_class": "unprivileged", "recoverability": "unknown", ` +
				`"score": 7.5}`},
		{"loss-ratio",
			validation.VObj(kv("economic_impact", validation.VObj(
				kv("extractable_usd", validation.VInt(1_000)),
				kv("max_loss_usd", validation.VInt(20_000))))),
			`{"asset_exposure": "lt_100k", "insolvency_risk": "medium", ` +
				`"privilege_class": "unprivileged", "recoverability": "unknown", ` +
				`"score": 7.0}`},
		{"all-null", validation.VObj(
			kv("title", validation.VNull()),
			kv("root_cause", validation.VObj(kv("description", validation.VNull()))),
			kv("attacker", validation.VObj(
				kv("required_privileges", validation.VNull()),
				kv("capital_profile", validation.VNull()))),
			kv("economic_impact", validation.VNull())),
			`{"asset_exposure": "none", "insolvency_risk": "low", ` +
				`"privilege_class": "unprivileged", "recoverability": "unknown", ` +
				`"score": 4.5}`},
		{"band-weight-sum",
			validation.VObj(
				kv("economic_impact", validation.VObj(
					kv("extractable_usd", validation.VInt(5_000_000)))),
				kv("attacker", validation.VObj(
					kv("required_privileges", validation.VArr())))),
			`{"asset_exposure": "1m_10m", "insolvency_risk": "low", ` +
				`"privilege_class": "unprivileged", "recoverability": "unknown", ` +
				`"score": 9.0}`},
	}
	for _, c := range cases {
		got, err := ImpactVector(c.f)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if canon(t, got) != c.want {
			t.Errorf("%s: %s; want %s", c.name, canon(t, got), c.want)
		}
	}
}

// test_asset_exposure_bands (tests/test_severity_split.py).
func TestAssetExposureBands(t *testing.T) {
	v := func(usd validation.Value) string {
		iv, err := ImpactVector(validation.VObj(kv("economic_impact",
			validation.VObj(kv("extractable_usd", usd)))))
		if err != nil {
			t.Fatal(err)
		}
		return validation.ObjAt(iv, "asset_exposure").S
	}
	if got := v(validation.VNull()); got != "none" {
		t.Errorf("None -> %q; want none", got)
	}
	for _, c := range []struct {
		usd  int64
		want string
	}{{50_000, "lt_100k"}, {500_000, "100k_1m"}, {5_000_000, "1m_10m"},
		{50_000_000, "gt_10m"}, {0, "lt_100k"}, {-5, "lt_100k"}} {
		if got := v(validation.VInt(c.usd)); got != c.want {
			t.Errorf("usd %d -> %q; want %q", c.usd, got, c.want)
		}
	}
}

// test_privilege_class_mapping (tests/test_severity_split.py).
func TestPrivilegeClassMapping(t *testing.T) {
	v := func(privs ...string) string {
		items := make([]validation.Value, len(privs))
		for i, p := range privs {
			items[i] = validation.VStr(p)
		}
		iv, err := ImpactVector(validation.VObj(kv("attacker",
			validation.VObj(kv("required_privileges", validation.VArr(items...))))))
		if err != nil {
			t.Fatal(err)
		}
		return validation.ObjAt(iv, "privilege_class").S
	}
	for _, c := range []struct {
		privs []string
		want  string
	}{
		{nil, "unprivileged"},
		{[]string{"onlyOwner"}, "owner"},
		{[]string{"DEFAULT_ADMIN_ROLE"}, "role"},
		{[]string{"keeper-set via governance queue slot 3"}, "semi-privileged"},
		{[]string{"   "}, "unprivileged"},
		{[]string{"owner", "role"}, "role"},
		{[]string{"guardian"}, "owner"},
		{[]string{"pauser"}, "role"},
	} {
		if got := v(c.privs...); got != c.want {
			t.Errorf("privs %v -> %q; want %q", c.privs, got, c.want)
		}
	}
	iv, err := ImpactVector(validation.VObj(kv("attacker", validation.VObj(
		kv("required_privileges", validation.VArr(validation.VNull(),
			validation.VStr("onlyOwner")))))))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(iv, "privilege_class").S != "owner" {
		t.Error("null elements inside the privilege list must be skipped")
	}
}

// test_recoverability_and_insolvency (tests/test_severity_split.py).
func TestRecoverabilityAndInsolvency(t *testing.T) {
	base := validation.VObj(kv("attacker", validation.VObj(
		kv("capital_profile", validation.VObj(
			kv("recoverable_usd", validation.VInt(10_000)),
			kv("irrecoverable_cost_usd", validation.VInt(0)))))))
	iv, err := ImpactVector(base)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(iv, "recoverability").S; got != "high" {
		t.Errorf("recoverability = %q; want high", got)
	}
	mid := validation.VObj(kv("attacker", validation.VObj(
		kv("capital_profile", validation.VObj(
			kv("recoverable_usd", validation.VInt(10_000)),
			kv("irrecoverable_cost_usd", validation.VInt(90_000)))))))
	iv, err = ImpactVector(mid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(iv, "recoverability").S; got != "medium" {
		t.Errorf("recoverability = %q; want medium", got)
	}
	iv, err = ImpactVector(validation.VObj(kv("root_cause", validation.VObj(
		kv("description", validation.VStr("drains the entire liquidity pool"))))))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(iv, "insolvency_risk").S; got != "high" {
		t.Errorf("insolvency = %q; want high", got)
	}
	iv, err = ImpactVector(validation.VObj(kv("economic_impact",
		validation.VObj(kv("extractable_usd", validation.VInt(1_000)),
			kv("max_loss_usd", validation.VInt(20_000))))))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(iv, "insolvency_risk").S; got != "medium" {
		t.Errorf("insolvency = %q; want medium", got)
	}
}

// test_impact_vector_score_is_band_weight_sum (tests/test_severity_split.py).
func TestImpactVectorScoreIsBandWeightSum(t *testing.T) {
	f := validation.VObj(
		kv("economic_impact", validation.VObj(
			kv("extractable_usd", validation.VInt(5_000_000)))),
		kv("attacker", validation.VObj(kv("required_privileges",
			validation.VArr()))))
	iv, err := ImpactVector(f)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(iv, "score").F; got != validation.PythonRound(4.5+3.0+1.0+0.5, 2) {
		t.Errorf("score = %v; want the band-weight sum", got)
	}
	if got := validation.ObjAt(iv, "score").F; got != 9.0 {
		t.Errorf("score = %v; want 9.0", got)
	}
}

// test_impact_vector_null_fields_fall_back_to_defaults
// (tests/test_severity_split.py::I-2).
func TestImpactVectorNullFieldsFallBackToDefaults(t *testing.T) {
	iv, err := ImpactVector(validation.VObj(
		kv("title", validation.VNull()),
		kv("root_cause", validation.VObj(kv("description", validation.VNull()))),
		kv("attacker", validation.VObj(
			kv("required_privileges", validation.VNull()),
			kv("capital_profile", validation.VNull()))),
		kv("economic_impact", validation.VNull())))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(iv, "asset_exposure").S != "none" {
		t.Errorf("asset_exposure = %q", validation.ObjAt(iv, "asset_exposure").S)
	}
	if validation.ObjAt(iv, "privilege_class").S != "unprivileged" {
		t.Errorf("privilege_class = %q", validation.ObjAt(iv, "privilege_class").S)
	}
	if validation.ObjAt(iv, "recoverability").S != "unknown" {
		t.Errorf("recoverability = %q", validation.ObjAt(iv, "recoverability").S)
	}
	if validation.ObjAt(iv, "insolvency_risk").S != "low" {
		t.Errorf("insolvency_risk = %q", validation.ObjAt(iv, "insolvency_risk").S)
	}
}

// TestInsolvencyBoundaryParity pins the RE2 form of Python's Unicode \b:
// every expectation below was produced by the Python twin's
// RK.impact_vector(...)["insolvency_risk"].
func TestInsolvencyBoundaryParity(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"poolé", "low"}, {"poolſ", "high"}, {"pool\u0301", "high"},
		{"poolsé", "low"}, {"pool\u212a", "low"}, {"POOLé", "low"},
		{"tvlsé", "high"}, {"liquidityé", "high"}, {"drainé", "high"},
		{"insolvené", "high"}, {"pool-", "high"}, {"pool_", "low"},
		{"pool1", "low"}, {"pool\u00b2", "low"}, {"épool", "low"},
		{"pooled", "low"}, {"pools", "high"}, {"TVL shrinks", "high"},
	}
	for _, c := range cases {
		iv, err := ImpactVector(validation.VObj(kv("title", validation.VStr(c.text))))
		if err != nil {
			t.Fatalf("%q: %v", c.text, err)
		}
		if got := validation.ObjAt(iv, "insolvency_risk").S; got != c.want {
			t.Errorf("%q -> %q; want %q", c.text, got, c.want)
		}
	}
}

func TestPrivilegeRegexParity(t *testing.T) {
	for _, c := range []struct{ priv, want string }{
		{"\u212a", "semi-privileged"}, {"OWNER", "owner"}, {"OwnEr", "owner"},
		{"\u00f8wner", "semi-privileged"}, {"\u027eole", "semi-privileged"},
		{"minter", "role"}, {"guardian", "owner"}, {"admin", "owner"},
	} {
		iv, err := ImpactVector(validation.VObj(kv("attacker",
			validation.VObj(kv("required_privileges",
				validation.VArr(validation.VStr(c.priv)))))))
		if err != nil {
			t.Fatal(err)
		}
		if got := validation.ObjAt(iv, "privilege_class").S; got != c.want {
			t.Errorf("%q -> %q; want %q", c.priv, got, c.want)
		}
	}
}

// ---- formatting helpers ---------------------------------------------------

func TestPyUsd0f(t *testing.T) {
	cases := []struct {
		x    float64
		want string
	}{
		{0, "0"}, {math.Copysign(0, -1), "-0"}, {0.5, "0"}, {1.5, "2"},
		{2.5, "2"}, {99_999.5, "100,000"}, {-1234.5, "-1,234"},
		{1e12, "1,000,000,000,000"}, {1234.5678, "1,235"}, {-5, "-5"},
		{999.5, "1,000"}, {1_000_000, "1,000,000"}, {123_456_789.5, "123,456,790"},
	}
	for _, c := range cases {
		if got := pyUsd0f(c.x); got != c.want {
			t.Errorf("pyUsd0f(%v) = %q; want %q", c.x, got, c.want)
		}
	}
	if got := pyUsd0f(math.NaN()); got != "nan" {
		t.Errorf("nan -> %q", got)
	}
	if got := pyUsd0f(math.Inf(1)); got != "inf" {
		t.Errorf("+inf -> %q", got)
	}
	if got := pyUsd0f(math.Inf(-1)); got != "-inf" {
		t.Errorf("-inf -> %q", got)
	}
}

func TestGroupThousands(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"1", "1"}, {"123", "123"}, {"1234", "1,234"}, {"12345", "12,345"},
		{"123456", "123,456"}, {"1234567", "1,234,567"},
	} {
		if got := groupThousands(c.in); got != c.want {
			t.Errorf("groupThousands(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func boolPtr(b bool) *bool { return &b }

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ---- campaign-backed operations ------------------------------------------

const notesGolden = "max_loss_usd recorded on economic_impact; extractable " +
	"is bounded by on-chain liquidity, not by the theoretical exposure"

// riskBlockA is the calibrate-only risk block, generated by the Python twin
// (json.dumps(..., indent=2)) for the fixture below.
const riskBlockA = `{
  "validated": {
    "score": 4.0,
    "band": "medium",
    "rationale": "blast_radius(subset-of-users)=3.0; evidence(E0)=+0.0; unprivileged-attacker +1.0"
  },
  "economic": {
    "extractable_usd": null,
    "capital_required_usd": null,
    "leverage_ratio": null,
    "notes": "` + notesGolden + `"
  },
  "impact_vector": {
    "asset_exposure": "none",
    "privilege_class": "unprivileged",
    "recoverability": "unknown",
    "insolvency_risk": "low",
    "score": 4.5
  }
}`

// riskBlockB is the same finding after record_economic_impact(
// extractable_usd=800_000, max_loss_usd=800_000) — Python twin output.
const riskBlockB = `{
  "validated": {
    "score": 4.4,
    "band": "medium",
    "rationale": "blast_radius(subset-of-users)=3.0; evidence(E0)=+0.0; unprivileged-attacker +1.0; extractable($800,000) +0.4"
  },
  "economic": {
    "extractable_usd": 800000.0,
    "capital_required_usd": null,
    "leverage_ratio": null,
    "notes": "` + notesGolden + `"
  },
  "impact_vector": {
    "asset_exposure": "100k_1m",
    "privilege_class": "unprivileged",
    "recoverability": "unknown",
    "insolvency_risk": "low",
    "score": 7.0
  }
}`

// test_calibrate_writes_impact_vector (tests/test_severity_split.py).
func TestCalibrateWritesImpactVector(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	riskV, err := Calibrate(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	out, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fieldAt(validation.ObjAt(out, "risk"), "impact_vector"); !ok {
		t.Fatal("calibrate must write risk.impact_vector")
	}
	if got := validation.DumpIndented(riskV); got != riskBlockA {
		t.Errorf("risk block:\n%s\nwant:\n%s", got, riskBlockA)
	}
	if got := validation.DumpIndented(validation.ObjAt(out, "risk")); got != riskBlockA {
		t.Errorf("stored risk block differs:\n%s", got)
	}
}

// TestCalibrateLogsBand pins finding.calibrated's payload.
func TestCalibrateLogsBand(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	if _, err := Calibrate(c, fid); err != nil {
		t.Fatal(err)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var found int
	for _, e := range evs {
		if validation.ObjStr(e, "type") != "finding.calibrated" {
			continue
		}
		found++
		if got := validation.DumpIndented(validation.ObjAt(e, "data")); got !=
			"{\n  \"band\": \"medium\"\n}" {
			t.Errorf("event data = %s", got)
		}
		if validation.ObjStr(e, "ref") != fid {
			t.Errorf("ref = %q; want %q", validation.ObjStr(e, "ref"), fid)
		}
	}
	if found != 1 {
		t.Errorf("finding.calibrated events = %d; want 1", found)
	}
}

// TestRecordEconomicImpactKeepsKwargType pins the int-vs-float split: the
// finding stores float(v), the event keeps the caller's literal (Python
// passes the raw kwarg into the log data).
func TestRecordEconomicImpactKeepsKwargType(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	out, err := RecordEconomicImpact(c, fid, validation.VInt(800_000),
		validation.VInt(800_000), validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.DumpIndented(validation.ObjAt(out, "economic_impact")); got !=
		"{\n  \"extractable_usd\": 800000.0,\n  \"max_loss_usd\": 800000.0\n}" {
		t.Errorf("impact = %s", got)
	}
	if got := validation.DumpIndented(validation.ObjAt(out, "risk")); got != riskBlockB {
		t.Errorf("risk = %s\nwant:\n%s", got, riskBlockB)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var logged int
	for _, e := range evs {
		if validation.ObjStr(e, "type") != "finding.impact_recorded" {
			continue
		}
		logged++
		if got := validation.CanonCompact(validation.ObjAt(e, "data")); got !=
			`{"extractable_usd":800000,"max_loss_usd":800000}` {
			t.Errorf("log data = %s; ints must survive", got)
		}
	}
	if logged != 1 {
		t.Errorf("impact_recorded events = %d; want 1", logged)
	}
}

// TestRecordEconomicImpactFloatAndCapital covers the float kwarg plus the
// required_capital_usd branch (attacker.required_capital_usd = float(v)).
func TestRecordEconomicImpactFloatAndCapital(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	out, err := RecordEconomicImpact(c, fid, validation.VFloat(1_000_000.0),
		validation.VNull(), validation.VInt(3))
	if err != nil {
		t.Fatal(err)
	}
	att := validation.ObjAt(out, "attacker")
	if got := validation.DumpIndented(validation.ObjAt(att, "required_capital_usd")); got != "3.0" {
		t.Errorf("required_capital_usd = %s; want 3.0", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(validation.ObjAt(out, "risk"), "economic")); got !=
		`{"capital_required_usd":3.0,"extractable_usd":1000000.0,`+
			`"leverage_ratio":333333.333,"notes":"`+notesGolden+`"}` {
		t.Errorf("economic risk = %s", got)
	}
	if got := validation.ObjAt(validation.ObjAt(out, "economic_impact"), "max_loss_usd"); got.Kind != validation.Null {
		t.Errorf("max_loss_usd must stay null: %v", got)
	}
}

// TestRecordEconomicImpactNoNumbers: Python's setdefault still inserts an
// empty economic_impact block when no number is passed.
func TestRecordEconomicImpactNoNumbers(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	out, err := RecordEconomicImpact(c, fid, validation.VNull(),
		validation.VNull(), validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(out, "economic_impact"); got.Kind != validation.Obj ||
		len(got.O) != 0 {
		t.Errorf("economic_impact = %s; want {}", validation.DumpIndented(got))
	}
	if _, ok := fieldAt(out, "attacker"); !ok {
		t.Error("attacker must exist on an ingested finding")
	}
}

// TestRecordEconomicImpactRefusesClassWeightSmuggling pins the G2 boundary
// mirroring the floors test: a caller-supplied Value smuggling
// class-weights-table shape ({classes: {...: {severity_default: ...}}}) is
// refused with an error naming the key.
func TestRecordEconomicImpactRefusesClassWeightSmuggling(t *testing.T) {
	c := riskCamp(t)
	fid := ingest(t, c)
	smuggled := validation.VObj(kv("classes", validation.VObj(
		kv("reentrancy", validation.VObj(
			kv("severity_default", validation.VStr("critical")))))))
	_, err := RecordEconomicImpact(c, fid, smuggled, validation.VNull(),
		validation.VNull())
	if err == nil || !strings.Contains(err.Error(), "severity_default") {
		t.Fatalf("risk must refuse class-weights-shaped input naming the key, got %v", err)
	}
}

// TestRecordEconomicImpactRefusesDeeplyNestedSeverityDefault pins the
// recursion: a severity_default buried three objects deep inside a
// caller-supplied Value is still refused (naming the key), a legitimate
// scalar input still records, and nesting past refusalWalkMaxDepth is
// refused fail-closed.
func TestRecordEconomicImpactRefusesDeeplyNestedSeverityDefault(t *testing.T) {
	c := riskCamp(t)
	fid := ingest(t, c)
	deep := validation.VObj(kv("wrap", validation.VObj(
		kv("l1", validation.VObj(
			kv("l2", validation.VObj(
				kv("severity_default", validation.VStr("critical")))))))))
	if _, err := RecordEconomicImpact(c, fid, deep, validation.VNull(),
		validation.VNull()); err == nil ||
		!strings.Contains(err.Error(), "severity_default") {
		t.Fatalf("risk must refuse depth-3 severity_default naming the key, got %v", err)
	}
	if _, err := RecordEconomicImpact(c, fid, validation.VInt(1_500_000),
		validation.VNull(), validation.VNull()); err != nil {
		t.Fatalf("legitimate scalar input must still record, got %v", err)
	}
	// fail-closed cap: 40 levels of clean nesting, no bad key, still refused.
	nested := validation.VObj()
	for range 40 {
		nested = validation.VObj(kv("l", nested))
	}
	if _, err := RecordEconomicImpact(c, fid, nested, validation.VNull(),
		validation.VNull()); err == nil ||
		!strings.Contains(err.Error(), "max nesting depth") {
		t.Fatalf("risk must refuse over-depth docs fail-closed, got %v", err)
	}
}

// TestMintImpactEvidence ports the E7 slices of tests/test_runbook_flow.py
// and tests/test_independent_verification.py.
func TestMintImpactEvidence(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	if _, err := RecordEconomicImpact(c, fid, validation.VInt(1_500_000),
		validation.VNull(), validation.VNull()); err != nil {
		t.Fatal(err)
	}
	art := writeArtifact(t, c)
	out, err := MintImpactEvidence(c, fid, art,
		"1.5M extractable given pool depth")
	if err != nil {
		t.Fatal(err)
	}
	var e7 validation.Value
	for _, e := range validation.ObjAt(out, "evidence").A {
		if validation.ObjStr(e, "level") == "E7" {
			e7 = e
		}
	}
	if e7.Kind != validation.Obj {
		t.Fatal("no E7 evidence item minted")
	}
	id := validation.ObjStr(e7, "evidence_id")
	if !strings.HasPrefix(id, "EV-") || len(id) != 11 {
		t.Errorf("evidence_id = %q; want EV-<8 hex>", id)
	}
	if got := validation.CanonCompact(e7); got != `{"artifact_id":"`+art+
		`","description":"1.5M extractable given pool depth","evidence_id":"`+id+
		`","level":"E7","produced_at":"2026-01-01T00:00:00.000000+00:00",`+
		`"snapshot_id":"unpinned","type":"balance-delta"}` {
		t.Errorf("E7 item = %s", got)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if validation.ObjStr(e, "type") != "finding.impact_quantified" {
			continue
		}
		if got := validation.CanonCompact(validation.ObjAt(e, "data")); got !=
			`{"artifact_id":"`+art+`","from_level":"E0"}` {
			t.Errorf("impact_quantified data = %s", got)
		}
	}
}

func TestMintImpactEvidenceErrors(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	_, err := MintImpactEvidence(c, fid, "ART-x", "desc")
	want := "cannot mint E7 on " + fid + ": no economic_impact numbers " +
		"recorded (set extractable_usd and/or max_loss_usd first)"
	if err == nil || err.Error() != want {
		t.Errorf("err = %v; want %q", err, want)
	}
	if _, err := RecordEconomicImpact(c, fid, validation.VInt(1_500_000),
		validation.VNull(), validation.VNull()); err != nil {
		t.Fatal(err)
	}
	_, err = MintImpactEvidence(c, fid, "ART-nope", "desc")
	if err == nil || err.Error() != "unknown artifact 'ART-nope'" {
		t.Errorf("err = %v; want the KeyError text", err)
	}
}

// writeArtifact registers one artifact row and returns its id.
func writeArtifact(t *testing.T, c *state.Campaign) string {
	t.Helper()
	p := filepath.Join(c.Root, "impact.json")
	if err := os.WriteFile(p, []byte(`{"delta": 1.5}`), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("economic-impact", p, "fork balance delta", nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// test_null_fields_still_fail_at_validation
// (tests/test_severity_split.py::I-2 companion): None-safety must not launder
// invalid data — a hand-nulled finding still fails at save_finding's
// validate() with SchemaError instead of crashing in the banding helpers.
func TestNullFieldsStillFailAtValidation(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	rc := validation.ObjAt(stored, "root_cause")
	rc.O = validation.SetOrAppend(rc.O, "description", validation.VNull())
	stored.O = validation.SetOrAppend(stored.O, "root_cause", rc)
	att := validation.ObjAt(stored, "attacker")
	att.O = validation.SetOrAppend(att.O, "required_privileges", validation.VNull())
	stored.O = validation.SetOrAppend(stored.O, "attacker", att)
	if err := validation.WriteJson(findings.FindingPath(c, fid), stored, ""); err != nil {
		t.Fatal(err)
	}
	_, err = Calibrate(c, fid)
	if err == nil {
		t.Fatal("calibrate must fail on a hand-nulled finding")
	}
	var se *validation.SchemaError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v; want *validation.SchemaError", err)
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("message = %q", err.Error())
	}
}

// test_reported_severity_is_inert (tests/test_severity_split.py) — the
// unit-level half. The campaign half needs findings.confirmation_gate_detail
// and bounty_policy.severity_for (unported).
func TestReportedSeverityIsInert(t *testing.T) {
	payload := func(sev string) validation.Value {
		return validation.VObj(
			kv("title", validation.VStr(
				"Flash-loan push of the TWAP lets a redeemer exit above NAV")),
			kv("reported_severity", validation.VStr(sev)),
			kv("root_cause", validation.VObj(
				kv("class", validation.VStr("oracle-manipulation")),
				kv("description", validation.VStr(
					"TWAP window exceeds the manipulation horizon"))),
			),
			kv("attacker", validation.VObj(
				kv("profile", validation.VStr("arbitrary EOA")),
				kv("capabilities", validation.VArr()),
				kv("required_privileges", validation.VArr()))),
			kv("economic_impact", validation.VObj(
				kv("blast_radius", validation.VStr("all-users")),
				kv("extractable_usd", validation.VInt(5_000_000)),
				kv("max_loss_usd", validation.VInt(20_000_000)))),
		)
	}
	lo, hi := payload("low"), payload("critical")
	loRisk, err := ValidatedRisk(lo)
	if err != nil {
		t.Fatal(err)
	}
	hiRisk, err := ValidatedRisk(hi)
	if err != nil {
		t.Fatal(err)
	}
	if canon(t, loRisk) != canon(t, hiRisk) {
		t.Errorf("validated_risk moved with the claim: %s vs %s",
			canon(t, loRisk), canon(t, hiRisk))
	}
	loIV, err := ImpactVector(lo)
	if err != nil {
		t.Fatal(err)
	}
	hiIV, err := ImpactVector(hi)
	if err != nil {
		t.Fatal(err)
	}
	if canon(t, loIV) != canon(t, hiIV) {
		t.Errorf("impact_vector moved with the claim: %s vs %s",
			canon(t, loIV), canon(t, hiIV))
	}
}
