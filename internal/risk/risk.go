// Package risk is the port of webv2/risk.py: three-pass risk calibration.
//
// Risk is computed at three distinct moments and each answers a different
// question — never one score:
//
//	prior_risk      (0..1, at triage)   "is this worth validating at all?"
//	validated_risk  (1..10, post-proof) "how bad is this, given the evidence?"
//	economic_risk   (USD, post-proof)   "what is actually extractable given
//	                                     on-chain liquidity?"
//	bounty_score    (advisory)          prioritization only; a score never
//	                                     replaces the evidence gate.
package risk

import (
	"fmt"
	"math"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// wBlast is _W_BLAST: deterministic weight table for validated_risk (1..10).
var wBlast = map[string]float64{
	"single-user": 1.0, "subset-of-users": 3.0, "all-users": 5.0,
	"protocol-solvency": 7.0, "bridge-canonical": 8.0,
}

// wLevel is _W_LEVEL, keyed by evidence level E0..E7.
var wLevel = map[string]float64{
	"E0": 0.0, "E1": 0.5, "E2": 1.0, "E3": 1.5, "E4": 2.0,
	"E5": 2.5, "E6": 3.0, "E7": 3.0,
}

// priorBase is the triage base table inside prior_risk.
var priorBase = map[string]float64{
	"access-control": 0.9, "authorization": 0.9, "upgrade-initializer": 0.85,
	"oracle-manipulation": 0.8, "flash-loan": 0.75, "share-price-inflation": 0.8,
	"bridge-message": 0.85, "cross-chain-replay": 0.85, "reentrancy": 0.7,
	"economic-invariant": 0.7, "liquidation-logic": 0.75, "precision-rounding": 0.5,
	"dos-griefing": 0.45, "logic-error": 0.5, "token-integration": 0.55,
}

// PriorRisk is prior_risk: cheap, explainable triage score in [0, 1].
// invariantID nil/empty and capitalUSD nil mirror Python's None.
func PriorRisk(bugClass string, reachableUnprivileged, requiresForkState,
	historicalAnalog bool, invariantID *string, capitalUSD *float64) validation.Value {
	base, ok := priorBase[bugClass]
	if !ok {
		base = 0.4
	}
	score := base
	factors := []string{"base(" + bugClass + ")=" + validation.PythonFloat(base)}
	if reachableUnprivileged {
		score += 0.1
		factors = append(factors, "unprivileged-reachable +0.1")
	}
	if historicalAnalog {
		score += 0.08
		factors = append(factors, "historical-analog +0.08")
	}
	if invariantID != nil && *invariantID != "" {
		score += 0.05
		factors = append(factors, "tied-to-invariant +0.05")
	}
	if capitalUSD != nil && *capitalUSD > 1_000_000 {
		score -= 0.05
		factors = append(factors, "high-capital-requirement -0.05")
	}
	if requiresForkState {
		score += 0.02
		factors = append(factors, "fork-state-dependent +0.02")
	}
	return validation.VObj(
		validation.KV{K: "score",
			V: validation.VFloat(validation.PythonRound(math.Min(score, 1.0), 3))},
		validation.KV{K: "factors", V: strArr(factors)},
	)
}

// ValidationCost is validation_cost: cheap / standard / expensive — used by
// the planner's decision rule.
func ValidationCost(class string, needsFork, needsSymbolic bool) string {
	if needsFork || class == "bridge-message" || class == "cross-chain-replay" {
		return "expensive"
	}
	if needsSymbolic || class == "economic-invariant" ||
		class == "oracle-manipulation" {
		return "standard"
	}
	return "cheap"
}

// AmplifierBonus is amplifier_bonus: advisory +0.5 per distinct amplifier in
// (playbook tags ∩ detected signals), capped at 1.0. A medium flaw touching
// two live amplifiers sorts above one that touches none — ordering context,
// never a gate.
func AmplifierBonus(playbookTags []string, detected validation.Value) (float64, []string) {
	tags := make(map[string]struct{}, len(playbookTags))
	for _, t := range playbookTags {
		tags[t] = struct{}{}
	}
	hit := []string{}
	for _, kv := range detected.O {
		if _, ok := tags[kv.K]; ok {
			hit = append(hit, kv.K)
		}
	}
	sort.Strings(hit)
	return validation.PythonRound(math.Min(0.5*float64(len(hit)), 1.0), 2), hit
}

// ValidatedRisk is validated_risk: deterministic 1..10 score from recorded
// finding fields. 10 = protocol-wide loss, independently reproduced, no
// controls. The band mapping follows Immunefi-style conventions.
func ValidatedRisk(finding validation.Value) (validation.Value, error) {
	score, rationale, err := validatedScore(finding)
	if err != nil {
		return validation.VNull(), err
	}
	score = math.Max(1.0, math.Min(10.0, score))
	return validation.VObj(
		validation.KV{K: "score",
			V: validation.VFloat(validation.PythonRound(score, 2))},
		validation.KV{K: "band", V: validation.VStr(riskBand(score))},
		validation.KV{K: "rationale", V: validation.VStr(strings.Join(rationale, "; "))},
	), nil
}

// validatedScore is the arithmetic half of validated_risk: the score before
// the 1..10 clamp plus the rationale lines in Python's append order.
func validatedScore(finding validation.Value) (float64, []string, error) {
	impact := orObj(objAt(finding, "economic_impact"))
	blast := blastRadius(impact)
	score := 2.0
	if w, ok := wBlast[blast]; ok {
		score = w
	}
	rationale := []string{"blast_radius(" + blast + ")=" + validation.PythonFloat(score)}
	level, err := findings.FindingLevel(finding)
	if err != nil {
		return 0, nil, err
	}
	lw := 0.5
	if w, ok := wLevel[level]; ok {
		lw = w
	}
	score += lw
	rationale = append(rationale, "evidence("+level+")=+"+validation.PythonFloat(lw))
	if n := pyLen(privilegesOf(finding)); n == 0 {
		score += 1.0
		rationale = append(rationale, "unprivileged-attacker +1.0")
	} else {
		rationale = append(rationale, fmt.Sprintf("privileged (%d) +0", n))
	}
	if ev, ok := fieldAt(impact, "extractable_usd"); ok && ev.Kind != validation.Null {
		usd, err := asFloat(ev)
		if err != nil {
			return 0, nil, err
		}
		bump := extractableBump(usd)
		score += bump
		rationale = append(rationale,
			"extractable($"+pyUsd0f(usd)+") +"+validation.PythonFloat(bump))
	}
	return score, rationale, nil
}

// extractableBump is the nested conditional in validated_risk.
func extractableBump(usd float64) float64 {
	switch {
	case usd >= 10_000_000:
		return 1.0
	case usd >= 1_000_000:
		return 0.7
	case usd >= 100_000:
		return 0.4
	case usd > 0:
		return 0.2
	}
	return 0.0
}

// riskBand is the band ladder at the tail of validated_risk.
func riskBand(score float64) string {
	switch {
	case score >= 8.5:
		return "critical"
	case score >= 6.5:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 2.0:
		return "low"
	}
	return "informational"
}

// blastRadius is impact.get("blast_radius", "subset-of-users"): the default
// applies only when the key is absent (a present null renders as "None").
func blastRadius(impact validation.Value) string {
	if v, ok := fieldAt(impact, "blast_radius"); ok {
		return pyStr(v)
	}
	return "subset-of-users"
}

// privilegesOf is (finding.get("attacker") or {}).get("required_privileges").
func privilegesOf(finding validation.Value) validation.Value {
	return objAt(orObj(objAt(finding, "attacker")), "required_privileges")
}

// EconomicRisk is economic_risk: theoretical exposure and realistic
// extraction are different numbers; both are recorded. The args are raw JSON
// values because Python passes the caller's int/float identity through to
// the result (an int stays an int in the stored finding).
func EconomicRisk(maxLossUSD, extractableUSD, capitalRequiredUSD validation.Value) validation.Value {
	out, _ := economicRisk(maxLossUSD, extractableUSD, capitalRequiredUSD)
	return out
}

// EconomicRiskFloat is the nil-tolerant numeric form of EconomicRisk for
// callers that hold Go floats (nil = Python None).
func EconomicRiskFloat(maxLossUSD, extractableUSD, capitalRequiredUSD *float64) validation.Value {
	out, _ := economicRisk(optNum(maxLossUSD), optNum(extractableUSD),
		optNum(capitalRequiredUSD))
	return out
}

// economicRisk is economic_risk on raw JSON values so that an int stays an
// int in the stored finding (Python passes impact.get(...) through).
func economicRisk(maxLoss, extractable, capital validation.Value) (validation.Value, error) {
	var lev validation.Value = validation.VNull()
	if extractable.Kind != validation.Null && capital.Kind != validation.Null &&
		!isZeroNum(capital) {
		ex, err := asFloat(extractable)
		if err != nil {
			return validation.VNull(), err
		}
		ca, err := asFloat(capital)
		if err != nil {
			return validation.VNull(), err
		}
		lev = validation.VFloat(validation.PythonRound(ex/ca, 3))
	}
	return validation.VObj(
		validation.KV{K: "extractable_usd", V: extractable},
		validation.KV{K: "capital_required_usd", V: capital},
		validation.KV{K: "leverage_ratio", V: lev},
		validation.KV{K: "notes", V: validation.VStr(
			"max_loss_usd recorded on economic_impact; extractable is bounded " +
				"by on-chain liquidity, not by the theoretical exposure")},
	), nil
}

// isZeroNum is Python's `capital_required_usd not in (None, 0)`: numeric
// zero (and -0.0, and false) compares equal to 0.
func isZeroNum(v validation.Value) bool {
	switch v.Kind {
	case validation.Int:
		return v.Big == "" && v.I == 0
	case validation.Flt:
		return v.F == 0
	case validation.Bool:
		return !v.B
	}
	return false
}

// BountyScore is bounty_score: advisory prioritization number in [0, 10].
// Deliberately simple: it orders human/compute attention, it does NOT decide
// submission. eligibility nil = Python None (not False).
func BountyScore(risk validation.Value, eligibility *bool, amplifierBonus float64) float64 {
	base := numOrZero(objAt(objAt(risk, "validated"), "score"))
	econ := numOrZero(objAt(objAt(risk, "economic"), "extractable_usd"))
	bonus := 0.0
	if econ >= 100_000 {
		bonus = 1.0
	} else if econ > 0 {
		bonus = 0.5
	}
	score := math.Min(10.0, base+bonus+math.Max(0.0, amplifierBonus))
	if eligibility != nil && !*eligibility {
		score = math.Min(score, 4.0)
	}
	return validation.PythonRound(score, 2)
}

// strArr renders a []string as a JSON array value.
func strArr(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

// ---- impact vector: the computed half of severity -------------------------
// The model's self-assessed severity is data (reported_severity), not a
// verdict. This vector is what the framework computes from recorded fields:
// four named components, each banded, each weighted. Advisory — display-only
// in the report, never the confirmation gate, ordering, or validated_risk.

// assetExposureBands is _ASSET_EXPOSURE_BANDS in order.
var assetExposureBands = []struct {
	floor float64
	band  string
}{
	{10_000_000, "gt_10m"}, {1_000_000, "1m_10m"},
	{100_000, "100k_1m"}, {0, "lt_100k"},
}

// impactWeights is _IMPACT_BAND_WEIGHTS.
var impactWeights = map[string]map[string]float64{
	"asset_exposure": {"none": 0.0, "lt_100k": 1.0, "100k_1m": 2.5,
		"1m_10m": 4.5, "gt_10m": 6.0},
	"privilege_class": {"unprivileged": 3.0, "semi-privileged": 1.5,
		"role": 1.0, "owner": 0.5},
	"recoverability":  {"unknown": 1.0, "low": 2.5, "medium": 1.5, "high": 0.5},
	"insolvency_risk": {"low": 0.5, "medium": 2.0, "high": 3.5},
}

var (
	// privOwnerRe / privRoleRe are _PRIV_OWNER_RE / _PRIV_ROLE_RE.
	privOwnerRe = regexp.MustCompile(`(?i)(owner|admin|guardian)`)
	privRoleRe  = regexp.MustCompile(`(?i)(role|governor|pauser|minter)`)
	// insolvencyRe is _INSOLVENCY_RE. Python's \b is Unicode-aware (a word
	// char is alphanumeric or "_") while RE2's \b is ASCII-only, so
	// \bpools?\b is spelled with an explicit boundary class — the same
	// convention as internal/findings (claimHalfRe) and internal/sandbox.
	insolvencyRe = regexp.MustCompile(`(?i)(liquidity|` +
		`(?:^|[^\p{L}\p{N}\p{Pc}])pools?(?:$|[^\p{L}\p{N}\p{Pc}])|` +
		`tvls?|insolven|drain)`)
)

// ImpactVector is impact_vector: the computed half of severity — four named
// components plus the weighted score. Keeping reported_severity and this
// vector both visible makes divergence a signal instead of hiding it.
func ImpactVector(finding validation.Value) (validation.Value, error) {
	rec, err := recoverability(finding)
	if err != nil {
		return validation.VNull(), err
	}
	ae := assetExposure(finding)
	pc := privilegeClass(finding)
	ir := insolvencyRisk(finding)
	// Summation order is Python's generator order; float addition is not
	// associative, so it is part of the contract.
	score := impactWeights["asset_exposure"][ae] +
		impactWeights["privilege_class"][pc] +
		impactWeights["recoverability"][rec] +
		impactWeights["insolvency_risk"][ir]
	return validation.VObj(
		validation.KV{K: "asset_exposure", V: validation.VStr(ae)},
		validation.KV{K: "privilege_class", V: validation.VStr(pc)},
		validation.KV{K: "recoverability", V: validation.VStr(rec)},
		validation.KV{K: "insolvency_risk", V: validation.VStr(ir)},
		validation.KV{K: "score",
			V: validation.VFloat(validation.PythonRound(score, 2))},
	), nil
}

// assetExposure is _asset_exposure: band the max recorded USD exposure into a
// coarse size bucket.
func assetExposure(finding validation.Value) string {
	usd, ok := maxExposure(orObj(objAt(finding, "economic_impact")))
	if !ok {
		return "none"
	}
	for _, b := range assetExposureBands {
		if usd >= b.floor {
			return b.band
		}
	}
	return "lt_100k"
}

// maxExposure is max([extractable_usd, max_loss_usd] non-None, default=None).
func maxExposure(imp validation.Value) (float64, bool) {
	best, found := 0.0, false
	for _, key := range []string{"extractable_usd", "max_loss_usd"} {
		v, ok := fieldAt(imp, key)
		if !ok || v.Kind == validation.Null {
			continue
		}
		f, err := asFloat(v)
		if err != nil {
			continue // schema-typed number; Python would raise TypeError
		}
		if !found || f > best {
			best, found = f, true
		}
	}
	return best, found
}

// privilegeClass is _privilege_class: classify the cheapest attacker
// privilege from recorded privilege text.
//
// WHY role is checked before owner: identifiers like DEFAULT_ADMIN_ROLE
// contain both signals and the role reading is the precise one; keeper-style
// operational actors (e.g. "keeper-set via governance queue") match neither
// pattern and fall through to semi-privileged.
func privilegeClass(finding validation.Value) string {
	text := privText(privilegesOf(finding))
	if pyStrip(text) == "" {
		return "unprivileged"
	}
	if privRoleRe.MatchString(text) {
		return "role"
	}
	if privOwnerRe.MatchString(text) {
		return "owner"
	}
	return "semi-privileged"
}

// privText is " ".join(str(p) for p in privs if p is not None). A bare
// string iterates char by char in Python, so it does here too.
func privText(privs validation.Value) string {
	switch privs.Kind {
	case validation.Arr:
		parts := make([]string, 0, len(privs.A))
		for _, p := range privs.A {
			if p.Kind != validation.Null {
				parts = append(parts, pyStr(p))
			}
		}
		return strings.Join(parts, " ")
	case validation.Str:
		parts := []string{}
		for _, r := range privs.S {
			parts = append(parts, string(r))
		}
		return strings.Join(parts, " ")
	}
	return ""
}

// recoverability is _recoverability: band attacker-cost recoverability from
// the recorded capital profile.
func recoverability(finding validation.Value) (string, error) {
	cap := orObj(objAt(orObj(objAt(finding, "attacker")), "capital_profile"))
	rec, recSet, err := optNumAt(cap, "recoverable_usd")
	if err != nil {
		return "", err
	}
	irr, irrSet, err := optNumAt(cap, "irrecoverable_cost_usd")
	if err != nil {
		return "", err
	}
	if !recSet && !irrSet {
		return "unknown", nil
	}
	if rec >= 1.0 && irr == 0 {
		return "high", nil
	}
	if rec > 0 {
		return "medium", nil
	}
	return "low", nil
}

// insolvencyRisk is _insolvency_risk: band protocol-solvency risk from claim
// text and loss/gain ratio.
func insolvencyRisk(finding validation.Value) string {
	text := orStr(objAt(orObj(objAt(finding, "root_cause")), "description")) +
		" " + orStr(objAt(finding, "title"))
	if insolvencyRe.MatchString(text) {
		return "high"
	}
	imp := orObj(objAt(finding, "economic_impact"))
	ex := numOrZero(objAt(imp, "extractable_usd"))
	ml := numOrZero(objAt(imp, "max_loss_usd"))
	if ex != 0 && ml != 0 && ml >= 10*ex {
		return "medium"
	}
	return "low"
}

// ---- campaign operations -------------------------------------------------

// RecordEconomicImpact is record_economic_impact: record quantified impact
// numbers on a finding, then recalibrate. Each number is a validation.Value
// so Python's None (VNull) and the int-vs-float identity of the caller's
// kwarg survive: the finding stores float(v), the event keeps the literal.
func RecordEconomicImpact(campaign *state.Campaign, findingID string,
	extractableUSD, maxLossUSD, requiredCapitalUSD validation.Value) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ii, err := ensureObjField(&f.O, "economic_impact")
	if err != nil {
		return validation.VNull(), err
	}
	impact := &f.O[ii].V.O
	if err := setFloatField(impact, "extractable_usd", extractableUSD); err != nil {
		return validation.VNull(), err
	}
	if err := setFloatField(impact, "max_loss_usd", maxLossUSD); err != nil {
		return validation.VNull(), err
	}
	if requiredCapitalUSD.Kind != validation.Null {
		ai, err := ensureObjField(&f.O, "attacker")
		if err != nil {
			return validation.VNull(), err
		}
		if err := setFloatField(&f.O[ai].V.O, "required_capital_usd",
			requiredCapitalUSD); err != nil {
			return validation.VNull(), err
		}
	}
	if err := findings.SaveFinding(campaign, &f); err != nil {
		return validation.VNull(), err
	}
	if _, err := Calibrate(campaign, findingID); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "extractable_usd", V: extractableUSD},
		validation.KV{K: "max_loss_usd", V: maxLossUSD},
	)
	if _, err := campaign.Log("finding.impact_recorded", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return findings.LoadFinding(campaign, findingID)
}

// Calibrate is calibrate: compute and store all three passes plus the
// advisory impact vector, then log finding.calibrated.
func Calibrate(campaign *state.Campaign, findingID string) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	impact := orObj(objAt(f, "economic_impact"))
	ri, err := ensureObjField(&f.O, "risk")
	if err != nil {
		return validation.VNull(), err
	}
	riskV := f.O[ri].V
	validated, err := ValidatedRisk(f)
	if err != nil {
		return validation.VNull(), err
	}
	riskV.O = setOrAppend(riskV.O, "validated", validated)
	econ, err := economicRisk(objAt(impact, "max_loss_usd"),
		objAt(impact, "extractable_usd"),
		objAt(orObj(objAt(f, "attacker")), "required_capital_usd"))
	if err != nil {
		return validation.VNull(), err
	}
	riskV.O = setOrAppend(riskV.O, "economic", econ)
	iv, err := ImpactVector(f)
	if err != nil {
		return validation.VNull(), err
	}
	riskV.O = setOrAppend(riskV.O, "impact_vector", iv)
	f.O[ri].V = riskV
	if err := findings.SaveFinding(campaign, &f); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(validation.KV{K: "band", V: objAt(validated, "band")})
	if _, err := campaign.Log("finding.calibrated", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return riskV, nil
}

// MintImpactEvidence is mint_impact_evidence: mint E7 — the economic impact
// is quantified against a recorded artifact. E7 is ANALYSIS evidence (no
// execution created it), so instead of a sandbox profile it must cite an
// artifact registered in this campaign.
func MintImpactEvidence(campaign *state.Campaign, findingID, artifactID,
	description string) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	impact := orObj(objAt(f, "economic_impact"))
	if isNoneField(impact, "extractable_usd") && isNoneField(impact, "max_loss_usd") {
		return validation.VNull(), fmt.Errorf("cannot mint E7 on %s: no "+
			"economic_impact numbers recorded (set extractable_usd and/or "+
			"max_loss_usd first)", findingID)
	}
	if _, err := campaign.Artifact(artifactID); err != nil {
		return validation.VNull(), err
	}
	level, err := findings.FindingLevel(f)
	if err != nil {
		return validation.VNull(), err
	}
	item := validation.VObj(
		validation.KV{K: "evidence_id",
			V: validation.VStr("EV-" + idTail(state.NewID("x", 8)))},
		validation.KV{K: "level", V: validation.VStr("E7")},
		validation.KV{K: "type", V: validation.VStr("balance-delta")},
		validation.KV{K: "artifact_id", V: validation.VStr(artifactID)},
		validation.KV{K: "description", V: validation.VStr(description)},
		validation.KV{K: "produced_at", V: validation.VStr(nowIso())},
		validation.KV{K: "snapshot_id", V: snapshotSource(f)},
	)
	out, err := findings.AddEvidence(campaign, findingID, item)
	if err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "artifact_id", V: validation.VStr(artifactID)},
		validation.KV{K: "from_level", V: validation.VStr(level)},
	)
	if _, err := campaign.Log("finding.impact_quantified", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return out, nil
}

// ---- helpers -------------------------------------------------------------

// objAt is d.get(key) as a Value: a missing key reads as Null.
func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// fieldAt is d.get(key) with presence: (value, true) also for a present null.
func fieldAt(v validation.Value, key string) (validation.Value, bool) {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// orObj is Python's `v or {}` for the object fields read by the banding
// helpers: a missing/null/falsy value reads as an empty object.
func orObj(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return v
	}
	return validation.VObj()
}

// orStr is Python's `v or ""` for the text fields.
func orStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// isNoneField is `d.get(key) is None`: absent or present-null.
func isNoneField(v validation.Value, key string) bool {
	got, ok := fieldAt(v, key)
	return !ok || got.Kind == validation.Null
}

// snapshotSource is f.get("snapshot_ids", {}).get("source").
func snapshotSource(f validation.Value) validation.Value {
	return objAt(orObj(objAt(f, "snapshot_ids")), "source")
}

// idTail is new_id(prefix, n).split("-")[1].
func idTail(id string) string {
	parts := strings.SplitN(id, "-", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// ensureObjField is dict.setdefault(key, {}): the index of key in o, with an
// empty object appended when absent. A present non-object value reproduces
// Python's TypeError on the following item assignment.
func ensureObjField(o *[]validation.KV, key string) (int, error) {
	for i := range *o {
		if (*o)[i].K == key {
			if (*o)[i].V.Kind != validation.Obj {
				return 0, fmt.Errorf("'%s' object does not support item "+
					"assignment", pyTypeName((*o)[i].V))
			}
			return i, nil
		}
	}
	*o = append(*o, validation.KV{K: key, V: validation.VObj()})
	return len(*o) - 1, nil
}

// setFloatField is d[key] = float(v), skipped for Python None.
func setFloatField(o *[]validation.KV, key string, v validation.Value) error {
	if v.Kind == validation.Null {
		return nil
	}
	f, err := asFloat(v)
	if err != nil {
		return err
	}
	*o = setOrAppend(*o, key, validation.VFloat(f))
	return nil
}

// setOrAppend mirrors Python dict assignment: an existing key is replaced in
// place (position kept), a new key is appended at the end.
func setOrAppend(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, validation.KV{K: key, V: v})
}

// optNum is Python Optional[float] as a Value.
func optNum(f *float64) validation.Value {
	if f == nil {
		return validation.VNull()
	}
	return validation.VFloat(*f)
}

// optNumAt is (obj.get(key) or 0) as a float, plus "the key was present and
// not None". Falsy scalars (0, 0.0, "", false) read as 0.
func optNumAt(obj validation.Value, key string) (float64, bool, error) {
	v, ok := fieldAt(obj, key)
	if !ok || v.Kind == validation.Null {
		return 0, false, nil
	}
	if !pyTruthy(v) {
		return 0, true, nil
	}
	f, err := asFloat(v)
	if err != nil {
		return 0, true, err
	}
	return f, true, nil
}

// numOrZero is `v or 0` as a float for the comparison helpers.
func numOrZero(v validation.Value) float64 {
	if !pyTruthy(v) {
		return 0
	}
	f, err := asFloat(v)
	if err != nil {
		return 0 // schema-typed number; Python would raise TypeError
	}
	return f
}

// pyTruthy is Python bool(v).
func pyTruthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.Big != "" || v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

// pyLen is Python len(v) for the sequence kinds (str counts code points).
func pyLen(v validation.Value) int {
	switch v.Kind {
	case validation.Arr:
		return len(v.A)
	case validation.Obj:
		return len(v.O)
	case validation.Str:
		return utf8.RuneCountInString(v.S)
	}
	return 0
}

// pyStr is Python str(v) for the JSON scalar kinds.
func pyStr(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	case validation.Str:
		return v.S
	}
	return validation.PyRepr(v)
}

// pyTypeName is type(v).__name__ for the JSON kinds.
func pyTypeName(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "NoneType"
	case validation.Bool:
		return "bool"
	case validation.Int:
		return "int"
	case validation.Flt:
		return "float"
	case validation.Str:
		return "str"
	case validation.Arr:
		return "list"
	case validation.Obj:
		return "dict"
	}
	return "object"
}

// asFloat is Python float(v) for the JSON scalar kinds; the error text
// mirrors CPython's ValueError / TypeError wording.
func asFloat(v validation.Value) (float64, error) {
	switch v.Kind {
	case validation.Flt:
		return v.F, nil
	case validation.Int:
		if v.Big != "" {
			f, err := strconv.ParseFloat(v.Big, 64)
			if err != nil {
				return 0, fmt.Errorf("int too large to convert to float")
			}
			return f, nil
		}
		return float64(v.I), nil
	case validation.Bool:
		if v.B {
			return 1, nil
		}
		return 0, nil
	case validation.Str:
		f, err := strconv.ParseFloat(pyStrip(v.S), 64)
		if err != nil {
			return 0, fmt.Errorf("could not convert string to float: %s",
				validation.PyReprStr(v.S))
		}
		return f, nil
	}
	return 0, fmt.Errorf("float() argument must be a string or a real "+
		"number, not '%s'", pyTypeName(v))
}

// pyUsd0f is Python's f"{x:,.0f}": thousands-grouped, zero decimals,
// round-half-even on the exact binary value (so 0.5 -> "0", 99_999.5 ->
// "100,000"), with CPython's nan/inf spellings and a signed "-0".
func pyUsd0f(x float64) string {
	switch {
	case math.IsNaN(x):
		return "nan"
	case math.IsInf(x, 1):
		return "inf"
	case math.IsInf(x, -1):
		return "-inf"
	}
	r := validation.PythonRound(x, 0)
	neg := math.Signbit(r)
	if r == 0 {
		if neg {
			return "-0"
		}
		return "0"
	}
	i, _ := new(big.Float).SetFloat64(math.Abs(r)).Int(nil)
	digits := groupThousands(i.String())
	if neg {
		return "-" + digits
	}
	return digits
}

// groupThousands inserts "," every three digits from the right.
func groupThousands(digits string) string {
	if len(digits) <= 3 {
		return digits
	}
	var b strings.Builder
	lead := len(digits) % 3
	if lead > 0 {
		b.WriteString(digits[:lead])
	}
	for i := lead; i < len(digits); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(digits[i : i+3])
	}
	return b.String()
}

// pyStrip is Python's str.strip() with no argument: trim str.isspace()
// characters from both ends.
func pyStrip(s string) string {
	return strings.TrimFunc(s, pySpace)
}

// pySpace is Py_UNICODE_ISSPACE: the Unicode White_Space property plus the
// ASCII file separators U+001C-U+001F (Python's str.isspace() says true
// there, unicode.IsSpace does not).
func pySpace(r rune) bool {
	if r >= 0x1c && r <= 0x1f {
		return true
	}
	return unicode.IsSpace(r)
}

// nowIso is now_iso (mirrors state.nowIso, unexported there). The WEBV2_NOW
// golden-suite clock pin is honored identically.
func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}
