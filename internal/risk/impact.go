// Risk — impact vector: asset exposure, privilege class, recoverability and insolvency (split from risk.go; pure structural move).

package risk

import (
	"regexp"
	"strings"

	"websec/internal/validation"
)

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
	usd, ok := maxExposure(orObj(validation.ObjAt(finding, "economic_impact")))
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
	if validation.PyStrip(text) == "" {
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
				parts = append(parts, validation.PyStr(p))
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
	cap := orObj(validation.ObjAt(orObj(validation.ObjAt(finding, "attacker")), "capital_profile"))
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
	text := orStr(validation.ObjAt(orObj(validation.ObjAt(finding, "root_cause")), "description")) +
		" " + orStr(validation.ObjAt(finding, "title"))
	if insolvencyRe.MatchString(text) {
		return "high"
	}
	imp := orObj(validation.ObjAt(finding, "economic_impact"))
	ex := numOrZero(validation.ObjAt(imp, "extractable_usd"))
	ml := numOrZero(validation.ObjAt(imp, "max_loss_usd"))
	if ex != 0 && ml != 0 && ml >= 10*ex {
		return "medium"
	}
	return "low"
}

// ---- campaign operations -------------------------------------------------
