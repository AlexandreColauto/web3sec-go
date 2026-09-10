// Package bounty ports webv2.bounty_policy: the bounty policy engine + the
// final gate.
//
// "Is this a real bug" and "is this submission-ready against THIS program's
// rules" are different questions. This package answers the second one,
// deterministically, from a machine-readable policy:
//
//	SECURITY CONFIRMED + BOUNTY ELIGIBLE + EVIDENCE SUFFICIENT = SUBMISSION READY
//
// The matching is deliberately simple (substring/keyword on class, title,
// description) so behavior is predictable and testable. `unknown` results are
// surface for human review, never treated as pass. Always read the actual
// program page before submitting — known-issue and severity-floor calls are
// the two checks most likely to need human judgment.
package bounty

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"websec/internal/findings"
	"websec/internal/pricing"
	"websec/internal/state"
	"websec/internal/validation"
)

// pyLower is str.lower() under the Python default locale — the same emulation
// findings uses (a plain strings.ToLower is not Python's case mapping).
var pyLower = cases.Lower(language.Und)

// objAt is the dict lookup: the value for key, or Null when the key is absent
// (or the receiver is not an object).
func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// objStr is the string flavor of objAt ("" when absent or not a string).
func objStr(v validation.Value, key string) string {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V.S
		}
	}
	return ""
}

// fieldAt is (key in obj, obj[key]): the present-but-null case is distinct
// from the absent case.
func fieldAt(v validation.Value, key string) (validation.Value, bool) {
	if v.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// getDefault is obj.get(key, def): the value when the key is present (a
// present null is NOT replaced), def when it is absent.
func getDefault(v validation.Value, key string, def validation.Value) validation.Value {
	if got, ok := fieldAt(v, key); ok {
		return got
	}
	return def
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

// pyTruthy is Python truthiness for a JSON value.
func pyTruthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
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

// pyStrAny is f-string interpolation of a value: str(v). A string is itself;
// everything else is the Python repr (which equals str for null, bool,
// numbers, lists and dicts).
func pyStrAny(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
}

// pyFloat is isinstance(v, (int, float)) as a float64 (bool included, as in
// Python; a big int is parsed best-effort).
func pyFloat(v validation.Value) (float64, bool) {
	switch v.Kind {
	case validation.Int:
		if v.Big != "" {
			f, err := strconv.ParseFloat(v.Big, 64)
			if err != nil {
				return 0, false
			}
			return f, true
		}
		return float64(v.I), true
	case validation.Flt:
		return v.F, true
	case validation.Bool:
		if v.B {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// pyListRepr renders a list of strings in Python's list-literal form
// (["a", "b"] with repr quoting), which is what an f-string prints.
func pyListRepr(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = validation.PyReprStr(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// headRunes is s[:n] — a Python slice counts characters (runes).
func headRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// LoadPolicy is load_policy: read + schema-validate a program policy.
func LoadPolicy(path string) (validation.Value, error) {
	policy, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	if err := validation.Validate(policy, "bounty_policy", 1); err != nil {
		return validation.VNull(), err
	}
	return policy, nil
}

// SavePolicy is save_policy: validate, then write to *path (default
// <campaign.dir>/bounty_policy.json) and return the path written. A nil or
// empty path selects the campaign default.
func SavePolicy(campaign *state.Campaign, policy validation.Value,
	path *string) (string, error) {
	if err := validation.Validate(policy, "bounty_policy", 1); err != nil {
		return "", err
	}
	p := filepath.Join(campaign.Dir, "bounty_policy.json")
	if path != nil && *path != "" {
		p = *path
	}
	if err := validation.WriteJson(p, policy, ""); err != nil {
		return "", err
	}
	return p, nil
}

// InScope is in_scope: substring scope match on contract name / path /
// address. The bool is the match; the string is the human-facing why.
func InScope(policy validation.Value, target string) (bool, string, error) {
	t := pyLower.String(target)
	for _, s := range objAt(policy, "scope").A {
		needleV, ok := fieldAt(s, "target")
		if !ok {
			return false, "", fmt.Errorf("%s", validation.PyReprStr("target"))
		}
		needle := pyLower.String(needleV.S)
		if needle != "" && strings.Contains(t, needle) {
			return true, "matched scope entry " + validation.PyRepr(needleV), nil
		}
	}
	return false, validation.PyReprStr(target) + " matches no scope entry", nil
}

// textHit is _text_hit: substring match, case-insensitive by default.
func textHit(text, pattern string, caseSensitive bool) bool {
	if caseSensitive {
		return strings.Contains(text, pattern)
	}
	return strings.Contains(pyLower.String(text), pyLower.String(pattern))
}

// ExclusionHit is exclusion_hit: the first exclusion whose pattern matches
// class/title/desc/mechanism, or Null (Python None).
func ExclusionHit(policy, finding validation.Value) (validation.Value, error) {
	root := objAt(finding, "root_cause")
	haystacks := strings.Join([]string{
		objStr(root, "class"),
		objStr(finding, "title"),
		objStr(root, "description"),
		objStr(root, "mechanism"),
	}, " \n")
	for _, ex := range objAt(policy, "exclusions").A {
		pattern, ok := fieldAt(ex, "pattern")
		if !ok {
			return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr("pattern"))
		}
		if textHit(haystacks, pattern.S, pyTruthy(objAt(ex, "case_sensitive"))) {
			return ex, nil
		}
	}
	return validation.VNull(), nil
}

// AcceptedRiskHit is accepted_risk_hit: the first accepted_risks entry whose
// pattern matches class/title/desc/mechanism (the same haystack and text
// semantics as exclusions), or Null. Accepted risks are the program's
// "we know, we accept, we do not pay" channel (IMPROVEMENTS A1).
func AcceptedRiskHit(policy, finding validation.Value) (validation.Value, error) {
	root := objAt(finding, "root_cause")
	haystacks := strings.Join([]string{
		objStr(root, "class"),
		objStr(finding, "title"),
		objStr(root, "description"),
		objStr(root, "mechanism"),
	}, " \n")
	for _, ar := range objAt(policy, "accepted_risks").A {
		pattern, ok := fieldAt(ar, "pattern")
		if !ok {
			return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr("pattern"))
		}
		if textHit(haystacks, pattern.S, pyTruthy(objAt(ar, "case_sensitive"))) {
			return ar, nil
		}
	}
	return validation.VNull(), nil
}

// severityRank orders the band names for the accepted-risk min_severity cap
// (0 = no severity assigned — the acceptance still applies).
func severityRank(sev string) int {
	switch sev {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return 0
}

// SeverityFor is severity_for: deterministic severity from policy rules — the
// highest severity whose match block is satisfied by the finding. The
// severity is "" for Python None.
func SeverityFor(policy, finding validation.Value) (string, string, error) {
	impact := objAt(finding, "economic_impact")
	class := objStr(objAt(finding, "root_cause"), "class")
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		for _, rule := range objAt(policy, "severity_rules").A {
			sevV, ok := fieldAt(rule, "severity")
			if !ok {
				return "", "", fmt.Errorf("%s", validation.PyReprStr("severity"))
			}
			if sevV.S != sev {
				continue
			}
			m := objAt(rule, "match")
			if bc := objAt(m, "bug_classes"); pyTruthy(bc) && !inStringList(bc, class) {
				continue
			}
			if br := objAt(m, "blast_radius"); pyTruthy(br) &&
				!inStringList(br, objStr(impact, "blast_radius")) {
				continue
			}
			if minUsd := objAt(m, "min_extractable_usd"); minUsd.Kind != validation.Null {
				got, okGot := pyFloat(objAt(impact, "extractable_usd"))
				floor, okFloor := pyFloat(minUsd)
				if !okGot {
					got = 0
				}
				if !okFloor || got < floor {
					continue
				}
			}
			if pyTruthy(objAt(m, "require_invariant_violation")) &&
				!pyTruthy(objAt(objAt(finding, "invariant"), "violation_demonstrated")) {
				continue
			}
			return sev, "matched severity rule for " + sev, nil
		}
	}
	return "", "no severity rule matched", nil
}

// inStringList is `needle in list` for a JSON array of strings.
func inStringList(list validation.Value, needle string) bool {
	for _, e := range list.A {
		if e.Kind == validation.Str && e.S == needle {
			return true
		}
	}
	return false
}

// BountyRemediation is BOUNTY_REMEDIATION: every failing bounty gate check
// carries a REMEDIATION — the exact command that clears it. `webv2 gate
// explain <check>` shows these without a run.
var BountyRemediation = map[string]string{
	"security-confirmed":   "webv2 verdict <fid> confirmed ... + webv2 recall <campaign> --finding <fid> + webv2 mint <fid> --exec <EXEC>  (see `webv2 gate explain` for the full CONFIRMED checklist)",
	"snapshot-pinned":      "webv2 snap   (re-pin, then re-run the gate)",
	"in-scope":             "re-check the target against the program scope; if it is a different component, re-aim the hypothesis",
	"known-issue-check":    "read the matched exclusion on the program page \u2014 if it truly does not apply, record the reasoning in the report; if it does, drop the finding (webv2 status <fid> OUT_OF_SCOPE ...)",
	"severity-floor":       "quantify the impact (economic_impact) so a severity rule matches, or read the program's terms for the band",
	"evidence-sufficient":  "webv2 mint <fid> --exec <EXEC>   (reproduce at the required tier)",
	"fork-repro":           "webv2 mint <fid> --exec <EXEC>   (a T3/T4 fork reproduction)",
	"economic-quantified":  "set economic_impact.extractable_usd from a MEASURED PoC run, priced against the campaign price table (webv2 price set ...)",
	"maximal-exploitation": "webv2 ladder start <fid> ... webv2 ladder complete <fid>   (or: webv2 ladder waive <fid> --reason '...' \u2014 the named escape hatch)",
	"e7-price-basis":       "webv2 price set <asset> <usd> --source '<where the price came from>' then webv2 price-basis <fid> <PRICE-ID>   (USD figures must name their price row \u2014 no unattributed $)",
	"claim-drift":          "make the claim and the measurement agree: fix the title, or re-run the PoC and re-measure extraction_ratio",
	"precondition-audit":   "webv2 ladder add <fid> ... --removes '<precondition>' then webv2 ladder repro <fid> <rung> --exec <EXEC>   (or: webv2 shield the precondition as code-enforced if the PoC assumption was wrong)",
	"mainnet-fork-poc":     "webv2 exec <campaign> --profile fork-runner --command 'forge test --fork-url <pinned-rpc> --fork-block-number <pin> --match-test test_exploit' --finding <fid>   then webv2 mint <fid> --exec <EXEC-ID> --type fork-test   (unit tests prove semantics; only the fork proves mainnet)",
	"immunization":         "webv2 immunize <fid> --poc-exec <FORK-EXEC-ID> --patch '<the fix>' --mutations 'm1;m2;m3'   (the patch must block the FORK PoC and all 3 boundary mutations \u2014 a unit-test patch is not a patch; if a bypass is real, fix the patch and re-verify)",
	"accepted-risk":        "the program documented this as an accepted risk \u2014 not a payable vulnerability as written. If this particular finding IS payable despite the acceptance, record the decision: webv2 waive <campaign> accepted-risk --subject <fid> --reason 'why this one is payable' --actor <who>   (or: drop the finding \u2014 webv2 status <fid> OUT_OF_SCOPE \u2014 if it is genuinely the accepted behavior)",
}

// GateExplain is gate_explain: human-facing explanation + remediation for one
// check id — the `webv2 gate explain` backend. Covers both the CONFIRMED gate
// (findings) and the bounty gate; an unknown id is a loud KeyError, not a
// guess.
func GateExplain(checkID string) (validation.Value, error) {
	if rem, ok := confirmedRemediation[checkID]; ok {
		return validation.VObj(
			validation.KV{K: "check", V: validation.VStr(checkID)},
			validation.KV{K: "gate", V: validation.VStr("confirmed")},
			validation.KV{K: "remediation", V: validation.VStr(rem)},
		), nil
	}
	if rem, ok := BountyRemediation[checkID]; ok {
		return validation.VObj(
			validation.KV{K: "check", V: validation.VStr(checkID)},
			validation.KV{K: "gate", V: validation.VStr("bounty")},
			validation.KV{K: "remediation", V: validation.VStr(rem)},
		), nil
	}
	known := make([]string, 0, len(confirmedRemediation)+len(BountyRemediation))
	for k := range confirmedRemediation {
		known = append(known, k)
	}
	for k := range BountyRemediation {
		known = append(known, k)
	}
	sort.Strings(known)
	// dedupe: the two maps can share a check id (claim-drift is in both).
	var uniq []string
	for i, k := range known {
		if i == 0 || known[i-1] != k {
			uniq = append(uniq, k)
		}
	}
	msg := fmt.Sprintf("unknown check id %s (known: %s)",
		validation.PyReprStr(checkID), pyListRepr(uniq))
	return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(msg))
}

// --- seams for modules that are not ported yet (rule 5) --------------------
//
// maximization.load_ladder, fork_poc.fork_poc_status, completion.waivers and
// immunize.immunization_detail are P1+ modules. Each seam below has a safe
// default equal to the Python behavior on data those modules have not
// produced yet (no ladder, no proven fork PoC, no waivers, no patch
// verification). pricing.price_row and findings.GATE_REMEDIATION are ported,
// so those two defaults call the real modules.

var (
	loadLadderFunc = func(c *state.Campaign, findingID string) (validation.Value, error) {
		return validation.VNull(), nil
	}
	priceRowFunc = func(c *state.Campaign, priceID string) (validation.Value, error) {
		row, err := pricing.PriceRow(c, priceID)
		if err != nil {
			return validation.VNull(), err
		}
		if row == nil {
			return validation.VNull(), nil
		}
		return *row, nil
	}
	forkPocStatusFunc = func(c *state.Campaign, findingID string) (bool, string, error) {
		return false, "no fork PoC proven", nil
	}
	waiversFunc = func(c *state.Campaign, stage string) ([]validation.Value, error) {
		return nil, nil
	}
	immunizationDetailFunc = func(f validation.Value) (string, string) {
		return "missing", "no patch verification recorded (webv2 immunize " +
			"... against the FORK PoC)"
	}
	// B4: contract-name → source-path resolver for the scope check. The
	// default is a no-op (empty) — the real resolver (structidx) is wired by
	// the CLI's ensureSeams, which is the top module free of the
	// structidx→orchestrator→bounty import cycle. When it returns empty the
	// scope check falls back to name-only matching (the pre-B4 behaviour).
	contractPathFunc = func(*state.Campaign, string) string { return "" }
	confirmedRemediation = findings.GATE_REMEDIATION
)

// SetLoadLadder installs maximization.load_ladder; nil restores the default.
func SetLoadLadder(f func(*state.Campaign, string) (validation.Value, error)) {
	if f == nil {
		f = func(c *state.Campaign, findingID string) (validation.Value, error) {
			return validation.VNull(), nil
		}
	}
	loadLadderFunc = f
}

// SetPriceRow overrides pricing.price_row; nil restores the default (the
// ported pricing module).
func SetPriceRow(f func(*state.Campaign, string) (validation.Value, error)) {
	if f == nil {
		f = func(c *state.Campaign, priceID string) (validation.Value, error) {
			row, err := pricing.PriceRow(c, priceID)
			if err != nil {
				return validation.VNull(), err
			}
			if row == nil {
				return validation.VNull(), nil
			}
			return *row, nil
		}
	}
	priceRowFunc = f
}

// SetForkPocStatus installs fork_poc.fork_poc_status; nil restores the
// default (not proven, "no fork PoC proven" — the module's literal fallback;
// its real reason text is one of three ledger-dependent messages).
func SetForkPocStatus(f func(*state.Campaign, string) (bool, string, error)) {
	if f == nil {
		f = func(c *state.Campaign, findingID string) (bool, string, error) {
			return false, "no fork PoC proven", nil
		}
	}
	forkPocStatusFunc = f
}

// SetWaivers installs completion.waivers; nil restores the default (none).
func SetWaivers(f func(*state.Campaign, string) ([]validation.Value, error)) {
	if f == nil {
		f = func(c *state.Campaign, stage string) ([]validation.Value, error) {
			return nil, nil
		}
	}
	waiversFunc = f
}

// SetImmunizationDetail installs immunize.immunization_detail; nil restores
// the default (the no-patch-verification verdict, byte-exact for that case).
func SetImmunizationDetail(f func(validation.Value) (string, string)) {
	if f == nil {
		f = func(v validation.Value) (string, string) {
			return "missing", "no patch verification recorded (webv2 immunize " +
				"... against the FORK PoC)"
		}
	}
	immunizationDetailFunc = f
}

// SetContractPathResolver installs the contract-name → source-path resolver
// the scope check uses (B4): a path-based scope entry can match a
// name-carrying finding only if the name resolves to its source path. nil
// restores the default (read the saved structural index; empty when absent).
func SetContractPathResolver(f func(*state.Campaign, string) string) {
	if f == nil {
		f = func(*state.Campaign, string) string { return "" }
	}
	contractPathFunc = f
}

// SetConfirmedGateRemediation overrides the CONFIRMED-gate half of the
// gate-explain catalog (findings.GATE_REMEDIATION by default); nil restores
// that default.
func SetConfirmedGateRemediation(m map[string]string) {
	if m == nil {
		m = findings.GATE_REMEDIATION
	}
	confirmedRemediation = m
}

// ladderDisposition is _ladder_disposition: (state, ladder) where the state
// defaults to "open" and "missing" means no ladder row at all.
func ladderDisposition(campaign *state.Campaign,
	f validation.Value) (string, validation.Value, error) {
	lad, err := loadLadderFunc(campaign, objStr(f, "finding_id"))
	if err != nil {
		return "", validation.VNull(), err
	}
	if lad.Kind == validation.Null {
		return "missing", validation.VNull(), nil
	}
	stateV := objAt(objAt(lad, "disposition"), "state")
	st := "open"
	if pyTruthy(stateV) {
		st = pyStrAny(stateV)
	}
	return st, lad, nil
}

// gate accumulates one evaluate_bounty_gate run: the ordered check rows and
// the blocking reasons.
type gate struct {
	campaign *state.Campaign
	policy   validation.Value
	f        validation.Value
	checks   []validation.Value
	blockers []string
}

// add is the Python closure: an entry always carries its detail, and a
// non-pass result carries a remediation (the explicit one, else the catalog's).
func (g *gate) add(name, result, detail, remediation string) {
	entry := validation.VObj(
		validation.KV{K: "check", V: validation.VStr(name)},
		validation.KV{K: "result", V: validation.VStr(result)},
		validation.KV{K: "detail", V: validation.VStr(detail)},
	)
	if (result == "fail" || result == "unknown" || result == "human-review") &&
		remediation == "" {
		remediation = BountyRemediation[name]
	}
	if remediation != "" {
		entry.O = append(entry.O,
			validation.KV{K: "remediation", V: validation.VStr(remediation)})
	}
	g.checks = append(g.checks, entry)
}

// scopeTargets returns the strings the scope policy is matched against for
// this finding, deduplicated and order-preserving. A name-carrying finding is
// matched on the name (the primary target, the pre-B4 behaviour) AND (B4) the
// path the name resolves to via the structural index — so a path-based scope
// entry can match a name-carrying finding (the campaign's false "everything
// is out of scope" was the name never resolving to the path the scope named).
// A nameless finding falls back to its recorded path, exactly as before.
func (g *gate) scopeTargets() []string {
	first := validation.VObj()
	if aff := objAt(g.f, "affected"); aff.Kind == validation.Arr && len(aff.A) > 0 {
		first = aff.A[0]
	}
	name := ""
	if c := objAt(first, "contract"); c.Kind == validation.Str && c.S != "" {
		name = c.S
	}
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	if name != "" {
		// The name is the primary target (the pre-B4 behaviour — the name
		// takes precedence over the recorded path). B4 adds the path the
		// name resolves to via the structural index, so a path-based scope
		// entry can match a name-carrying finding. The recorded path is NOT
		// a separate candidate: a name-carrying finding is scoped by its
		// name (and where that name lives), not by an independent path field.
		add(name)
		add(contractPathFunc(g.campaign, name))
	} else {
		// No name: fall back to the recorded path (the pre-B4 behaviour).
		add(objStr(first, "path"))
	}
	return out
}

// check1 is security-confirmed (deterministic, from finding status).
func (g *gate) check1() {
	if objStr(g.f, "status") == "CONFIRMED" {
		g.add("security-confirmed", "pass", "", "")
		return
	}
	g.add("security-confirmed", "fail",
		"status is "+pyStrAny(objAt(g.f, "status")), "")
	g.blockers = append(g.blockers, "finding is not CONFIRMED")
}

// check2 is reachable deployment / snapshot pin.
func (g *gate) check2() error {
	active, err := g.campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return err
	}
	pin := objAt(objAt(g.f, "snapshot_ids"), "source")
	switch {
	case active != nil && pin.Kind == validation.Str && pin.S == *active:
		g.add("snapshot-pinned", "pass", "", "")
	case active != nil:
		g.add("snapshot-pinned", "fail", "finding pinned to "+
			validation.PyRepr(pin)+", campaign to "+validation.PyReprStr(*active), "")
		g.blockers = append(g.blockers,
			"snapshot mismatch — re-verify against active pin")
	default:
		g.add("snapshot-pinned", "unknown", "campaign has no active snapshot", "")
		g.blockers = append(g.blockers, "no active snapshot pin")
	}
	return nil
}

// check3 is scope. A finding is in scope if ANY of its candidate targets
// (name, path, and the name's structidx-resolved path — B4) matches a scope
// entry; the failure is reported against the primary target (the name, else
// the path) exactly as before.
func (g *gate) check3() error {
	targets := g.scopeTargets()
	if len(targets) == 0 {
		g.add("in-scope", "unknown", "no affected component recorded", "")
		g.blockers = append(g.blockers, "no affected component to scope-check")
		return nil
	}
	primaryWhy := ""
	for i, t := range targets {
		ok, why, err := InScope(g.policy, t)
		if err != nil {
			return err
		}
		if i == 0 {
			primaryWhy = why
		}
		if ok {
			g.add("in-scope", "pass", why, "")
			return nil
		}
	}
	g.add("in-scope", "fail", primaryWhy, "")
	g.blockers = append(g.blockers,
		"target "+validation.PyReprStr(targets[0])+" out of scope")
	return nil
}

// check4 is exclusions / known issues. A same-pattern accepted risk
// suppresses the exclusion (A1: the accepted risk is the narrower, more
// specific rule — the program already decided "we know and we accept", so the
// exclusion tripwire must not re-block it; check13 carries the record and the
// waiver path instead).
func (g *gate) check4() error {
	ex, err := ExclusionHit(g.policy, g.f)
	if err != nil {
		return err
	}
	if ex.Kind == validation.Obj {
		pattern := objStr(ex, "pattern")
		ar, err := AcceptedRiskHit(g.policy, g.f)
		if err != nil {
			return err
		}
		if ar.Kind == validation.Obj && objStr(ar, "pattern") == pattern {
			g.add("known-issue-check", "pass", "exclusion "+
				validation.PyReprStr(pattern)+" suppressed — an accepted risk "+
					"with the same pattern is the narrower rule (check "+
					"accepted-risk)", "")
			return nil
		}
		kind := objAt(ex, "kind")
		g.add("known-issue-check", "fail", "matches exclusion "+
			validation.PyReprStr(pattern)+" ("+pyStrAny(kind)+")", "")
		g.blockers = append(g.blockers,
			"excluded: "+pyStrAny(kind)+" — "+pattern)
		return nil
	}
	g.add("known-issue-check", "pass", "no exclusion pattern matched", "")
	return nil
}

// check5 is the severity floor.
func (g *gate) check5() error {
	sev, why, err := SeverityFor(g.policy, g.f)
	if err != nil {
		return err
	}
	if sev != "" {
		g.add("severity-floor", "pass", why, "")
		return nil
	}
	g.add("severity-floor", "human-review",
		"no deterministic severity rule matched — read program terms", "")
	g.blockers = append(g.blockers, "severity not established by policy rules")
	return nil
}

// needLevel is req.get("min_evidence_level", "E4") with the ValueError text
// level_index raises for a non-string level.
func needLevel(req validation.Value) (string, error) {
	v := getDefault(req, "min_evidence_level", validation.VStr("E4"))
	if v.Kind == validation.Str {
		return v.S, nil
	}
	return "", fmt.Errorf("unknown evidence level %s; the ladder is %s",
		validation.PyRepr(v), strings.Join(findings.EVIDENCE_ORDER, "/"))
}

// check6 is evidence sufficiency (policy-level, stricter than the CONFIRMED
// floor).
func (g *gate) check6() error {
	req := objAt(g.policy, "poc_requirements")
	need, err := needLevel(req)
	if err != nil {
		return err
	}
	have, err := findings.FindingLevel(g.f)
	if err != nil {
		return err
	}
	hi, err := findings.LevelIndex(have)
	if err != nil {
		return err
	}
	ni, err := findings.LevelIndex(need)
	if err != nil {
		return err
	}
	if hi >= ni {
		g.add("evidence-sufficient", "pass",
			fmt.Sprintf("%s >= required %s", have, need), "")
	} else {
		g.add("evidence-sufficient", "fail",
			fmt.Sprintf("%s < required %s", have, need), "")
		g.blockers = append(g.blockers,
			fmt.Sprintf("evidence %s below program floor %s", have, need))
	}
	if err := g.check6Fork(req); err != nil {
		return err
	}
	return g.check6Economic(req)
}

// check6Fork is the require_fork_repro clause of check 6.
func (g *gate) check6Fork(req validation.Value) error {
	if !pyTruthy(objAt(req, "require_fork_repro")) {
		return nil
	}
	repro := objAt(objAt(g.f, "verification"), "reproduction")
	tier := getDefault(repro, "tier_reached", validation.VStr("none"))
	if tier.Kind == validation.Str && (tier.S == "T3" || tier.S == "T4") {
		g.add("fork-repro", "pass", "tier "+tier.S, "")
		return nil
	}
	g.add("fork-repro", "fail", "repro tier "+pyStrAny(tier)+
		", program requires T3+", "")
	g.blockers = append(g.blockers, "program requires fork-based reproduction")
	return nil
}

// check6Economic is the require_economic_quantification clause of check 6.
func (g *gate) check6Economic(req validation.Value) error {
	if !pyTruthy(objAt(req, "require_economic_quantification")) {
		return nil
	}
	usd := objAt(objAt(g.f, "economic_impact"), "extractable_usd")
	floor := objAt(req, "min_extractable_usd")
	ok := usd.Kind != validation.Null
	if ok && floor.Kind != validation.Null {
		got, okGot := pyFloat(usd)
		want, okWant := pyFloat(floor)
		ok = okGot && okWant && got >= want
	}
	if ok {
		g.add("economic-quantified", "pass", "", "")
		return nil
	}
	g.add("economic-quantified", "fail", "extractable_usd missing or below floor", "")
	g.blockers = append(g.blockers,
		"economic impact not quantified to program floor")
	return nil
}

// maximalAxes is the five axes a closed ladder must have explored.
var maximalAxes = []string{"capital-minimization", "precondition-removal",
	"role-conflation", "ordering-permutation", "cap-saturation"}

// check7 is maximal exploitation (A) — a CONFIRMED finding ships its MAXIMAL
// claim: every ladder rung the operator believed in is either reproduced (and
// pinned) or disproved, all five axes explored, the ladder closed — or the
// closure is an explicit, named waiver.
func (g *gate) check7() error {
	if objStr(g.f, "status") != "CONFIRMED" {
		return nil
	}
	disposition, lad, err := ladderDisposition(g.campaign, g.f)
	if err != nil {
		return err
	}
	switch disposition {
	case "complete":
		g.add("maximal-exploitation", "pass",
			"ladder closed (maximal: "+pyStrAny(objAt(lad, "maximal_rung_id"))+")", "")
	case "waived":
		reason := objAt(objAt(lad, "disposition"), "reason")
		if !pyTruthy(reason) {
			reason = validation.VStr("")
		}
		g.add("maximal-exploitation", "pass", "ladder waived: "+
			headRunes(pyStrAny(reason), 80), "")
	case "missing":
		g.add("maximal-exploitation", "fail", "no variant ladder — the claim "+
			"may still be a base-rung artifact (run-1: 50% at $2.5k claimed; "+
			"100% at 1 wei true)", "")
		g.blockers = append(g.blockers,
			"variant ladder missing for a CONFIRMED finding")
	default:
		explored := objAt(lad, "axes_explored")
		var openAxes []string
		for _, a := range maximalAxes {
			if !inStringList(explored, a) {
				openAxes = append(openAxes, a)
			}
		}
		detail := "ladder " + disposition
		if len(openAxes) > 0 {
			detail += "; unexplored axes: " + pyListRepr(openAxes)
		}
		g.add("maximal-exploitation", "fail", detail, "")
		g.blockers = append(g.blockers,
			"variant ladder not closed (complete or waived)")
	}
	return nil
}

// check8 is price basis (G) — every USD figure must name the price row it was
// computed from.
func (g *gate) check8() error {
	ei := objAt(g.f, "economic_impact")
	var usdKeys []string
	for _, kv := range ei.O {
		if strings.HasSuffix(kv.K, "_usd") && kv.V.Kind != validation.Null {
			usdKeys = append(usdKeys, kv.K)
		}
	}
	if len(usdKeys) == 0 {
		return nil
	}
	sort.Strings(usdKeys)
	basis := objAt(ei, "price_basis")
	row := validation.VNull()
	if pyTruthy(basis) && basis.Kind == validation.Str {
		var err error
		row, err = priceRowFunc(g.campaign, basis.S)
		if err != nil {
			return err
		}
	}
	if row.Kind != validation.Obj {
		g.add("e7-price-basis", "fail", "USD figures "+pyListRepr(usdKeys)+
			" carry no resolvable price_basis "+validation.PyRepr(basis), "")
		g.blockers = append(g.blockers,
			"USD figures without a resolvable price basis")
		return nil
	}
	detail := pyStrAny(basis) + " -> " + pyStrAny(objAt(row, "asset")) + " @ $" +
		pyStrAny(objAt(row, "usd")) + " (" +
		headRunes(pyStrAny(objAt(row, "source")), 40) + ")"
	g.add("e7-price-basis", "pass", detail, "")
	return nil
}

// check9 is claim drift (C) — the claim must not contradict the measurement.
func (g *gate) check9() error {
	drifts, err := findings.ClaimDriftProblems(g.f)
	if err != nil {
		return err
	}
	if len(drifts) > 0 {
		g.add("claim-drift", "fail", drifts[0], "")
		g.blockers = append(g.blockers,
			"claim contradicts measured extraction_ratio")
		return nil
	}
	g.add("claim-drift", "pass", "", "")
	return nil
}

// falsePreconditions is f.get("preconditions", []) filtered to the audited
// "the code never enforces this" rows.
func falsePreconditions(f validation.Value) []validation.Value {
	var out []validation.Value
	for _, p := range objAt(f, "preconditions").A {
		if objStr(p, "enforced_by_poc") == "false" {
			out = append(out, p)
		}
	}
	return out
}

// removedPreconditions is every variant's removed_preconditions, flattened.
func removedPreconditions(lad validation.Value) []string {
	var out []string
	for _, v := range objAt(lad, "variants").A {
		for _, r := range objAt(v, "removed_preconditions").A {
			if r.Kind == validation.Str {
				out = append(out, r.S)
			}
		}
	}
	return out
}

// check10 is the precondition audit (C) — every precondition the PoC ASSUMED
// but the code never enforced must be closed: removed by a ladder rung, or
// covered by the ladder's waiver.
func (g *gate) check10() error {
	falsePre := falsePreconditions(g.f)
	if len(falsePre) == 0 {
		g.add("precondition-audit", "pass", "", "")
		return nil
	}
	disposition, lad, err := ladderDisposition(g.campaign, g.f)
	if err != nil {
		return err
	}
	if disposition == "waived" {
		g.add("precondition-audit", "pass", fmt.Sprintf(
			"%d code-unenforced precondition(s) covered by the ladder waiver",
			len(falsePre)), "")
		return nil
	}
	removed := removedPreconditions(lad)
	var openPre []string
	for _, p := range falsePre {
		desc := objStr(p, "description")
		closed := false
		for _, r := range removed {
			if strings.Contains(desc, r) || strings.Contains(r, desc) {
				closed = true
				break
			}
		}
		if !closed {
			openPre = append(openPre, desc)
		}
	}
	if len(openPre) > 0 {
		g.add("precondition-audit", "fail", "precondition(s) the code never "+
			"enforces, unaddressed by any ladder rung: "+
			strings.Join(openPre, "; "), "")
		g.blockers = append(g.blockers,
			"unaudited preconditions unaddressed by the ladder")
		return nil
	}
	g.add("precondition-audit", "pass", fmt.Sprintf(
		"all %d code-unenforced preconditions addressed by ladder rungs",
		len(falsePre)), "")
	return nil
}

// check11 is mainnet-fork-poc — the LATEST REQUIRED STEP: the PoC must have
// RUN on the pinned mainnet fork. A unit harness proves the semantics; only
// the fork proves mainnet.
func (g *gate) check11() error {
	findingID := objStr(g.f, "finding_id")
	ok, why, err := forkPocStatusFunc(g.campaign, findingID)
	if err != nil {
		return err
	}
	if ok {
		g.add("mainnet-fork-poc", "pass", why, "")
		return nil
	}
	rows, err := waiversFunc(g.campaign, "mainnet-fork-poc")
	if err != nil {
		return err
	}
	for _, w := range rows {
		subject := objStr(w, "subject")
		if subject != "*" && subject != findingID {
			continue
		}
		g.add("mainnet-fork-poc", "pass", "waived by "+pyStrAny(objAt(w, "actor"))+
			": "+headRunes(pyStrAny(objAt(w, "reason")), 80), "")
		return nil
	}
	g.add("mainnet-fork-poc", "fail", why, "")
	g.blockers = append(g.blockers,
		"no proven mainnet fork PoC (the latest required step)")
	return nil
}

// check12 is immunization — the patch BLOCKS the fork PoC and all 3 boundary
// mutations. A patch that only blocks a unit test is not a patch. Like its
// siblings, an explicit waiver (stage "immunization") records the check as
// passed-waived rather than failed (B1: with the fork PoC waived, this
// unconditional requirement made submission_ready permanently unreachable).
func (g *gate) check12() error {
	state, detail := immunizationDetailFunc(g.f)
	if state == "immunized" {
		g.add("immunization", "pass", detail, "")
		return nil
	}
	findingID := objStr(g.f, "finding_id")
	rows, err := waiversFunc(g.campaign, "immunization")
	if err != nil {
		return err
	}
	for _, w := range rows {
		subject := objStr(w, "subject")
		if subject != "*" && subject != findingID {
			continue
		}
		g.add("immunization", "pass", "waived by "+pyStrAny(objAt(w, "actor"))+
			": "+headRunes(pyStrAny(objAt(w, "reason")), 80), "")
		return nil
	}
	g.add("immunization", "fail", state+": "+detail, "")
	g.blockers = append(g.blockers, "not immunized ("+state+") — the patch "+
		"must block the FORK PoC and its 3 boundary mutations")
	return nil
}

// check13 is the accepted-risk channel (IMPROVEMENTS A1). A documented,
// program-accepted risk is NOT an exclusion: the finding stays visible and
// counted, but it is not submittable as a vulnerability. On a hit the match
// is recorded on the finding (bounty.accepted_risk) and the check fails with
// a named remediation: waive it (webv2 waive <campaign> accepted-risk
// --subject <finding> --reason ...) once the operator has decided this
// particular finding IS payable. An accepted_risk.min_severity caps the
// acceptance — at that severity and above the acceptance does not apply and
// the gate demands real handling (no record, no waiver path of its own:
// the finding simply has to clear the gate on its merits).
func (g *gate) check13() error {
	ar, err := AcceptedRiskHit(g.policy, g.f)
	if err != nil {
		return err
	}
	if ar.Kind != validation.Obj {
		g.add("accepted-risk", "pass", "no accepted-risk pattern matched", "")
		return nil
	}
	pattern := objStr(ar, "pattern")
	kind := pyStrAny(objAt(ar, "kind"))
	if minSev := objStr(ar, "min_severity"); minSev != "" {
		sev, _, err := SeverityFor(g.policy, g.f)
		if err != nil {
			return err
		}
		if sev != "" && severityRank(sev) >= severityRank(minSev) {
			g.add("accepted-risk", "fail",
				"matches accepted risk "+validation.PyReprStr(pattern)+" ("+
					kind+") but severity "+sev+" reaches its "+minSev+
					" floor — the acceptance does not apply", "")
			g.blockers = append(g.blockers,
				"accepted risk "+validation.PyReprStr(pattern)+" not "+
					"honored at severity "+sev)
			return nil
		}
	}
	// Record the acceptance on the finding (visible, counted, not
	// submittable) before the waiver decision: a waived finding still
	// carries the record, so the report can show both facts.
	rec := validation.VObj(
		validation.KV{K: "pattern", V: validation.VStr(pattern)})
	for _, key := range []string{"kind", "reference", "note"} {
		if v, ok := fieldAt(ar, key); ok {
			rec.O = append(rec.O, validation.KV{K: key, V: v})
		}
	}
	bounty := objAt(g.f, "bounty")
	if bounty.Kind != validation.Obj {
		bounty = validation.VObj()
	}
	bounty.O = setOrAppend(bounty.O, "accepted_risk", rec)
	g.f.O = setOrAppend(g.f.O, "bounty", bounty)

	findingID := objStr(g.f, "finding_id")
	rows, err := waiversFunc(g.campaign, "accepted-risk")
	if err != nil {
		return err
	}
	for _, w := range rows {
		subject := objStr(w, "subject")
		if subject != "*" && subject != findingID {
			continue
		}
		g.add("accepted-risk", "pass", "waived by "+pyStrAny(objAt(w, "actor"))+
			": "+headRunes(pyStrAny(objAt(w, "reason")), 80), "")
		return nil
	}
	g.add("accepted-risk", "fail",
		"matches accepted risk "+validation.PyReprStr(pattern)+" ("+kind+
			") — recorded; not submittable", "")
	g.blockers = append(g.blockers,
		"accepted risk "+validation.PyReprStr(pattern)+" — not "+
			"submittable as a vulnerability")
	return nil
}

// run executes the thirteen checks (the twelve ported + accepted-risk, A1).
func (g *gate) run() error {
	g.check1()
	for _, check := range []func() error{g.check2, g.check3, g.check4, g.check5,
		g.check6, g.check7, g.check8, g.check9, g.check10, g.check11,
		g.check12, g.check13} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// EvaluateBountyGate is evaluate_bounty_gate: the full bounty gate. Produces
// bounty.eligible, bounty.submission_ready and bounty.blocking_reasons. Check
// results are pass / fail / unknown / human-review; `unknown` never becomes
// pass. Every failing check carries a remediation (K): the exact command that
// clears it.
func EvaluateBountyGate(campaign *state.Campaign, findingID string,
	policy validation.Value, save bool) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	g := &gate{campaign: campaign, policy: policy, f: f}
	if err := g.run(); err != nil {
		return validation.VNull(), err
	}
	// The checks run on a struct copy of the finding (the gate's f shares
	// the top-level KV slice but a check may re-append to it — check13
	// records the accepted risk when the finding had no bounty object yet).
	// Re-adopt the gate's copy so the record reaches the save below.
	f = g.f
	eligible := true
	for _, c := range g.checks {
		if objStr(c, "result") != "fail" {
			continue
		}
		switch objStr(c, "check") {
		case "security-confirmed", "in-scope", "known-issue-check":
			eligible = false
		}
	}
	submissionReady := len(g.blockers) == 0
	for _, c := range g.checks {
		if objStr(c, "result") != "pass" {
			submissionReady = false
			break
		}
	}
	bounty := objAt(f, "bounty")
	if bounty.Kind != validation.Obj {
		bounty = validation.VObj()
	}
	bounty.O = setOrAppend(bounty.O, "eligible", validation.VBool(eligible))
	bounty.O = setOrAppend(bounty.O, "submission_ready",
		validation.VBool(submissionReady))
	bounty.O = setOrAppend(bounty.O, "blocking_reasons", strList(g.blockers))
	bounty.O = setOrAppend(bounty.O, "policy_checks",
		validation.Value{Kind: validation.Arr, A: g.checks})
	f.O = setOrAppend(f.O, "bounty", bounty)
	if save {
		if err := findings.SaveFinding(campaign, &f); err != nil {
			return validation.VNull(), err
		}
		data := validation.VObj(
			validation.KV{K: "eligible", V: validation.VBool(eligible)},
			validation.KV{K: "submission_ready", V: validation.VBool(submissionReady)},
			validation.KV{K: "blockers", V: strList(g.blockers)},
		)
		if _, err := campaign.Log("bounty.gate", &findingID, &data); err != nil {
			return validation.VNull(), err
		}
	}
	return bounty, nil
}

// strList renders a []string as a JSON array value ([] when empty).
func strList(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return validation.Value{Kind: validation.Arr, A: out}
}
