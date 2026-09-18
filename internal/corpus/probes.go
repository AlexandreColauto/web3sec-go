// probes.go: the probe table. Each predicate is a pure function over the
// structural index returning hit dicts {"node_id", "detail"}. Confidence
// reflects how tightly the predicate scopes its class: high = tight mechanism
// shape, medium = plausible surface, low = weak/catch-all signal. A probe that
// always returns "exposed" is worse than none — classes without an honest
// structural predicate go to Unprobed.
package corpus

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

var (
	reGuard           = regexp.MustCompile(`(?i)nonreentrant|reentrancyguard|rlock|noconcurrentcall`)
	reBalanceTotal    = regexp.MustCompile(`(?i)total|sum|pool|assets|balanceof`)
	reAccountingCount = regexp.MustCompile(`(?i)shares|supply|amount|debt|principal`)
	reRateVar         = regexp.MustCompile(`(?i)rate|pershare|price|exchangerate`)
	rePriceyCall      = regexp.MustCompile(`(?i)\.(price|oracle|spot|round)\w*\(`)
	rePriceyVar       = regexp.MustCompile(`(?i)price|rate|exchangerate|tokenprice`)
	reTransferIn      = regexp.MustCompile(`(?i)\.(transferfrom|deposit|borrow)\b`)
	reTransferOut     = regexp.MustCompile(`(?i)\.transfer\b|\.withdraw\b`)
	reTokenIface      = regexp.MustCompile(`(?i)\.(balanceof|allowance|approve|transferfrom)\b`)
	reValueMoveCall   = regexp.MustCompile(`(?i)\.(transfer|mint|withdraw)\b`)
	reValueVar        = regexp.MustCompile(`(?i)balance|amount|reserve`)
	reBridge          = regexp.MustCompile(`(?i)onmessage|fulfill|relayer|settle|bridge`)
	reGriefVar        = regexp.MustCompile(`(?i)queue|pending|batch|nonce|counter`)
	reValidationCall  = regexp.MustCompile(`(?i)check|verify|validate`)
)

// TransferOutRe is _TRANSFER_OUT, exported so the paren-boundary parity test
// can assert on the pattern itself (`.transfer` must not swallow
// `.transferFrom`).
var TransferOutRe = reTransferOut

func fns(index validation.Value) []validation.Value {
	return structidx.Nodes(index, "function")
}

func hit(nodeID, detail string) validation.Value {
	return validation.VObj(
		validation.KV{K: "node_id", V: validation.VStr(nodeID)},
		validation.KV{K: "detail", V: validation.VStr(detail)},
	)
}

// pReentrancy is _p_reentrancy: an unguarded entry point that calls out and
// then writes storage.
func pReentrancy(index validation.Value) []validation.Value {
	hits := []validation.Value{}
	for _, n := range structidx.ExternalSurface(index) {
		calls := strListAt(n, "calls_external")
		deleg := strListAt(n, "delegatecalls")
		if len(calls) == 0 && len(deleg) == 0 {
			continue
		}
		writes := structidx.WritersOf(index, n)
		if len(writes) == 0 {
			continue
		}
		if reGuard.MatchString(strings.Join(strListAt(n, "guarded_by"), " ")) {
			continue
		}
		hits = append(hits, hit(validation.ObjStr(n, "id"), fmt.Sprintf(
			"external %s + writes %s", pyReprList(firstN(calls, 2)),
			pyReprList(firstN(writes, 3)))))
	}
	return hits
}

// pSharePriceInflation is _p_share_price_inflation: the donation-attack
// shape, in both accounting layouts (inline and delegated).
func pSharePriceInflation(index validation.Value) []validation.Value {
	byID := map[string]validation.Value{}
	for _, n := range fns(index) {
		byID[validation.ObjStr(n, "id")] = n
	}
	hits := []validation.Value{}
	for _, n := range fns(index) {
		rw := structidx.ReadsWritesOf(index, n)
		if !anyMatch(reBalanceTotal, rw) {
			continue
		}
		if !anyMatch(reAccountingCount, rw) {
			continue
		}
		var writesRate []string
		for _, v := range structidx.WritersOf(index, n) {
			if reRateVar.MatchString(v) {
				writesRate = append(writesRate, v)
			}
		}
		if len(writesRate) > 0 {
			hits = append(hits, hit(validation.ObjStr(n, "id"),
				"inline accounting, rate write "+pyReprList(writesRate)))
			continue
		}
		var entryCallers []string
		for _, c := range structidx.CallersOf(index, validation.ObjStr(n, "id")) {
			if b := validation.ObjAt(byID[c], "is_entry_point"); b.Kind == validation.Bool && b.B {
				entryCallers = append(entryCallers, c)
			}
		}
		if len(entryCallers) > 0 {
			names := make([]string, 0, len(entryCallers))
			for _, c := range entryCallers {
				parts := strings.Split(c, ".")
				names = append(names, parts[len(parts)-1])
			}
			hits = append(hits, hit(validation.ObjStr(n, "id"),
				"delegated ratio site read by entry "+
					pyReprList(firstN(names, 2))))
		}
	}
	return hits
}

// pOracleManipulation is _p_oracle_manipulation.
func pOracleManipulation(index validation.Value) []validation.Value {
	hits := []validation.Value{}
	for _, n := range structidx.ExternalSurface(index) {
		calls := strListAt(n, "calls_external")
		pricey := false
		for _, c := range calls {
			if rePriceyCall.MatchString(c + "(") {
				pricey = true
				break
			}
		}
		if pricey {
			hits = append(hits, hit(validation.ObjStr(n, "id"),
				"pricey call "+pyReprList(firstN(calls, 2))))
			continue
		}
		var reads []string
		for _, v := range strListAt(n, "reads_storage") {
			if rePriceyVar.MatchString(v) {
				reads = append(reads, v)
			}
		}
		if len(reads) > 0 {
			hits = append(hits, hit(validation.ObjStr(n, "id"),
				"reads price var "+pyReprList(reads)))
		}
	}
	return hits
}

// pAccessControl is _p_access_control.
func pAccessControl(index validation.Value) []validation.Value {
	hits := []validation.Value{}
	for _, n := range structidx.UnguardedEntryPoints(index) {
		writes := structidx.WritersOf(index, n)
		if len(writes) == 0 {
			continue
		}
		hits = append(hits, hit(validation.ObjStr(n, "id"),
			"unguarded entry writes "+pyReprList(firstN(writes, 3))))
	}
	return hits
}

// pFlashLoan is _p_flash_loan: an in-out flow in one function, or a
// flashloan-shaped contract/interface name.
func pFlashLoan(index validation.Value) []validation.Value {
	hits := []validation.Value{}
	for _, n := range fns(index) {
		calls := strings.Join(strListAt(n, "calls_external"), " ")
		if reTransferIn.MatchString(calls) && reTransferOut.MatchString(calls) {
			hits = append(hits, hit(validation.ObjStr(n, "id"), "transfer-in + out"))
		}
	}
	nameRe := regexp.MustCompile(`(?i)flashloan|lendingpool|flashborrow`)
	for _, kind := range []string{"contract", "interface"} {
		for _, n := range structidx.Nodes(index, kind) {
			if nameRe.MatchString(validation.ObjStr(n, "name")) {
				hits = append(hits, hit(validation.ObjStr(n, "id"), kind+" name"))
			}
		}
	}
	return hits
}

// pTokenIntegration is _p_token_integration.
func pTokenIntegration(index validation.Value) []validation.Value {
	hits := []validation.Value{}
	for _, n := range structidx.ExternalSurface(index) {
		if reTokenIface.MatchString(strings.Join(strListAt(n, "calls_external"), " ")) {
			hits = append(hits, hit(validation.ObjStr(n, "id"), "token iface calls"))
		}
	}
	return hits
}

// pUncheckedExternalCall is _p_unchecked_external_call.
func pUncheckedExternalCall(index validation.Value) []validation.Value {
	hits := []validation.Value{}
	for _, n := range fns(index) {
		var raw []string
		for _, c := range strListAt(n, "calls_external") {
			if strings.HasPrefix(c, "low-level.") {
				raw = append(raw, c)
			}
		}
		deleg := strListAt(n, "delegatecalls")
		if len(raw) == 0 && len(deleg) == 0 {
			continue
		}
		shown := raw
		if len(shown) == 0 {
			shown = deleg
		}
		hits = append(hits, hit(validation.ObjStr(n, "id"), "raw calls "+pyReprList(shown)))
	}
	return hits
}

// pLogicError is _p_logic_error.
func pLogicError(index validation.Value) []validation.Value {
	hits := []validation.Value{}
	for _, n := range structidx.ExternalSurface(index) {
		writes := structidx.WritersOf(index, n)
		if len(writes) == 0 {
			continue
		}
		called := strings.Join(append(strListAt(n, "calls_internal"),
			strListAt(n, "calls_external")...), " ")
		if reValidationCall.MatchString(called) {
			continue
		}
		hits = append(hits, hit(validation.ObjStr(n, "id"),
			"writes "+pyReprList(firstN(writes, 3))+" without validation call"))
	}
	return hits
}

// pCentralizationRisk is _p_centralization_risk.
func pCentralizationRisk(index validation.Value) []validation.Value {
	hits := []validation.Value{}
	for _, n := range structidx.GuardedEntryPoints(index) {
		calls := strings.Join(strListAt(n, "calls_external"), " ")
		if anyMatch(reValueVar, strListAt(n, "writes_storage")) {
			hits = append(hits, hit(validation.ObjStr(n, "id"), "authz write of value var"))
		} else if reValueMoveCall.MatchString(calls) {
			hits = append(hits, hit(validation.ObjStr(n, "id"), "authz value move"))
		}
	}
	return hits
}

// pBridgeMessage is _p_bridge_message.
func pBridgeMessage(index validation.Value) []validation.Value {
	hits := []validation.Value{}
	for _, n := range fns(index) {
		name := validation.ObjStr(n, "name")
		if reBridge.MatchString(name) {
			hits = append(hits, hit(validation.ObjStr(n, "id"), "fn "+name))
			continue
		}
		for _, c := range strListAt(n, "calls_external") {
			if reBridge.MatchString(c) {
				hits = append(hits, hit(validation.ObjStr(n, "id"), "call "+c))
				break
			}
		}
	}
	return hits
}

// pDosGriefing is _p_dos_griefing.
func pDosGriefing(index validation.Value) []validation.Value {
	hits := []validation.Value{}
	for _, n := range structidx.UnguardedEntryPoints(index) {
		var shared []string
		for _, v := range strListAt(n, "writes_storage") {
			if reGriefVar.MatchString(v) {
				shared = append(shared, v)
			}
		}
		if len(shared) > 0 {
			hits = append(hits, hit(validation.ObjStr(n, "id"),
				"unguarded write of shared state "+pyReprList(shared)))
		}
	}
	return hits
}

// pUpgradeInitializer is _p_upgrade_initializer.
func pUpgradeInitializer(index validation.Value) []validation.Value {
	initRe := regexp.MustCompile(`(?i)^(init|initialize)$`)
	guardRe := regexp.MustCompile(`(?i)initializer|initialized`)
	hits := []validation.Value{}
	for _, n := range fns(index) {
		if !initRe.MatchString(validation.ObjStr(n, "name")) {
			continue
		}
		writes := strListAt(n, "writes_storage")
		if len(writes) == 0 {
			continue
		}
		if guardRe.MatchString(strings.Join(strListAt(n, "guarded_by"), " ")) {
			continue
		}
		hits = append(hits, hit(validation.ObjStr(n, "id"),
			"init writes "+pyReprList(firstN(writes, 3))+" unguarded"))
	}
	return hits
}

// probe is one entry in the probe table: an id, a confidence and the
// predicate.
type probe struct {
	id         string
	confidence string
	fn         func(validation.Value) []validation.Value
}

// Probes is PROBES: canonical class -> its probe entries.
var Probes = map[string][]probe{
	"reentrancy": {
		{"ext-call-before-write", "high", pReentrancy}},
	"share-price-inflation": {
		{"donation-attack-shape", "high", pSharePriceInflation}},
	"oracle-manipulation": {
		{"pricey-read", "medium", pOracleManipulation}},
	"access-control": {
		{"unguarded-state-write", "medium", pAccessControl}},
	"flash-loan": {
		{"in-out-flow", "medium", pFlashLoan}},
	"token-integration": {
		{"token-iface-calls", "low", pTokenIntegration}},
	"unchecked-external-call": {
		{"raw-call-surface", "medium", pUncheckedExternalCall}},
	"logic-error": {
		{"unvalidated-state-transition", "low", pLogicError}},
	"centralization-risk": {
		{"authz-value-surface", "medium", pCentralizationRisk}},
	"bridge-message": {
		{"bridge-naming", "low", pBridgeMessage}},
	"dos-griefing": {
		{"grievable-shared-state", "low", pDosGriefing}},
	"upgrade-initializer": {
		{"init-without-guard", "medium", pUpgradeInitializer}},
}

// Aliases is ALIASES: alternative corpus labels served by a canonical
// predicate.
var Aliases = map[string]string{
	"donation":               "share-price-inflation",
	"share-price-accounting": "share-price-inflation",
	"liquidation-logic":      "logic-error",
}

// Unprobed is UNPROBED: classes with no honest structural predicate, and why.
var Unprobed = map[string]string{
	"precision-rounding": "requires body-level arithmetic-ordering analysis " +
		"(division-before-multiplication) not present in the structural index",
	"signature-replay": "requires ecrecover/signature body analysis not " +
		"present in the structural index",
}

// confidenceOrder is the min() key of probe_classes.
var confidenceOrder = []string{"high", "medium", "low"}

// ProbeClasses is probe_classes: run every predicate; one row per probed
// class and per alias (aliases report under their own name with the canonical
// predicate's hits).
func ProbeClasses(index validation.Value) []validation.Value {
	out := []validation.Value{}
	classes := make([]string, 0, len(Probes))
	for cls := range Probes {
		classes = append(classes, cls)
	}
	sort.Strings(classes)
	for _, cls := range classes {
		entries := Probes[cls]
		hits := []validation.Value{}
		for _, e := range entries {
			hits = append(hits, e.fn(index)...)
		}
		conf := entries[0].confidence
		for _, e := range entries {
			if confIndex(e.confidence) < confIndex(conf) {
				conf = e.confidence
			}
		}
		out = append(out, validation.VObj(
			validation.KV{K: "bug_class", V: validation.VStr(cls)},
			validation.KV{K: "exposed", V: validation.VBool(len(hits) > 0)},
			validation.KV{K: "hits", V: validation.VArr(firstNVal(hits, 20)...)},
			validation.KV{K: "confidence", V: validation.VStr(conf)},
		))
	}
	aliases := make([]string, 0, len(Aliases))
	for alias := range Aliases {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		var src validation.Value
		for _, x := range out {
			if validation.ObjStr(x, "bug_class") == Aliases[alias] {
				src = x
				break
			}
		}
		hits := append([]validation.Value{}, listAt(src, "hits")...)
		out = append(out, validation.VObj(
			validation.KV{K: "bug_class", V: validation.VStr(alias)},
			validation.KV{K: "exposed", V: validation.ObjAt(src, "exposed")},
			validation.KV{K: "hits", V: validation.VArr(hits...)},
			validation.KV{K: "confidence", V: validation.ObjAt(src, "confidence")},
		))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return validation.ObjStr(out[i], "bug_class") < validation.ObjStr(out[j], "bug_class")
	})
	return out
}

func confIndex(c string) int {
	for i, x := range confidenceOrder {
		if x == c {
			return i
		}
	}
	return len(confidenceOrder)
}

// ---- helpers -------------------------------------------------------------

// pyReprList renders a []string the way Python's repr() does — probe details
// embed list reprs, so the artifact bytes depend on it.
func pyReprList(xs []string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = validation.PyReprStr(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func firstNVal(xs []validation.Value, n int) []validation.Value {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

func firstN(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

func anyMatch(re *regexp.Regexp, values []string) bool {
	for _, v := range values {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}
