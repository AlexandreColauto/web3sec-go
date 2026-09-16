// Package economics ports webv2.economics: the economic security engine.
//
// Most LLM auditors read code better than they read economics. This package
// makes the economic model a first-class, testable object:
//
//	equations   — recorded accounting/valuation relations, each mapped to the
//	              code that enforces it and the known ways it can break
//	transforms  — deterministic generation of adversarial transformations
//	              (donation, first-depositor inflation, fee-on-transfer
//	              asymmetry, rounding sweep, oracle skew, flash-loan
//	              amplification, liquidity withdrawal) tailored to what the
//	              protocol model actually contains
//
// The transforms feed the economic trajectory (B) as concrete experiments:
// "for each transform, can the attacker construct a transaction that changes
// one side of an equation without the other?"
package economics

import (
	"fmt"
	"strings"

	"websec/internal/protocolgraph"
	"websec/internal/validation"
)

// catalogEntry is one (name, applies_to, question) catalog row. The index in
// catalog is the TR-%03d number: numbering follows the CATALOG position, not
// the position in the generated output, so a filtered list has gaps.
type catalogEntry struct {
	name     string
	applies  func(validation.Value) bool
	question string
}

// catalog is _CATALOG, in file order. The question strings are contractual
// (they are emitted verbatim into the trajectory) and pinned byte-for-byte
// against testdata/catalog.json.
var catalog = []catalogEntry{
	{"donation-attack", func(validation.Value) bool { return true },
		"Can anyone transfer assets directly to the accounting contract, " +
			"inflating a share/price denominator they don't own?"},
	{"first-depositor-rounding", func(m validation.Value) bool { return has(m, "share") },
		"Can the first depositor mint shares at a rounded-down rate and steal " +
			"the next depositor's rounding dust — or invert it via a donation?"},
	{"fee-on-transfer-asymmetry",
		func(m validation.Value) bool { return hasFlag(m, "fee-on-transfer") },
		"Does accounting record amountIn while only amountIn-fee arrives?"},
	{"rebasing-supply-desync",
		func(m validation.Value) bool { return hasFlag(m, "rebasing") },
		"Does balance-based accounting desync when the token rebases?"},
	{"erc777-callback-reentrancy",
		func(m validation.Value) bool { return hasFlag(m, "erc777-callbacks") },
		"Do hooks fire during transfers used inside accounting updates?"},
	{"erc4626-inflation",
		func(m validation.Value) bool { return hasFlag(m, "erc4626-vault") },
		"Can virtual shares/offset defenses be bypassed by direct asset " +
			"donation plus precise rounding?"},
	{"oracle-spot-skew",
		func(m validation.Value) bool {
			return len(protocolgraph.OracleChain(m)) > 0
		},
		"Can a single transaction move the price source the protocol reads, " +
			"then trade against the moved price?"},
	{"oracle-staleness",
		func(m validation.Value) bool {
			return len(protocolgraph.OracleChain(m)) > 0
		},
		"What happens on every stale/zero/sequencer-down path the oracle " +
			"can return?"},
	{"flash-loan-amplification", func(validation.Value) bool { return true },
		"With unlimited borrowed capital for one transaction, which " +
			"assumption about capital cost breaks?"},
	{"liquidity-withdrawal-bounded", func(validation.Value) bool { return true },
		"What is the realistic extractable ceiling given pool depth, not " +
			"theoretical exposure?"},
	{"odd-decimals-mismatch",
		func(m validation.Value) bool { return hasFlag(m, "odd-decimals") },
		"Where do two assets of different decimals meet in one equation?"},
	{"insolvency-by-withdraw-order", func(m validation.Value) bool { return has(m, "debt") },
		"Can liabilities be withdrawn/liquidated ahead of the assets backing " +
			"them?"},
}

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// objAt is dict.get(key): the value for key, or Null when absent.
func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V
		}
	}
	return validation.VNull()
}

// listOf is model.get(key, []) normalised to a non-nil slice.
func listOf(model validation.Value, key string) []validation.Value {
	v := objAt(model, key)
	if v.Kind != validation.Arr || len(v.A) == 0 {
		return []validation.Value{}
	}
	return v.A
}

// has is _has: some asset declares this kind.
func has(model validation.Value, kind string) bool {
	for _, a := range listOf(model, "assets") {
		if objAt(a, "kind").S == kind {
			return true
		}
	}
	return false
}

// hasFlag is _has_flag: match a flag exactly or as a parameterized family.
//
// protocol_graph.external_assets emits `odd-decimals-<n>` (the decimals count
// is part of the flag), so an exact-membership test for `odd-decimals` never
// matched and the transform silently never fired.
func hasFlag(model validation.Value, flag string) bool {
	for _, a := range protocolgraph.ExternalAssets(model) {
		for _, f := range objAt(a, "flags").A {
			// Python: `f == flag or f.startswith(flag + "-")`. A non-string
			// flag can only satisfy the equality test, never startswith.
			if f.Kind == validation.Str &&
				(f.S == flag || strings.HasPrefix(f.S, flag+"-")) {
				return true
			}
		}
	}
	return false
}

// strArr lifts Go strings into an array Value.
func strArr(items ...string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

// BuildEquations is build_equations: the recorded economic relations, plus
// the universal ones when share/debt assets (or accounting variables) exist
// but were not explicitly recorded. The EQ-%03d counter continues after the
// recorded rows, and a recorded equation suppresses its universal twin.
// Synthesized rows carry `synthesized: true`: they are templates the operator
// may adopt, not recorded model, so EquationGaps does not price them.
func BuildEquations(model validation.Value) []validation.Value {
	eqs := append([]validation.Value{}, listOf(model, "economic_relations")...)
	have := map[string]bool{}
	for _, e := range eqs {
		have[objAt(e, "equation").S] = true
	}
	add := func(eq, meaning string, variables []string, breakable []string) {
		if have[eq] {
			return
		}
		eqs = append(eqs, validation.VObj(
			kv("id", validation.VStr(fmt.Sprintf("EQ-%03d", len(eqs)+1))),
			kv("equation", validation.VStr(eq)),
			kv("meaning", validation.VStr(meaning)),
			kv("variables", strArr(variables...)),
			kv("enforced_by", validation.VArr()),
			kv("breakable_by", strArr(breakable...)),
			kv("synthesized", validation.VBool(true)),
		))
	}
	if has(model, "share") {
		add("shares_minted <= economically_justified_shares(deposit)",
			"no share can exist without corresponding backing",
			[]string{"shares", "deposits"},
			[]string{"donation-attack", "first-depositor-rounding",
				"erc4626-inflation"})
	}
	if has(model, "debt") {
		add("collateral_value * liq_threshold >= total_debt",
			"protocol remains solvent under the recorded thresholds",
			[]string{"collateral", "debt"},
			[]string{"oracle-spot-skew", "oracle-staleness",
				"insolvency-by-withdraw-order"})
	}
	if len(protocolgraph.AccountingVars(model)) > 0 {
		add("sum(user_claims) + protocol_liabilities <= total_assets",
			"global accounting conservation",
			[]string{"user_claims", "liabilities", "total_assets"},
			[]string{"donation-attack", "precision-rounding"})
	}
	return eqs
}

// GenerateTransforms is generate_transforms: the deterministic adversarial
// transformation list for trajectory B.
func GenerateTransforms(model validation.Value) []validation.Value {
	out := []validation.Value{}
	for i, entry := range catalog {
		if entry.applies(model) {
			out = append(out, validation.VObj(
				kv("transform_id", validation.VStr(fmt.Sprintf("TR-%03d", i+1))),
				kv("name", validation.VStr(entry.name)),
				kv("question", validation.VStr(entry.question)),
			))
		}
	}
	return out
}

// EquationGaps is equation_gaps: equations with no recorded enforcement or no
// known break paths — gaps mean the economic model is unfinished, not that it
// is safe. `missing` lists the absent halves in fixed order. Synthesized
// templates are skipped: their empty enforced_by is true by construction, so
// reporting them accuses the operator of a gap no operator input can clear
// (the template stays in BuildEquations, adoptable, just not a gap).
func EquationGaps(model validation.Value) []validation.Value {
	gaps := []validation.Value{}
	for _, eq := range BuildEquations(model) {
		if validation.PyTruthy(objAt(eq, "synthesized")) {
			continue // a template ships with empty enforced_by by construction
		}
		enforced := validation.PyTruthy(objAt(eq, "enforced_by"))
		breakable := validation.PyTruthy(objAt(eq, "breakable_by"))
		if enforced && breakable {
			continue
		}
		missing := []validation.Value{}
		if !enforced {
			missing = append(missing, validation.VStr("enforced_by"))
		}
		if !breakable {
			missing = append(missing, validation.VStr("breakable_by"))
		}
		gaps = append(gaps, validation.VObj(
			kv("equation_id", objAt(eq, "id")),
			kv("equation", objAt(eq, "equation")),
			kv("missing", validation.VArr(missing...)),
		))
	}
	return gaps
}

// EconomicSummary is economic_summary: one-glance economic surface for the
// planner — accounting variables, risky asset features, oracle surfaces,
// equation gaps (key order is contractual).
func EconomicSummary(model validation.Value) validation.Value {
	oracles := []validation.Value{}
	for _, o := range protocolgraph.OracleChain(model) {
		oracles = append(oracles, objAt(o, "id"))
	}
	names := []validation.Value{}
	for _, tr := range GenerateTransforms(model) {
		names = append(names, objAt(tr, "name"))
	}
	return validation.VObj(
		kv("accounting_vars", validation.VArr(protocolgraph.AccountingVars(model)...)),
		kv("risky_assets", validation.VArr(protocolgraph.ExternalAssets(model)...)),
		kv("oracles", validation.VArr(oracles...)),
		kv("equations", validation.VInt(int64(len(BuildEquations(model))))),
		kv("equation_gaps", validation.VArr(EquationGaps(model)...)),
		kv("transforms", validation.VArr(names...)),
	)
}
