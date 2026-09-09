package probes

import (
	"sort"

	"websec/internal/validation"
)

// probeOut is one probe's raw output dict: `sites` (raw hits before the shape
// discriminator), the post-discriminator `rows`, and the published `blind[]`
// keys (a probe that SAW sites and rejected every one is not silent).
type probeOut struct {
	sites      int
	rows       []validation.Value
	blind      []validation.Value
	blindTotal int
}

// probeSpec is one PROBES[probe_id] entry. fn is the pure function over
// (index, model); merge folds two raw rows that share (contract, function,
// line) into one; sortName is the probe's own deterministic tiebreak name.
type probeSpec struct {
	axis        string
	lens        string
	rank        []string
	whyTemplate string
	gapRule     string
	anchors     []string
	fields      []string
	fn          func(index, model validation.Value) (probeOut, error)
	merge       func(group *groupState, raw validation.Value)
	sortName    func(row validation.Value) string
}

// probesTable is PROBES, verbatim: the registry the engine, the closure
// clause, the cockpit and the blank store all read.
var probesTable = map[string]*probeSpec{
	"assertion-strength": {
		axis: "enforcement-timing", lens: "L-03",
		rank: []string{"tier", "-assertion_gap", "siblings", "function_name"},
		whyTemplate: "{concept_keys} is asserted as equality-to-persisted-state in " +
			"{asserter}#{asserter_line} (class {assert_class}) but consumed by " +
			"{consumer}#{consumer_line} under a class-{own_class} guard — does " +
			"{consumer} verify {concept_keys} itself?",
		gapRule: "4 - own_class (the row's weakest guard class for the concept)",
		anchors: []string{"consumer", "asserter", "concept"},
		fields: []string{"contract", "consumer", "consumer_line", "asserter",
			"asserter_line", "concept_keys", "own_class", "assert_class"},
		fn:       probeAssertionStrength,
		merge:    mergeAssertion,
		sortName: func(row validation.Value) string { return vStr(row, "function") },
	},
	"custody-primitive": {
		axis: "primitive-symmetry", lens: "L-04",
		rank: []string{"tier", "-assertion_gap", "siblings", "function_name"},
		whyTemplate: "{contract}::{consumer} (defined in {base}#{base_line}, " +
			"inherited={inherited}) pays out of its own balance while the " +
			"forward path {forward} {custody} — who funds the payout?",
		gapRule: "4 when the recovery path is inherited, else 0",
		anchors: []string{"consumer", "base", "custody", "sibling"},
		fields: []string{"contract", "consumer", "consumer_line", "base", "base_line",
			"custody", "forward", "inherited"},
		fn:       probeCustodyPrimitive,
		merge:    mergeFirst,
		sortName: func(row validation.Value) string { return vStr(row, "function") },
	},
	"trust-assumption": {
		axis: "incentive-inversion", lens: "L-02",
		rank: []string{"tier", "-assertion_gap", "siblings", "function_name"},
		whyTemplate: "{invariant} ({kind}) relies on {actor} ({trust}) — does it still " +
			"hold if {actor} is dishonest? {statement}",
		gapRule:  "0 (the actor's trust already sets the tier)",
		anchors:  []string{"actor", "invariant"},
		fields:   []string{"actor", "invariant", "trust", "kind", "statement"},
		fn:       probeTrustAssumption,
		merge:    mergeFirst,
		sortName: func(row validation.Value) string { return vStr(row, "actor") },
	},
	"sequential-cursor": {
		axis: "liveness", lens: "L-01",
		rank: []string{"tier", "-assertion_gap", "siblings", "function_name"},
		whyTemplate: "{consumer}#{consumer_line} requires `{guard}` over cursor " +
			"{cursor} — can any of {stranded_entry} strand every later batch?",
		gapRule: "0 (the cursor guard is the whole signal)",
		anchors: []string{"guard", "cursor", "stranded_entry"},
		fields: []string{"contract", "consumer", "consumer_line", "guard",
			"guard_line", "cursor", "stranded_entry"},
		fn:       probeSequentialCursor,
		merge:    mergeFirst,
		sortName: func(row validation.Value) string { return vStr(row, "function") },
	},
	"short-circuitable-guard": {
		axis: "guard-short-circuit", lens: "L-01",
		rank: []string{"tier", "-assertion_gap", "siblings", "function_name"},
		whyTemplate: "{contract}::{consumer}#{consumer_line} checks `{guard}` as ONE " +
			"conjunction: `{sentinel}` is a non-zero sentinel, so while it is " +
			"false `{safety}` is never evaluated — can {consumer} be reached " +
			"in that state?",
		gapRule: "0 (the sentinel conjunct is the whole signal)",
		anchors: []string{"guard", "sentinel", "safety"},
		fields: []string{"contract", "consumer", "consumer_line", "guard",
			"guard_line", "sentinel", "safety"},
		fn:       probeShortCircuitableGuard,
		merge:    mergeFirst,
		sortName: func(row validation.Value) string { return vStr(row, "function") },
	},
	"accumulator-basis-skew": {
		axis: "accumulator-skew", lens: "L-01",
		rank: []string{"tier", "-assertion_gap", "siblings", "function_name"},
		whyTemplate: "{contract}::{consumer}#{consumer_line} updates `{accumulator}` " +
			"through a rounding primitive (line {rounded_line}) while " +
			"`{companion}` is written at line {plain_line} — can " +
			"{accumulator} round away while {companion} still moves?",
		gapRule: "0 (the rounding asymmetry is the whole signal)",
		anchors: []string{"rounded", "plain", "accumulator", "companion"},
		fields: []string{"contract", "consumer", "consumer_line", "rounded_line",
			"plain_line", "accumulator", "companion"},
		fn:       probeAccumulatorBasisSkew,
		merge:    mergeFirst,
		sortName: func(row validation.Value) string { return vStr(row, "function") },
	},
}

// anchorFields is ANCHOR_FIELDS: the disposition anchor enum is PER PROBE — an
// anchor cannot be cited that the probe never produced.
var anchorFields = map[string]map[string]string{
	"assertion-strength": {"consumer": "consumer", "asserter": "asserter",
		"concept": "concept_keys"},
	"custody-primitive": {"consumer": "consumer", "base": "base",
		"custody": "custody", "sibling": "siblings"},
	"trust-assumption": {"actor": "actor", "invariant": "invariant"},
	"sequential-cursor": {"guard": "guard", "cursor": "cursor",
		"stranded_entry": "stranded_entry"},
	"short-circuitable-guard": {"guard": "guard", "sentinel": "sentinel",
		"safety": "safety"},
	"accumulator-basis-skew": {"rounded": "rounded_line",
		"plain": "plain_line", "accumulator": "accumulator",
		"companion": "companion"},
}

// RawProbe is spec["fn"](index, model) for one registered probe: the raw
// output dict (sites, rows, blind, blind_total) the parity harness and the
// tests compare against Python.
func RawProbe(index, model validation.Value, probeID string) (validation.Value, error) {
	spec, ok := probesTable[probeID]
	if !ok {
		return validation.VNull(), errf("unknown probe %s", validation.PyReprStr(probeID))
	}
	out, err := spec.fn(index, model)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		kv("sites", validation.VInt(int64(out.sites))),
		kv("rows", validation.VArr(out.rows...)),
		kv("blind", validation.VArr(out.blind...)),
		kv("blind_total", validation.VInt(int64(out.blindTotal))),
	), nil
}

// NormTokens is _norm_tokens, exported for the parity harness.
func NormTokens(name string) []string { return normTokens(name) }

// ProbeIDs is probe_ids(): sorted registry keys.
func ProbeIDs() []string {
	out := make([]string, 0, len(probesTable))
	for pid := range probesTable {
		out = append(out, pid)
	}
	sort.Strings(out)
	return out
}

// AnchorEnum is anchor_enum(): every anchor ANY registered probe can produce,
// sorted. The CLI's `--anchor` help is generated from this, so help and
// registry cannot drift.
func AnchorEnum() []string {
	set := map[string]struct{}{}
	for _, spec := range probesTable {
		for _, a := range spec.anchors {
			set[a] = struct{}{}
		}
	}
	return sortedStrSet(set)
}

// AxisMeta is one registered_axes() entry: axis -> {axis, probe, lens}.
type AxisMeta struct {
	Axis  string
	Probe string
	Lens  string
}

// RegisteredAxes is registered_axes(): axis name -> meta, sorted by axis. A6
// gave lens L-01 three probes, so the KEY stays the unique axis NAME and the
// lens is the grouping.
func RegisteredAxes() map[string]AxisMeta {
	out := map[string]AxisMeta{}
	for _, pid := range ProbeIDs() {
		spec := probesTable[pid]
		out[spec.axis] = AxisMeta{Axis: spec.axis, Probe: pid, Lens: spec.lens}
	}
	return out
}

// AxisScope is axis_scope(token): `L-0n` -> EVERY axis on that lens; an axis
// name -> just it; nil when the token is neither.
type AxisScope struct {
	Token string
	Lens  string
	Axes  []string
}

// AxisScopeOf resolves a CLI `--axis` token.
func AxisScopeOf(token string) *AxisScope {
	token = strip(token)
	reg := RegisteredAxes()
	if meta, ok := reg[token]; ok {
		return &AxisScope{Token: token, Lens: meta.Lens, Axes: []string{token}}
	}
	axes := []string{}
	for _, ax := range sortedKeys(reg) {
		if reg[ax].Lens == token {
			axes = append(axes, ax)
		}
	}
	if len(axes) > 0 {
		return &AxisScope{Token: token, Lens: token, Axes: axes}
	}
	return nil
}

// ResolveAxis is resolve_axis(token): `L-0n` or the probe axis name ->
// {axis, probe, lens}, else nil.
func ResolveAxis(token string) *AxisMeta {
	token = strip(token)
	reg := RegisteredAxes()
	for _, ax := range sortedKeys(reg) {
		meta := reg[ax]
		if token == ax || token == meta.Lens {
			m := meta
			return &m
		}
	}
	return nil
}

// AnchorAllowed is anchor_allowed(probe_id, anchor).
func AnchorAllowed(probeID, anchor string) bool {
	spec, ok := probesTable[probeID]
	if !ok {
		return false
	}
	for _, a := range spec.anchors {
		if a == anchor {
			return true
		}
	}
	return false
}

// anchorField is ANCHOR_FIELDS[probe_id][anchor].
func anchorField(probeID, anchor string) (string, bool) {
	m, ok := anchorFields[probeID]
	if !ok {
		return "", false
	}
	f, ok := m[anchor]
	return f, ok
}
