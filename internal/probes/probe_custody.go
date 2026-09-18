package probes

import (
	"regexp"

	"websec/internal/structidx"
	"websec/internal/validation"
)

var mintCalls = map[string]struct{}{"mint": {}, "_mint": {}, "mintto": {},
	"_mintto": {}, "mintfrom": {}}
var burnCalls = map[string]struct{}{"burn": {}, "_burn": {}, "burnfrom": {},
	"_burnfrom": {}}
var payCalls = map[string]struct{}{"transfer": {}, "safetransfer": {},
	"sendvalue": {}, "transfereth": {}}
var inCalls = map[string]struct{}{"transferfrom": {}, "safetransferfrom": {},
	"safebatchtransferfrom": {}}

var forwardFnRe = regexp.MustCompile(`(?i)^(_?deposit|stake|lock|join|supply|_?mint|_?burn)`)
var recoveryFnRe = regexp.MustCompile(
	`(?i)^(ondrop|drop|refund|recover|rescue|claim|withdraw.*fail|emergency)`)

// custodySite is one (entry, node, primitives) triple of the custody pass.
type custodySite struct {
	entry validation.Value
	node  validation.Value
	prims map[string]struct{}
}

// primitives is _primitives(node): the asset primitives a function performs,
// read off the index's call edges.
func primitives(node validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, call := range vStrList(node, "calls_internal") {
		low := lower(call)
		if _, ok := mintCalls[low]; ok {
			out["mint"] = struct{}{}
		} else if _, ok := burnCalls[low]; ok {
			out["burn"] = struct{}{}
		}
	}
	for _, call := range vStrList(node, "calls_external") {
		low := lower(call)
		method := low
		if i := lastIndexByte(low, '.'); i >= 0 {
			method = low[i+1:]
		}
		switch {
		case inSet(mintCalls, method):
			out["mint"] = struct{}{}
		case inSet(burnCalls, method):
			out["burn"] = struct{}{}
		case inSet(payCalls, method):
			out["transfer-out"] = struct{}{}
		case inSet(inCalls, method):
			out["transfer-in"] = struct{}{}
		}
		if hasPrefix(low, "low-level.") {
			out["send-native"] = struct{}{}
		}
	}
	return out
}

// probeCustodyPrimitive is probe_custody_primitive: a contract whose FORWARD
// path burns/mints while a RECOVERY path pays out of its own balance.
// `inherited` is a ranking signal, never a filter.
func probeCustodyPrimitive(index, model validation.Value) (probeOut, error) {
	if err := structidx.RequireParseVersion(index, "structural index"); err != nil {
		return probeOut{}, err
	}
	fns := functionNodes(index)
	sites := 0
	raw := []validation.Value{}
	blind := []validation.Value{}
	for _, cnode := range contractNodes(index) {
		cname := vStr(cnode, "name")
		forward, recovery := custodySides(cnode, fns, &sites)
		if len(forward) == 0 {
			blind = append(blind, recoveryWithoutForward(cname, recovery)...)
			continue
		}
		if len(recovery) == 0 {
			blind = append(blind, forwardWithoutRecovery(cname, forward))
			continue
		}
		custody := "mints"
		for _, f := range forward {
			if _, burns := f.prims["burn"]; burns {
				custody = "burns"
			}
		}
		names := map[string]struct{}{}
		for _, f := range forward {
			names[vStr(f.entry, "name")] = struct{}{}
		}
		for _, r := range recovery {
			inherited := vStr(r.entry, "defining_contract") != cname
			mods := nodeModifiers(r.node)
			gap := 0
			if inherited {
				gap = 4
			}
			raw = append(raw, rawRow(cname, vStr(r.entry, "name"),
				vInt(r.entry, "line"), custody, TierOfGate(mods, model),
				GateLabel(mods, model), gap, vStr(r.entry, "name"),
				kv("base", validation.VStr(vStr(r.entry, "defining_contract"))),
				kv("base_line", validation.VInt(int64(vInt(r.entry, "line")))),
				kv("custody", validation.VStr(custody)),
				kv("forward", validation.StrArr(sortedStrSet(names))),
				kv("inherited", validation.VBool(inherited))))
		}
	}
	sortBlindFields(blind, "kind", "key", "near")
	return probeOut{sites: sites, rows: raw, blind: limit50(blind),
		blindTotal: len(blind)}, nil
}

// custodySides classifies a contract's closure into forward and recovery
// sites, counting every hit as a site.
func custodySides(cnode validation.Value, fns map[string]validation.Value,
	sites *int) ([]custodySite, []custodySite) {
	forward := []custodySite{}
	recovery := []custodySite{}
	for _, e := range vObjList(cnode, "contract_closure") {
		node, ok := fns[nodeID(e)]
		if !ok {
			continue
		}
		prims := primitives(node)
		if len(prims) == 0 {
			continue
		}
		name := vStr(e, "name")
		if forwardFnRe.MatchString(name) &&
			(inSet(prims, "mint") || inSet(prims, "burn")) {
			forward = append(forward, custodySite{e, node, prims})
			*sites++
		}
		if recoveryFnRe.MatchString(name) &&
			(inSet(prims, "transfer-out") || inSet(prims, "send-native")) {
			recovery = append(recovery, custodySite{e, node, prims})
			*sites++
		}
	}
	return forward, recovery
}

// recoveryWithoutForward is the `not forward` blind branch.
func recoveryWithoutForward(cname string, recovery []custodySite) []validation.Value {
	out := []validation.Value{}
	for _, r := range recovery {
		out = append(out, blindEntry("recovery-without-forward",
			cname+"."+vStr(r.entry, "name"), validation.VNull(),
			kv("contract", validation.VStr(cname)),
			kv("function", validation.VStr(vStr(r.entry, "name"))),
			kv("line", validation.VInt(int64(vInt(r.entry, "line")))),
			kv("reason", validation.VStr(cname+"::"+vStr(r.entry, "name")+
				" pays out of its own balance ("+reprPrims(r.prims)+") but no "+
				"forward path burns or mints — the custody model holds"))))
	}
	return out
}

// forwardWithoutRecovery is the `not recovery` blind branch.
func forwardWithoutRecovery(cname string, forward []custodySite) validation.Value {
	names := map[string]struct{}{}
	for _, f := range forward {
		names[vStr(f.entry, "name")] = struct{}{}
	}
	first := forward[0].entry
	return blindEntry("forward-without-recovery", cname, validation.VNull(),
		kv("contract", validation.VStr(cname)),
		kv("function", validation.VStr(vStr(first, "name"))),
		kv("line", validation.VInt(int64(vInt(first, "line")))),
		kv("reason", validation.VStr(cname+" burns/mints in "+
			reprStrings(sortedStrSet(names))+
			" but has no recovery path paying from self")))
}

// reprPrims is Python's `sorted(prims)` rendered with str().
func reprPrims(prims map[string]struct{}) string {
	return reprStrings(sortedStrSet(prims))
}

// reprStrings is Python str(list-of-str).
func reprStrings(items []string) string { return validation.PyRepr(validation.StrArr(items)) }

func inSet(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}
