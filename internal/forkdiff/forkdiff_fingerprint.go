package forkdiff

import (
	"regexp"
	"sort"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,40}$`)
	strong  = 0.6
	partial = 0.4
)

// FingerprintTree is fingerprint_tree: the content-addressable shape of a
// source tree, from the T0 parser.
func FingerprintTree(root string) (validation.Value, error) {
	tree, err := structidx.IndexTreeValue(root)
	if err != nil {
		return validation.VNull(), err
	}
	nodes := objListAt(tree, "nodes")
	contracts, selectors, stateVars, modifiers, deleg := []string{},
		[]string{}, []string{}, []string{}, []string{}
	selSeen := map[string]bool{}
	for _, n := range nodes {
		switch validation.ObjStr(n, "kind") {
		case "contract", "interface", "library":
			contracts = append(contracts, validation.ObjStr(n, "name"))
		case "function":
			if s := validation.ObjStr(n, "selector"); s != "" && !selSeen[s] {
				selSeen[s] = true
				selectors = append(selectors, s)
			}
			if len(objListAt(n, "delegatecalls")) > 0 {
				deleg = append(deleg, validation.ObjStr(n, "id"))
			}
		case "state-variable":
			stateVars = append(stateVars, validation.ObjStr(n, "name"))
		case "modifier":
			modifiers = append(modifiers, validation.ObjStr(n, "name"))
		}
	}
	sort.Strings(contracts)
	sort.Strings(selectors)
	sort.Strings(stateVars)
	sort.Strings(modifiers)
	sort.Strings(deleg)
	inherits := []string{}
	for _, e := range objListAt(tree, "edges") {
		if validation.ObjStr(e, "rel") != "inherits" {
			continue
		}
		from := validation.ObjStr(e, "from")
		to := validation.ObjStr(e, "to")
		if i := strings.Index(from, "#"); i >= 0 {
			from = from[i+1:]
		}
		if i := strings.Index(to, "#"); i >= 0 {
			to = to[i+1:]
		}
		inherits = append(inherits, from+"->"+to)
	}
	sort.Strings(inherits)
	return validation.VObj(
		validation.KV{K: "contracts", V: validation.StrArr(contracts)},
		validation.KV{K: "selectors", V: validation.StrArr(selectors)},
		validation.KV{K: "state_vars", V: validation.StrArr(stateVars)},
		validation.KV{K: "modifiers", V: validation.StrArr(modifiers)},
		validation.KV{K: "delegatecall_functions", V: validation.StrArr(deleg)},
		validation.KV{K: "inherits", V: validation.StrArr(inherits)},
	), nil
}

// FingerprintSha256 is fingerprint_sha256: canonical JSON + sha256. The
// canonical dump is ensure_ascii, so the utf-8 encoding is the identity.
func FingerprintSha256(fp validation.Value) string {
	return validation.Sha256Hex([]byte(validation.CanonCompact(fp)))
}

// jaccard is _jaccard: set intersection over union; two empty sets are
// identical surface, not dissimilar.
func jaccard(a, b []string) float64 {
	A, B := map[string]bool{}, map[string]bool{}
	for _, x := range a {
		A[x] = true
	}
	for _, x := range b {
		B[x] = true
	}
	inter, union := 0, 0
	for k := range A {
		if B[k] {
			inter++
		}
	}
	seen := map[string]bool{}
	for k := range A {
		seen[k] = true
	}
	for k := range B {
		seen[k] = true
	}
	union = len(seen)
	if union == 0 {
		return 1.0
	}
	return float64(inter) / float64(union)
}

// Match is match: weighted Jaccard against one baseline.
//
//	score = 0.5*J(selectors) + 0.3*J(state_vars) + 0.1*J(modifiers)
//	      + 0.1*J(contracts); strong >= 0.6, partial >= 0.4.
func Match(targetFP, baselineFP validation.Value, name string) validation.Value {
	js := jaccard(strs(targetFP, "selectors"), strs(baselineFP, "selectors"))
	jv := jaccard(strs(targetFP, "state_vars"), strs(baselineFP, "state_vars"))
	jm := jaccard(strs(targetFP, "modifiers"), strs(baselineFP, "modifiers"))
	jc := jaccard(strs(targetFP, "contracts"), strs(baselineFP, "contracts"))
	score := validation.PyRound(0.5*js+0.3*jv+0.1*jm+0.1*jc, 4)
	verdict := "none"
	if score >= strong {
		verdict = "strong"
	} else if score >= partial {
		verdict = "partial"
	}
	extra := difference(strs(targetFP, "selectors"), strs(baselineFP, "selectors"))
	missing := difference(strs(baselineFP, "selectors"), strs(targetFP, "selectors"))
	return validation.VObj(
		validation.KV{K: "baseline", V: validation.VStr(name)},
		validation.KV{K: "jaccard", V: validation.VObj(
			validation.KV{K: "selectors", V: validation.VFloat(validation.PyRound(js, 4))},
			validation.KV{K: "state_vars", V: validation.VFloat(validation.PyRound(jv, 4))},
			validation.KV{K: "modifiers", V: validation.VFloat(validation.PyRound(jm, 4))},
			validation.KV{K: "contracts", V: validation.VFloat(validation.PyRound(jc, 4))},
		)},
		validation.KV{K: "score", V: validation.VFloat(score)},
		validation.KV{K: "verdict", V: validation.VStr(verdict)},
		validation.KV{K: "extra_selectors", V: validation.StrArr(extra)},
		validation.KV{K: "missing_selectors", V: validation.StrArr(missing)},
	)
}

func difference(a, b []string) []string {
	B := map[string]bool{}
	for _, x := range b {
		B[x] = true
	}
	seen := map[string]bool{}
	out := []string{}
	for _, x := range a {
		if B[x] || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func strs(v validation.Value, key string) []string {
	x := validation.ObjAt(v, key)
	if x.Kind != validation.Arr {
		return nil
	}
	out := make([]string, 0, len(x.A))
	for _, e := range x.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

func objListAt(v validation.Value, key string) []validation.Value {
	x := validation.ObjAt(v, key)
	if x.Kind != validation.Arr {
		return nil
	}
	return x.A
}
