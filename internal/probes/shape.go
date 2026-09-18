package probes

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
	"strings"

	"websec/internal/validation"
)

// shapeAnchorFields is _SHAPE_ANCHOR_FIELDS.
var shapeAnchorFields = []string{"consumer", "asserter", "guard", "base",
	"actor", "invariant", "cursor", "sentinel", "safety", "rounded", "plain",
	"accumulator", "companion"}

// shapeClassFields is _SHAPE_CLASS_FIELDS.
var shapeClassFields = []string{"own_class", "assert_class"}

// probeRiskMap is PROBE_RISK.
var probeRiskMap = map[string]float64{"high": 0.9, "medium": 0.7, "low": 0.6}

// anchorSite is _ANCHOR_SITE: anchor -> (contract field, line field).
var anchorSite = map[string][2]string{
	"consumer": {"contract", "consumer_line"},
	"asserter": {"contract", "asserter_line"},
	"guard":    {"contract", "guard_line"},
	"base":     {"base", "base_line"},
	"cursor":   {"contract", "consumer_line"},
	"rounded":  {"contract", "rounded_line"},
	"plain":    {"contract", "plain_line"},
}

// RowShapeSha is row_shape_sha: sha256[:16] of the canonical JSON of the row's
// whole coordinate set.
func RowShapeSha(row validation.Value) string {
	slots := []validation.Value{}
	for _, f := range shapeAnchorFields {
		slots = append(slots, validation.VArr(
			validation.VStr(f), vGet(row, f), vGet(row, f+"_line")))
	}
	for _, f := range shapeClassFields {
		slots = append(slots, validation.VArr(validation.VStr(f), vGet(row, f)))
	}
	slots = append(slots, sortedSitePairs(vList(row, "siblings")))
	stranded := []string{}
	for _, e := range vList(row, "stranded_entry") {
		stranded = append(stranded, pyStr(e))
	}
	sort.Strings(stranded)
	slots = append(slots, validation.StrArr(stranded))
	canonical := validation.Canon(validation.VArr(slots...), true)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])[:16]
}

// sortedSitePairs is sorted([_site_pair(s) ...], key=(str(contract), str(line))).
func sortedSitePairs(sites []validation.Value) validation.Value {
	pairs := make([][2]validation.Value, 0, len(sites))
	for _, s := range sites {
		pairs = append(pairs, [2]validation.Value{
			vGet(s, "contract"), vGet(s, "line")})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if a, b := pyStr(pairs[i][0]), pyStr(pairs[j][0]); a != b {
			return a < b
		}
		return pyStr(pairs[i][1]) < pyStr(pairs[j][1])
	})
	out := make([]validation.Value, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, validation.VArr(p[0], p[1]))
	}
	return validation.VArr(out...)
}

// ProbeRisk is probe_risk: tier 0 AND gap >= 3 -> high; tier 0 OR gap >= 2 ->
// medium; otherwise low.
func ProbeRisk(row validation.Value) (string, float64) {
	tier := vInt(row, "tier")
	gap := vInt(row, "assertion_gap")
	band := "low"
	switch {
	case tier == 0 && gap >= 3:
		band = "high"
	case tier == 0 || gap >= 2:
		band = "medium"
	}
	return band, probeRiskMap[band]
}

// RowAnchorPairs is row_anchor_pairs: the row's `file#L` pairs in the probe's
// declared anchor order.
func RowAnchorPairs(row validation.Value, index *validation.Value) []string {
	paths := map[string]string{}
	hasIndex := index != nil
	if hasIndex {
		paths = contractPaths(*index)
	}
	out := []string{}
	probeID := vStr(row, "probe")
	spec, ok := probesTable[probeID]
	if !ok {
		return out
	}
	for _, anchor := range spec.anchors {
		sites := [][2]validation.Value{}
		switch {
		case anchor == "sibling":
			for _, s := range vList(row, "siblings") {
				sites = append(sites, [2]validation.Value{
					vGet(s, "contract"), vGet(s, "line")})
			}
		default:
			if fields, ok := anchorSite[anchor]; ok {
				line := vGet(row, fields[1])
				if line.Kind == validation.Int && line.I > 0 {
					sites = append(sites, [2]validation.Value{
						vGet(row, fields[0]), line})
				}
			}
		}
		for _, s := range sites {
			line := s[1]
			if line.Kind != validation.Int || line.I <= 0 {
				continue
			}
			contract := s[0]
			contractStr := ""
			if contract.Kind == validation.Str {
				contractStr = contract.S
			}
			token, resolved := resolveAnchorToken(paths, hasIndex, contractStr)
			if !resolved {
				continue // unresolvable with an index: no fabricated citation
			}
			pair := token + "#L" + itoa(int(line.I))
			if !slices.Contains(out, pair) {
				out = append(out, pair)
			}
		}
	}
	return out
}

// RowQuestion is row_question: the probe's own why_template rendered with the
// row's values, then the row's file#L anchors inline.
func RowQuestion(row validation.Value, index *validation.Value) (string, error) {
	spec, ok := probesTable[vStr(row, "probe")]
	if !ok {
		return "", errf("unknown probe %s", validation.PyReprStr(vStr(row, "probe")))
	}
	text := formatMap(spec.whyTemplate, row)
	pairs := RowAnchorPairs(row, index)
	if len(pairs) > 0 {
		return text + " [anchors: " + strings.Join(pairs, ", ") + "]", nil
	}
	return text, nil
}

// RowAnchorValue is row_anchor_value: the value a `--anchor` disposition
// cites; an anchor outside the probe's enum raises.
func RowAnchorValue(row validation.Value, anchor string) (validation.Value, error) {
	probeID := vStr(row, "probe")
	if !AnchorAllowed(probeID, anchor) {
		return validation.VNull(), errf(
			"anchor %s is not produced by probe %s; allowed: %s",
			validation.PyReprStr(anchor), validation.PyReprStr(probeID),
			reprAnchors(probeID))
	}
	field, ok := anchorField(probeID, anchor)
	if !ok {
		return validation.VNull(), errf("anchor %s is not produced by probe %s; allowed: %s",
			validation.PyReprStr(anchor), validation.PyReprStr(probeID),
			reprAnchors(probeID))
	}
	if !vHas(row, field) {
		return validation.VNull(), errf("row of %s has no field %s",
			validation.PyReprStr(probeID), validation.PyReprStr(field))
	}
	return vGet(row, field), nil
}

// reprAnchors is Python's repr of PROBES.get(probe_id, {}).get("anchors").
func reprAnchors(probeID string) string {
	spec, ok := probesTable[probeID]
	if !ok {
		return "None"
	}
	return validation.PyRepr(validation.StrArr(spec.anchors))
}

// AnchorRef is anchor_ref: the falsifiable citation a disposition records for
// ONE anchor field.
func AnchorRef(row validation.Value, anchor string,
	index *validation.Value) (string, error) {
	value, err := RowAnchorValue(row, anchor)
	if err != nil {
		return "", err
	}
	if anchor == "sibling" {
		paths := map[string]string{}
		hasIndex := index != nil
		if hasIndex {
			paths = contractPaths(*index)
		}
		pairs := []string{}
		for _, s := range vList(row, "siblings") {
			line := vGet(s, "line")
			if line.Kind != validation.Int || line.I <= 0 {
				continue
			}
			contract := vStr(s, "contract")
			token, resolved := resolveAnchorToken(paths, hasIndex, contract)
			if !resolved {
				continue
			}
			pair := token + "#L" + itoa(int(line.I))
			if !slices.Contains(pairs, pair) {
				pairs = append(pairs, pair)
			}
		}
		if len(pairs) > 0 {
			return strings.Join(pairs, ", "), nil
		}
		return renderAnchorValue(value), nil
	}
	if fields, ok := anchorSite[anchor]; ok {
		line := vGet(row, fields[1])
		if line.Kind == validation.Int && line.I > 0 {
			paths := map[string]string{}
			hasIndex := index != nil
			if hasIndex {
				paths = contractPaths(*index)
			}
			contract := vStr(row, fields[0])
			token, resolved := resolveAnchorToken(paths, hasIndex, contract)
			if resolved {
				return token + "#L" + itoa(int(line.I)), nil
			}
			// Unresolvable with an index: fall through to the raw value
			// rather than fabricate a "Name#L" citation.
		}
	}
	return renderAnchorValue(value), nil
}

// renderAnchorValue is _render_anchor_value.
func renderAnchorValue(value validation.Value) string {
	switch value.Kind {
	case validation.Arr:
		parts := make([]string, 0, len(value.A))
		for _, v := range value.A {
			parts = append(parts, pyStr(v))
		}
		return strings.Join(parts, ", ")
	case validation.Obj:
		return validation.CanonSpaced(value)
	}
	return pyStr(value)
}
