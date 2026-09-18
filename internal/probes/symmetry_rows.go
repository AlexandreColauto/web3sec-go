package probes

import (
	"websec/internal/validation"
)

// ---- surface rows ---------------------------------------------------------

// symmetryRawRows builds the custody-primitive rows for a family's
// divergences. The rows ride the existing custody-primitive axis and probe id
// (so dispositions, anchors and the schema keep working); they are prepended
// into the raw list only when the caller opts in.
func symmetryRawRows(index, model validation.Value) ([]validation.Value, map[string]validation.Value) {
	fns := functionNodes(index)
	// (contract, function) -> the node that implements it, so a divergence
	// row carries the same tier/gate modifiers the per-contract probe would
	// have given the site.
	byCF := map[string]validation.Value{}
	for _, cnode := range contractNodes(index) {
		cname := vStr(cnode, "name")
		for _, e := range vObjList(cnode, "contract_closure") {
			if node, ok := fns[nodeID(e)]; ok {
				byCF[cname+"\x00"+vStr(e, "name")] = node
			}
		}
	}
	out := []validation.Value{}
	extras := map[string]validation.Value{}
	for _, famVal := range vObjList(PrimitiveMatrix(index), "families") {
		divs := vObjList(famVal, "divergences")
		if len(divs) > divergenceCap {
			divs = divs[:divergenceCap]
		}
		members := vStrList(famVal, "members")
		// The family's forward (deposit) functions, rendered in the reference
		// probe's `forward` slot so the row reads as a custody row.
		fwd := map[string]struct{}{}
		for _, c := range vObjList(famVal, "cells") {
			if vStr(c, "direction") == "deposit" {
				fwd[vStr(c, "function")] = struct{}{}
			}
		}
		forward := sortedStrSet(fwd)
		for _, d := range divs {
			obs := vGet(d, "observed_site")
			exp := vGet(d, "expected_site")
			contract := vStr(obs, "contract")
			function := vStr(obs, "function")
			line := vInt(obs, "line")
			mods := []string{}
			if node, ok := byCF[contract+"\x00"+function]; ok {
				mods = nodeModifiers(node)
			}
			// `custody` is a schema enum (mints|burns) and the divergence's
			// expected primitive is often neither. Emitting such a value makes
			// `probes run --emit` abort on its own artifact, so the key is
			// omitted when the primitive has no schema value — the row's
			// identity falls back to `observed` (idSlots), and expected/
			// observed still ride the extras map below.
			extra := []validation.KV{
				kv("base", vGet(exp, "contract")),
				kv("base_line", vGet(exp, "line")),
				kv("base_function", vGet(exp, "function")),
			}
			if label := symCustodyLabel(vStr(d, "expected")); label != "" {
				extra = append(extra, kv("custody", validation.VStr(label)))
			}
			extra = append(extra,
				kv("forward", validation.StrArr(forward)),
				kv("inherited", validation.VBool(false)),
				kv("observed", vGet(d, "observed")),
				kv("family", vGet(d, "family")),
				kv("direction", vGet(d, "direction")),
				kv("asset", vGet(d, "asset")),
				kv("divergence", vGet(d, "kind")),
				kv("members", validation.StrArr(members)),
				kv("divergence_question", vGet(d, "question")))
			row := rawRow(contract, function, line,
				vStr(d, "direction")+":"+vStr(d, "asset"), TierOfGate(mods, model),
				GateLabel(mods, model), 4, function, extra...)
			out = append(out, row)
			// finalize copies only the probe's declared fields, so the
			// divergence extras ride a row_id -> dict map into the post-pass.
			withProbe := copyObj(row)
			vSet(&withProbe, "probe", validation.VStr("custody-primitive"))
			extras[RowIDFor(withProbe)] = validation.VObj(
				kv("family", vGet(d, "family")),
				kv("direction", vGet(d, "direction")),
				kv("asset", vGet(d, "asset")),
				kv("divergence", vGet(d, "kind")),
				kv("expected", vGet(d, "expected")),
				kv("expected_asset", vGet(d, "expected_asset")),
				kv("observed", vGet(d, "observed")),
				kv("base_function", vGet(exp, "function")),
				kv("members", validation.StrArr(members)),
				kv("why", vGet(d, "question")))
		}
	}
	return out, extras
}

// symCustodyLabel is the reference probe's `custody` vocabulary ("burns" /
// "mints"): a credit primitive named the way the custody row names the
// forward path. Any other primitive has no schema value — probe_surface's
// custody enum is exactly ["burns", "mints"] — so it maps to "", and the
// caller omits the key rather than write a value the schema rejects.
func symCustodyLabel(primitive string) string {
	switch primitive {
	case "mint":
		return "mints"
	case "burn":
		return "burns"
	}
	return ""
}

// attachSymmetry stamps the divergence extras onto the finalized rows that
// carry them (finalize copies only the probe's declared fields, so the
// family/direction/asset/observed set is set here, after the row shape is
// frozen). The `why` becomes the divergence question, so the operator reads the
// family disagreement rather than the single-contract custody template.
func attachSymmetry(rows []validation.Value,
	extras map[string]validation.Value) []validation.Value {
	for i := range rows {
		ex, ok := extras[vStr(rows[i], "row_id")]
		if !ok {
			continue
		}
		for _, field := range []string{"family", "direction", "asset",
			"divergence", "expected", "expected_asset", "observed",
			"base_function", "members"} {
			vSet(&rows[i], field, vGet(ex, field))
		}
		if q := vStr(ex, "why"); q != "" {
			vSet(&rows[i], "why", validation.VStr(q))
		}
	}
	return rows
}
