package probes

// symmetry.go — IMPROVEMENTS C2: the primitive matrix.
//
// The reference custody-primitive probe asks ONE question per contract: "does a
// recovery path pay out of its own balance while the forward path burns or
// mints?" (probe_custody.go). The systematic question underneath it is asked
// per contract FAMILY: for each inheritance group and each custody direction
// (deposit | withdrawal | drop | recover | other) and asset class (native |
// erc20 | share), which primitive does each member perform — and where do
// siblings disagree?
//
// That is exactly the shape of the morph campaign's G-02: the L1 gateway
// siblings credit deposits one way and move the asset back on the drop path
// another way, and the family-level question "who funds the difference?" was
// never computed. The per-contract probe can only see one side at a time.
//
// Everything here is deterministic over the structural index: the verb table
// is the same one probe_custody.go uses (shared package-level sets), the
// families are union-find over the index's `inherits` edges, and the
// divergences are sorted by (family, direction, asset, kind, observed site), so
// the same index renders byte-identical output.

import (
	"sort"

	"websec/internal/validation"
)

// ---- the matrix -----------------------------------------------------------

// PrimitiveMatrix is IMPROVEMENTS C2: families × (direction, asset) → the
// custody primitive each member performs, plus the divergences between them.
// Pure over the index.
func PrimitiveMatrix(index validation.Value) validation.Value {
	fns := functionNodes(index)
	families := []validation.Value{}
	flat := []symDivergence{}
	cells, members, sites := 0, 0, 0
	for _, fam := range symmetryFamilies(index) {
		memberSet := map[string]struct{}{}
		for _, m := range fam.Members {
			memberSet[m] = struct{}{}
		}
		famCells := []symCell{}
		for _, cnode := range contractNodes(index) {
			cname := vStr(cnode, "name")
			if _, ok := memberSet[cname]; !ok {
				continue
			}
			if symMemberIsTestDouble(cnode) {
				continue
			}
			for _, e := range vObjList(cnode, "contract_closure") {
				node, ok := fns[nodeID(e)]
				if !ok {
					continue
				}
				fn := vStr(e, "name")
				line := vInt(e, "line")
				got := symmetryCells(vStr(e, "defining_contract"), fn, line, node)
				if len(got) == 0 {
					continue
				}
				sites++
				famCells = append(famCells, got...)
			}
		}
		famCells = dedupeSymCells(famCells)
		if len(famCells) == 0 {
			continue
		}
		members += len(fam.Members)
		cells += len(famCells)
		divs := symmetryDivergencesOf(fam.Name, famCells)
		flat = append(flat, divs...)
		families = append(families, validation.VObj(
			kv("name", validation.VStr(fam.Name)),
			kv("members", validation.StrArr(fam.Members)),
			kv("cells", symCellValues(famCells)),
			kv("divergences", symDivergenceValues(divs)),
			kv("divergence_total", validation.VInt(int64(len(divs))))))
	}
	flatSorted := append([]symDivergence(nil), flat...)
	sort.SliceStable(flatSorted, func(i, j int) bool {
		return symDivKey(flatSorted[i]) < symDivKey(flatSorted[j])
	})
	return validation.VObj(
		kv("families", validation.VArr(families...)),
		kv("divergences", symDivergenceValues(flatSorted)),
		kv("stats", validation.VObj(
			kv("families", validation.VInt(int64(len(families)))),
			kv("members", validation.VInt(int64(members))),
			kv("sites", validation.VInt(int64(sites))),
			kv("cells", validation.VInt(int64(cells))),
			kv("divergences", validation.VInt(int64(len(flatSorted)))),
			kv("member_disagreements", validation.VInt(int64(countDivKind(flatSorted, SymMemberDisagreement)))),
			kv("funding_mismatches", validation.VInt(int64(countDivKind(flatSorted, SymFundingMismatch)))),
		)))
}

// SymQuestion is the question a divergence renders (exported so the CLI, the
// surface row and the tests all phrase it the same way).
func SymQuestion(d symDivergence) string { return symQuestion(d) }
