package probes

// stages.go — IMPROVEMENTS C1, the surface half: attach the enforcement stage
// table to the assertion-strength rows.
//
// The reference surface answers "this concept is asserted at class 4 in
// {asserter} and consumed by {consumer} under a class-{own_class} guard". That
// is a single (assertion, consumer) pair. The question underneath it — where
// is the value WRITTEN, where is it READ, and does any assertion about it
// cover the write -> read stage? — is deterministic over the index
// (structidx.EnforcementTable) and the reference never computed it.
//
// The rows keep their reference shape: `stages_unguarded` and
// `stages_unguarded_total` are appended only to the rows that have something
// to say, and only when the caller opts in (ProbeOpts.StageTables). The zero
// value of ProbeOpts reproduces the reference surface byte-for-byte, which is
// what the parity goldens pin. A pair is carried when it is not fully covered:
// the write side or the read side (or both) carries no assertion about the
// concept key, and each carried pair says which side is which.

import (
	"websec/internal/structidx"
	"websec/internal/validation"
)

// stageRowCap bounds the pairs carried on one row; the total is always
// published next to it, so a cap never hides work.
const stageRowCap = 8

// attachStageTables appends the uncovered (write, read) stage pairs of each
// row's concept keys, scoped to the row's own contract. Rows with no uncovered
// pair are left exactly as the reference wrote them. memo caches the table
// lookup per (contract, concept key) across the surface.
func attachStageTables(index validation.Value, rows []validation.Value,
	memo map[string][]validation.Value) []validation.Value {
	for i := range rows {
		contract := vStr(rows[i], "contract")
		keys := vStrList(rows[i], "concept_keys")
		carried := []validation.Value{}
		total := 0
		for _, key := range keys {
			cacheKey := contract + "\x00" + key
			pairs, ok := memo[cacheKey]
			if !ok {
				pairs = unguardedStages(index, contract, key)
				memo[cacheKey] = pairs
			}
			for _, p := range pairs {
				total++
				if len(carried) < stageRowCap {
					carried = append(carried, p)
				}
			}
		}
		if total == 0 {
			continue
		}
		vSet(&rows[i], "stages_unguarded", validation.VArr(carried...))
		vSet(&rows[i], "stages_unguarded_total", validation.VInt(int64(total)))
	}
	return rows
}

// unguardedStages is the (write, read) stage pairs of one concept key inside
// one contract that are not fully covered by an assertion about the key.
func unguardedStages(index validation.Value, contract, key string) []validation.Value {
	tbl := structidx.EnforcementTableOpts(index, key,
		structidx.EnforcementOpts{Contract: contract})
	out := []validation.Value{}
	for _, p := range vObjList(tbl, "stages") {
		if gap := vGet(p, "gap"); gap.Kind != validation.Bool || !gap.B {
			continue
		}
		out = append(out, validation.VObj(
			kv("write", stageRef(vGet(p, "write"))),
			kv("read", stageRef(vGet(p, "read"))),
			kv("write_guarded", vGet(p, "write_guarded")),
			kv("read_guarded", vGet(p, "read_guarded")),
			kv("contract", validation.VStr(contract)),
			kv("concept", validation.VStr(key))))
	}
	return out
}

// stageRef is the compact site identity of one end of a stage pair.
func stageRef(site validation.Value) validation.Value {
	return validation.VObj(
		kv("function", vGet(site, "function")),
		kv("line", vGet(site, "line")),
		kv("kind", vGet(site, "kind")))
}
