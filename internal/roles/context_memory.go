// context_memory.go: the negative-memory block split out of context.go —
// known_non_issues, memory-row loading/leakage partition and row summarizing.
package roles

import (
	"fmt"
	"slices"
	"sort"
	"websec/internal/learning"
	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/validation"
)

// knownNonIssues is _known_non_issues: the negative-memory block. Prior
// observations that are NOT proof of safety, each surfaced with its retrieval
// metadata.
func knownNonIssues(campaign *state.Campaign, bugClass *string,
	limit int) (validation.Value, error) {
	rows, err := loadMemoryRows(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	negative := rankNegative(negativeRows(devRows(rows)), bugClass)
	active, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	activePin := ""
	if active != nil {
		activePin = *active
	}
	summarized := []validation.Value{}
	for i, row := range negative {
		if i >= limit {
			break
		}
		summarized = append(summarized, summarizeNonIssue(row, activePin))
	}
	return validation.VObj(
		validation.KV{K: "authoritative", V: validation.VBool(false)},
		validation.KV{K: "label", V: validation.VStr(
			"KNOWN NON-ISSUES (prior observations; not proof of safety)")},
		validation.KV{K: "override_rule", V: validation.VStr("If a prior is " +
			"believed to no longer apply, state which assumption differs " +
			"from it (name the assumption id and the prior's memory_id in " +
			"differs_from_memory). A materially different hypothesis is " +
			"never suppressed by this block.")},
		validation.KV{K: "staleness_note", V: validation.VStr("rows with " +
			"pin_diverged=true were learned against a different snapshot " +
			"pin: their code-reality claims are suspect until re-checked " +
			"against the active pin. rows with policy_contingent=true go " +
			"stale when the program's threshold or the protocol's TVL " +
			"changes.")},
		validation.KV{K: "known_non_issues", V: validation.VArr(summarized...)},
	), nil
}

// loadMemoryRows is every candidate row: the campaign's own memory store,
// read through learning.AllMemory, then the shared store (wrapped {scope,
// program_key, row} entries unwrapped to the flat shape).
//
// r44c: this used to re-list memory/ with its own os.ReadDir and its own
// tolerance — every listing error was folded into "no local rows", and a row
// whose JSON did not parse was silently SKIPPED. learning.AllMemory is the
// one implementation of that listing (validation.ListPrefixedOptional, the
// r43 helper): absence of the store stays an empty campaign, and anything
// else refuses naming the store. Two readers with the same job and opposite
// tolerances are a bug; there is now one. The shared-store half is read by
// its one home too (sharedmem.LoadSharedMemory) and its refusal propagates:
// a proposer-context block built while a prior store could not be listed
// would tell the model "no priors", which is a claim the read does not
// support.
func loadMemoryRows(campaign *state.Campaign) ([]validation.Value, error) {
	rows, err := learning.AllMemory(campaign)
	if err != nil {
		return nil, err
	}
	wrapped, err := sharedmem.LoadSharedMemory(campaign.Root)
	if err != nil {
		return nil, fmt.Errorf(
			"the shared memory store for %s cannot be read: %v",
			campaign.Root, err)
	}
	for _, w := range wrapped {
		if w.Kind == validation.Obj {
			if r := validation.ObjAt(w, "row"); r.Kind != validation.Null {
				rows = append(rows, r)
				continue
			}
		}
		rows = append(rows, w)
	}
	return rows, nil
}

// devRows is the leakage-partition guard: held-out/training rows are
// evaluation data and must NEVER surface in proposer-context injection.
// Absent partition == 'dev'.
func devRows(rows []validation.Value) []validation.Value {
	dev := []validation.Value{}
	for _, r := range rows {
		if r.Kind != validation.Obj {
			continue
		}
		p := validation.ObjAt(r, "partition")
		if p.Kind == validation.Null || (p.Kind == validation.Str &&
			p.S == "dev") {
			dev = append(dev, r)
		}
	}
	return dev
}

// negativeRows is the rows whose status is a known non-issue.
func negativeRows(dev []validation.Value) []validation.Value {
	negative := []validation.Value{}
	for _, r := range dev {
		st := validation.ObjAt(r, "status")
		if st.Kind == validation.Str && slices.Contains(NegativeStatuses, st.S) {
			negative = append(negative, r)
		}
	}
	return negative
}

// rankNegative is the deterministic recall order: same-bug-class rows first,
// then created_at ascending.
func rankNegative(negative []validation.Value,
	bugClass *string) []validation.Value {
	sort.SliceStable(negative, func(i, j int) bool {
		ci, cj := int64(1), int64(1)
		if bugClass != nil && validation.ObjStr(negative[i], "bug_class") == *bugClass {
			ci = 0
		}
		if bugClass != nil && validation.ObjStr(negative[j], "bug_class") == *bugClass {
			cj = 0
		}
		if ci != cj {
			return ci < cj
		}
		return validation.ObjStr(negative[i], "created_at") < validation.ObjStr(negative[j], "created_at")
	})
	return negative
}

// summarizeNonIssue is one surfaced row: bounded text, the retrieval metadata
// the model needs to judge applicability (pin divergence, policy contingency,
// schema version), never the raw record.
func summarizeNonIssue(row validation.Value, activePin string) validation.Value {
	rejectionClass := validation.ObjAt(row, "rejection_class")
	if rejectionClass.Kind == validation.Null {
		rc := learning.RejectionClassForStatus(validation.ObjStr(row, "status"))
		if rc != "" {
			rejectionClass = validation.VStr(rc)
		}
	}
	rowPin := validation.ObjStr(row, "snapshot_id")
	// deciding_propositions is passed through VERBATIM for v2 rows (Python:
	// `row.get("deciding_propositions") if schema_version >= 2 else []`), so
	// an absent/None field serializes as null, not [] — the v2 schema makes
	// the distinction load-bearing for the boundary's differs_from_memory
	// check. v1 rows carry no proposition structure and always emit [].
	deciding := validation.VArr()
	if sv := validation.ObjAt(row, "schema_version"); sv.Kind == validation.Int &&
		sv.I >= 2 {
		deciding = validation.ObjAt(row, "deciding_propositions")
	}
	policyContingent := false
	if rejectionClass.Kind == validation.Str {
		policyContingent = rejectionClass.S == "below-threshold"
	}
	return validation.VObj(
		validation.KV{K: "memory_id", V: validation.ObjAt(row, "memory_id")},
		validation.KV{K: "status", V: validation.ObjAt(row, "status")},
		validation.KV{K: "rejection_class", V: rejectionClass},
		validation.KV{K: "bug_class", V: validation.ObjAt(row, "bug_class")},
		validation.KV{K: "cwe", V: validation.ObjAt(row, "cwe")},
		validation.KV{K: "pattern",
			V: validation.VStr(truncate(validation.ObjStr(row, "pattern"), 300))},
		validation.KV{K: "evidence_summary",
			V: validation.VStr(truncate(validation.ObjStr(row, "evidence_summary"), 200))},
		validation.KV{K: "deciding_propositions", V: deciding},
		validation.KV{K: "pin_diverged",
			V: validation.VBool(rowPin != "" && activePin != "" &&
				rowPin != activePin)},
		validation.KV{K: "policy_contingent", V: validation.VBool(policyContingent)},
		validation.KV{K: "schema_version",
			V: defaultedInt(validation.ObjAt(row, "schema_version"), 1)})
}

// KnownNonIssues is _known_non_issues through the exported seam the model
// boundary's memory-utility signal uses.
func KnownNonIssues(campaign *state.Campaign, bugClass *string,
	limit int) (validation.Value, error) {
	return knownNonIssues(campaign, bugClass, limit)
}
