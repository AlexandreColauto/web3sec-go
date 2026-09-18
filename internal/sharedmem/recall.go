// recall: the derived, advisory cross-campaign query over signatures and
// memory rows.

package sharedmem

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"websec/internal/capabilities"
	"websec/internal/chainengine"
	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- recall ----------------------------------------------------------------

// candidateProvides is _candidate_provides.
func candidateProvides(c *state.Campaign, candidate validation.Value) (map[string]struct{}, error) {
	pin := validation.ObjStr(validation.ObjAt(candidate, "snapshot_ids"), "source")
	provides := map[string]struct{}{}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return nil, err
	}
	for _, f := range all {
		if s := validation.ObjStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(f, "snapshot_ids"), "source") != pin {
			continue
		}
		for _, lab := range capabilities.Granted(f) {
			provides[lab] = struct{}{}
		}
	}
	return provides, nil
}

// kwOverlap is _kw_overlap: words longer than 3 code points shared.
func kwOverlap(a, b string) bool {
	wa := map[string]struct{}{}
	for _, w := range learning.ReSplit(a) {
		if utf8.RuneCountInString(w) > 3 {
			wa[w] = struct{}{}
		}
	}
	for _, w := range learning.ReSplit(b) {
		if utf8.RuneCountInString(w) > 3 {
			if _, ok := wa[w]; ok {
				return true
			}
		}
	}
	return false
}

// Recall is recall: the derived, advisory cross-campaign query.
func Recall(c *state.Campaign, candidateID string) (validation.Value, error) {
	rc, err := newRecallCtx(c, candidateID)
	if err != nil {
		return validation.VNull(), err
	}
	matches, err := rc.recallSignatureMatches()
	if err != nil {
		return validation.VNull(), err
	}
	rc.recallSortMatches(matches)
	memHits, err := rc.recallMemoryHits()
	if err != nil {
		return validation.VNull(), err
	}
	rc.recallSortMemoryHits(memHits)
	prefix := ""
	var programKeyV validation.Value = validation.VNull()
	if !rc.hasKey {
		prefix = "no program identity (policy not loaded) — only " +
			"global-scope rows recalled; "
	} else {
		programKeyV = validation.VStr(rc.key)
	}
	return validation.VObj(
		kv("candidate_id", validation.VStr(candidateID)),
		kv("candidate_class", validation.VStr(rc.candClass)),
		kv("program_key", programKeyV),
		kv("shared_signatures", validation.VArr(matches...)),
		kv("shared_memory", validation.VArr(memHits...)),
		kv("note", validation.VStr(prefix+"derived, advisory cross-campaign "+
			"query — nothing stored, no status moves; capabilities come from "+
			"the candidate's own snapshot reality, the store only records "+
			"what primitives depend on"))), nil
}

// recallCtx carries Recall's shared context across its extracted sections.
type recallCtx struct {
	c           *state.Campaign
	candidateID string
	cand        validation.Value
	candClass   string
	candGranted map[string]struct{}
	provides    map[string]struct{}
	key         string
	hasKey      bool
}

// newRecallCtx loads the candidate finding and derives the per-candidate
// facts every recall section reads.
func newRecallCtx(c *state.Campaign, candidateID string) (*recallCtx, error) {
	cand, err := findings.LoadFinding(c, candidateID)
	if err != nil {
		return nil, err
	}
	rc := &recallCtx{c: c, candidateID: candidateID, cand: cand}
	rc.candClass = validation.ObjStr(validation.ObjAt(cand, "root_cause"), "class")
	rc.candGranted = map[string]struct{}{}
	for _, lab := range capabilities.Granted(cand) {
		rc.candGranted[lab] = struct{}{}
	}
	provides, err := candidateProvides(c, cand)
	if err != nil {
		return nil, err
	}
	rc.provides = provides
	key, _, keyErr := ProgramKeyOf(c)
	rc.hasKey = keyErr == nil
	if !rc.hasKey {
		key = ""
	}
	rc.key = key
	return rc, nil
}

// visible is Recall's program-visibility gate over merged store rows: with
// no program identity only global-scope rows are visible.
func (rc *recallCtx) visible(rowKey string) bool {
	if !rc.hasKey {
		return false
	}
	return rowKey == rc.key
}

// recallSignatureMatches loads the merged signatures and builds the match
// row for every visible signature from another campaign.
func (rc *recallCtx) recallSignatureMatches() ([]validation.Value, error) {
	sigs, err := LoadSignatures(rc.c.Root)
	if err != nil {
		return nil, err
	}
	matches := []validation.Value{}
	for _, s := range sigs {
		if validation.ObjStr(s, "scope") != "global" && !rc.visible(validation.ObjStr(s, "program_key")) {
			continue
		}
		if validation.ObjStr(validation.ObjAt(s, "source"), "campaign_id") == rc.c.CampaignID {
			continue
		}
		if m, ok := rc.recallMatchOne(s); ok {
			matches = append(matches, m)
		}
	}
	return matches, nil
}

// recallMatchOne builds the advisory match row for one signature, reporting
// ok=false when the signature matches neither the candidate's bug class nor
// any capability similarity.
func (rc *recallCtx) recallMatchOne(s validation.Value) (validation.Value, bool) {
	sigGranted := strList(validation.ObjAt(s, "granted"))
	var sim validation.Value = validation.VNull()
	if len(rc.candGranted) > 0 || len(sigGranted) > 0 {
		overlap, union := 0, 0
		for lab := range rc.candGranted {
			union++
			if slices.Contains(sigGranted, lab) {
				overlap++
			}
		}
		for _, lab := range sigGranted {
			if _, ok := rc.candGranted[lab]; !ok {
				union++
			}
		}
		if union > 0 {
			sim = validation.VFloat(validation.PyRound(
				float64(overlap)/float64(union), 3))
		}
	}
	classMatch := rc.candClass == validation.ObjStr(s, "bug_class")
	if !classMatch && simOf(sim) <= 0 {
		return validation.Value{}, false
	}
	dependsSet := map[string]struct{}{}
	source := validation.ObjAt(s, "code_sourced_required")
	if source.Kind != validation.Arr {
		source = validation.ObjAt(s, "required")
	}
	for _, lab := range strList(source) {
		if slices.Contains(chainengine.AttackerBaseline, lab) {
			continue
		}
		dependsSet[lab] = struct{}{}
	}
	missing := []string{}
	for lab := range dependsSet {
		if _, ok := rc.provides[lab]; !ok {
			missing = append(missing, lab)
		}
	}
	sort.Strings(missing)
	stillProvided := []string{}
	for lab := range dependsSet {
		if _, ok := rc.provides[lab]; ok {
			stillProvided = append(stillProvided, lab)
		}
	}
	sort.Strings(stillProvided)
	dependsSorted := validation.SortedKeys(dependsSet)
	advisory := []string{}
	if len(missing) > 0 {
		advisory = append(advisory, fmt.Sprintf("the confirmed primitive "+
			"%s required %s; the candidate's snapshot reality no longer "+
			"provides %s — a patch may have removed exactly those",
			validation.ObjStr(validation.ObjAt(s, "source"), "finding_id"),
			pyReprList(dependsSorted), pyReprList(missing)))
	} else {
		advisory = append(advisory, "every capability the confirmed "+
			"primitive depended on is still provided by the candidate's "+
			"snapshot reality — treat the primitive as still live here")
	}
	return validation.VObj(
		kv("signature_id", validation.ObjAt(s, "signature_id")),
		kv("source", validation.ObjAt(s, "source")),
		kv("title", validation.ObjAt(s, "title")),
		kv("bug_class", validation.ObjAt(s, "bug_class")),
		kv("class_match", validation.VBool(classMatch)),
		kv("similarity", sim),
		kv("primitive_depended_on", validation.StrArr(dependsSorted)),
		kv("still_provided", validation.StrArr(stillProvided)),
		kv("missing", validation.StrArr(missing)),
		kv("terminal", validation.ObjAt(s, "terminal")),
		kv("advisory", validation.VStr(strings.Join(advisory, " ")))), true
}

// recallSortMatches orders the signature matches: class matches first, then
// similarity descending, then fewer missing capabilities.
func (rc *recallCtx) recallSortMatches(matches []validation.Value) {
	sort.SliceStable(matches, func(i, j int) bool {
		mi, mj := !validation.ObjAt(matches[i], "class_match").B,
			!validation.ObjAt(matches[j], "class_match").B
		if mi != mj {
			return !mi
		}
		si, sj := simOf(validation.ObjAt(matches[i], "similarity")),
			simOf(validation.ObjAt(matches[j], "similarity"))
		if si != sj {
			return si > sj
		}
		return len(validation.ObjAt(matches[i], "missing").A) <
			len(validation.ObjAt(matches[j], "missing").A)
	})
}

// recallMemoryHits loads the shared memory rows and builds the hit rows for
// every visible row from another campaign whose bug class or pattern
// keywords overlap the candidate.
func (rc *recallCtx) recallMemoryHits() ([]validation.Value, error) {
	shared, err := LoadSharedMemory(rc.c.Root)
	if err != nil {
		return nil, err
	}
	memHits := []validation.Value{}
	for _, w := range shared {
		if validation.ObjStr(w, "scope") != "global" && !rc.visible(validation.ObjStr(w, "program_key")) {
			continue
		}
		m := validation.ObjAt(w, "row")
		if validation.ObjStr(m, "campaign_id") == rc.c.CampaignID {
			continue
		}
		text := rc.candClass + " " + validation.ObjStr(rc.cand, "title") + " " +
			validation.ObjStr(validation.ObjAt(rc.cand, "root_cause"), "description")
		bugClass := validation.ObjStr(m, "bug_class")
		if (bugClass != "" && bugClass == rc.candClass) ||
			kwOverlap(validation.ObjStr(m, "pattern"), text) {
			memHits = append(memHits, validation.VObj(
				kv("memory_id", validation.ObjAt(m, "memory_id")),
				kv("status", validation.ObjAt(m, "status")),
				kv("kind", validation.ObjAt(m, "kind")),
				kv("pattern", validation.ObjAt(m, "pattern")),
				kv("bug_class", validation.ObjAt(m, "bug_class")),
				kv("source_campaign", validation.ObjAt(m, "campaign_id"))))
		}
	}
	return memHits, nil
}

// recallSortMemoryHits orders the memory hits by memory_id.
func (rc *recallCtx) recallSortMemoryHits(memHits []validation.Value) {
	sort.SliceStable(memHits, func(i, j int) bool {
		return validation.ObjStr(memHits[i], "memory_id") < validation.ObjStr(memHits[j], "memory_id")
	})
}
