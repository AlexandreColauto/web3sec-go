// transitions_anchor.go: the CONFIRMED anchor machinery — _anchor_rescan's
// plan mutation (re-open exhausted lenses, mint the ANCHOR priority) and
// its small plan/priority helpers (webv2.findings).
package findings

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

// anchorRescan is _anchor_rescan: a CONFIRMED high/critical finding is an
// ANCHOR — add one re-scan priority (idempotent per finding) so the discovery
// queue carries it.
func anchorRescan(campaign *state.Campaign, finding validation.Value) error {
	sev := validation.ObjStr(finding, "reported_severity")
	if sev != "high" && sev != "critical" {
		return nil
	}
	planPath := filepath.Join(campaign.ArtifactsDir, "campaign_plan.json")
	if _, err := os.Stat(planPath); err != nil {
		return nil // the discovery proof already reports the missing plan
	}
	if err := reopenExhaustedLenses(campaign, finding); err != nil {
		fid := validation.ObjStr(finding, "finding_id")
		data := validation.VObj(validation.KV{K: "error",
			V: validation.VStr(err.Error())})
		if _, lerr := campaign.Log("plan.lens_reopen_failed", &fid,
			&data); lerr != nil {
			return nil
		}
	}
	plan, err := plannerLoadPlanReadonlyFunc(campaign)
	if err != nil {
		return err
	}
	fid := validation.ObjStr(finding, "finding_id")
	if hasAnchorPriority(plan, fid) {
		return nil
	}
	priority, err := anchorPriority(finding, plan)
	if err != nil {
		return err
	}
	priorities := validation.ObjAt(plan, "priorities")
	if priorities.Kind != validation.Arr {
		return fmt.Errorf("%s", validation.PyReprStr("priorities"))
	}
	priorities.A = append(priorities.A, priority)
	plan.O = validation.SetOrAppend(plan.O, "priorities", priorities)
	if err := plannerSavePlanFunc(campaign, plan); err != nil {
		return err
	}
	data := validation.VObj(
		validation.KV{K: "priority_id", V: validation.ObjAt(priority, "id")},
		validation.KV{K: "severity", V: validation.ObjAt(finding, "reported_severity")},
	)
	_, err = campaign.Log("plan.anchor_priority", &fid, &data)
	return err
}

// reopenExhaustedLenses is the exhaustive-divergence pass: a CONFIRMED
// finding in a family a lens claimed to have exhausted proves the closure
// premature — re-open that lens.
func reopenExhaustedLenses(campaign *state.Campaign, finding validation.Value) error {
	toks := plannerFamiliesForFindingFunc(plannerModelOrEmptyFunc(campaign),
		finding)
	if len(toks) == 0 {
		return nil
	}
	plan, err := plannerLoadPlanReadonlyFunc(campaign)
	if err != nil {
		return err
	}
	lenses := validation.ObjAt(plan, "lenses")
	if lenses.Kind != validation.Arr {
		return nil
	}
	changed := false
	for i, l := range lenses.A {
		if l.Kind != validation.Obj {
			continue
		}
		st := validation.ObjStr(l, "status")
		if st != "answered" && st != "not-applicable" {
			continue
		}
		hit := intersectSorted(validation.ObjAt(l, "families"), toks)
		if len(hit) == 0 {
			continue
		}
		l = reopenLens(campaign, finding, l, hit)
		lenses.A[i] = l
		changed = true
	}
	if !changed {
		return nil
	}
	plan.O = validation.SetOrAppend(plan.O, "lenses", lenses)
	return plannerSavePlanFunc(campaign, plan)
}

// reopenLens applies one lens re-open and logs it.
func reopenLens(campaign *state.Campaign, finding, lens validation.Value,
	hit []string) validation.Value {
	fid := validation.ObjStr(finding, "finding_id")
	lens.O = validation.SetOrAppend(lens.O, "status", validation.VStr("open"))
	lens.O = validation.SetOrAppend(lens.O, "reopen_reason", validation.VStr(
		fmt.Sprintf("CONFIRMED %s in family %s after %s was closed — re-scan "+
			"the family", fid, strings.Join(hit, ", "), validation.ObjStr(lens, "lens"))))
	lens.O = validation.SetOrAppend(lens.O, "reopened_at", validation.VStr(state.NowIso()))
	for _, k := range []string{"closed_reason", "closed_ref", "closed_at",
		"closed_by", "families_checked", "symmetry"} {
		lens.O = dropKey(lens.O, k)
	}
	data := validation.VObj(
		validation.KV{K: "lens_id", V: validation.ObjAt(lens, "id")},
		validation.KV{K: "families", V: validation.StrArr(hit)},
	)
	_, _ = campaign.Log("plan.lens_reopened", &fid, &data)
	return lens
}

// hasAnchorPriority is any(q.get("anchor_of") == finding_id ...).
func hasAnchorPriority(plan validation.Value, findingID string) bool {
	for _, q := range validation.ObjAt(plan, "priorities").A {
		if validation.ObjAt(q, "anchor_of").Kind == validation.Str &&
			validation.ObjStr(q, "anchor_of") == findingID {
			return true
		}
	}
	return false
}

// anchorPriority builds the ANCHOR priority row for a CONFIRMED finding.
func anchorPriority(finding, plan validation.Value) (validation.Value, error) {
	surfaces := sortedContracts(finding)
	if len(surfaces) == 0 {
		surfaces = []string{"the affected surface"}
	}
	n, err := nextPriorityNumber(plan)
	if err != nil {
		return validation.VNull(), err
	}
	fid := validation.ObjStr(finding, "finding_id")
	cls := validation.ObjStr(asDict(validation.ObjAt(finding, "root_cause")), "class")
	clsText := cls
	if clsText == "" {
		clsText = "unclassified"
	}
	question := fmt.Sprintf("ANCHOR: %s (%s, %s) is CONFIRMED at %s — re-scan "+
		"the SAME lifecycle for a non-obvious coordination bug before "+
		"converging (the loud bug usually hides the subtle one)", fid,
		validation.PyStr(validation.ObjAt(finding, "reported_severity")), clsText,
		strings.Join(surfaces, ", "))
	priority := validation.VObj(
		validation.KV{K: "id", V: validation.VStr(fmt.Sprintf("Q-%03d", n))},
		validation.KV{K: "question", V: validation.VStr(question)},
		validation.KV{K: "risk", V: validation.VFloat(0.8)},
		validation.KV{K: "components", V: validation.StrArr(surfaces)},
		validation.KV{K: "trajectories", V: validation.VArr(validation.VStr("code"))},
		validation.KV{K: "status", V: validation.VStr("open")},
		validation.KV{K: "anchor_of", V: validation.VStr(fid)},
	)
	// root_cause.class is schema-free-form (advisory taxonomy mapping) but
	// save_plan hard-validates bug_class against the canonical vocabulary:
	// copying a non-canonical class would raise AFTER the CONFIRMED status
	// is already durable.
	if cls != "" && inSet(taxonomyKnownClassesFunc(), cls) {
		priority.O = validation.SetOrAppend(priority.O, "bug_class",
			validation.VStr(cls))
	}
	return priority, nil
}

// sortedContracts is sorted({a["contract"] for a in affected if a.contract}).
func sortedContracts(finding validation.Value) []string {
	seen := map[string]struct{}{}
	for _, a := range validation.ObjAt(finding, "affected").A {
		if a.Kind != validation.Obj {
			continue
		}
		if c := validation.ObjStr(a, "contract"); c != "" {
			seen[c] = struct{}{}
		}
	}
	return sortedSetKeys(seen)
}

// nextPriorityNumber is max([int(q["id"][2:]) for Q- ids] or [0]) + 1.
func nextPriorityNumber(plan validation.Value) (int, error) {
	var nums []int
	for _, q := range validation.ObjAt(plan, "priorities").A {
		id := validation.ObjStr(q, "id")
		if !strings.HasPrefix(id, "Q-") {
			continue
		}
		n, ok := pyIntText(id[2:])
		if !ok {
			return 0, fmt.Errorf("invalid literal for int() with base 10: %s",
				validation.PyReprStr(id[2:]))
		}
		nums = append(nums, n)
	}
	best := 0 // max([...] or [0])
	if len(nums) > 0 {
		best = nums[0]
		for _, n := range nums[1:] {
			if n > best {
				best = n
			}
		}
	}
	return best + 1, nil
}

// pyIntText is Python int() on a base-10 literal: surrounding whitespace, an
// optional sign, and single underscores between digits are accepted.
func pyIntText(s string) (int, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, false
	}
	neg := false
	if t[0] == '+' || t[0] == '-' {
		neg = t[0] == '-'
		t = t[1:]
	}
	if t == "" {
		return 0, false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c == '_' {
			if i == 0 || i == len(t)-1 || !isDigit(t[i-1]) || !isDigit(t[i+1]) {
				return 0, false
			}
			continue
		}
		if !isDigit(c) {
			return 0, false
		}
	}
	n, err := strconv.Atoi(strings.ReplaceAll(t, "_", ""))
	if err != nil {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// intersectSorted is sorted(set(families) & toks).
func intersectSorted(families validation.Value, toks map[string]struct{}) []string {
	seen := map[string]struct{}{}
	for _, f := range families.A {
		if f.Kind != validation.Str {
			continue
		}
		if _, ok := toks[f.S]; ok {
			seen[f.S] = struct{}{}
		}
	}
	return sortedSetKeys(seen)
}

// dropKey is dict.pop(k, None): the object without that key.
func dropKey(o []validation.KV, key string) []validation.KV {
	out := make([]validation.KV, 0, len(o))
	for _, kv := range o {
		if kv.K != key {
			out = append(out, kv)
		}
	}
	return out
}
