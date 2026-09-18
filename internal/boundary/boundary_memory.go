package boundary

import (
	"websec/internal/learning"
	"websec/internal/roles"
	"websec/internal/state"
	"websec/internal/validation"
)

// statementOverlap is _statement_overlap: cheap normalized word overlap
// between two propositions.
func statementOverlap(a, b string) bool {
	wa := map[string]bool{}
	for _, w := range learning.ReSplit(a) {
		if len([]rune(w)) > 3 {
			wa[w] = true
		}
	}
	for _, w := range learning.ReSplit(b) {
		if len([]rune(w)) > 3 && wa[w] {
			return true
		}
	}
	return false
}

// memoryUtility is _memory_utility: the cheap utility signal on
// negative-memory injection.
func memoryUtility(campaign *state.Campaign, findingID string,
	raw validation.Value) error {
	block, err := roles.KnownNonIssues(campaign,
		strPtr(validation.ObjStr(raw, "bug_class")), 12)
	if err != nil {
		return err
	}
	priors := validation.ObjAt(block, "known_non_issues")
	if priors.Kind != validation.Arr || len(priors.A) == 0 {
		return nil
	}
	declared := map[string]bool{}
	if d := validation.ObjAt(raw, "differs_from_memory"); d.Kind == validation.Arr {
		for _, item := range d.A {
			if item.Kind == validation.Obj {
				declared[validation.ObjStr(item, "memory_id")] = true
			}
		}
	}
	hypAssumptions := []string{}
	if as := validation.ObjAt(raw, "assumptions"); as.Kind == validation.Arr {
		for _, a := range as.A {
			if a.Kind == validation.Obj && truthy(validation.ObjAt(a, "blocking")) {
				hypAssumptions = append(hypAssumptions, validation.ObjStr(a, "claim"))
			}
		}
	}
	reRaised, overrideDeclared, notMatched := []string{}, []string{}, []string{}
	inContext := []string{}
	for _, prior := range priors.A {
		mid := validation.ObjStr(prior, "memory_id")
		inContext = append(inContext, mid)
		if declared[mid] {
			overrideDeclared = append(overrideDeclared, mid)
			continue
		}
		props := validation.ObjAt(prior, "deciding_propositions")
		hit := false
		if props.Kind == validation.Arr && len(props.A) > 0 {
			for _, h := range hypAssumptions {
				for _, p := range props.A {
					if p.Kind == validation.Obj &&
						statementOverlap(h, validation.ObjStr(p, "statement")) {
						hit = true
						break
					}
				}
				if hit {
					break
				}
			}
		} else {
			hit = validation.ObjStr(prior, "bug_class") == validation.ObjStr(raw, "bug_class")
		}
		if hit {
			reRaised = append(reRaised, mid)
		} else {
			notMatched = append(notMatched, mid)
		}
	}
	data := validation.VObj(
		validation.KV{K: "bug_class", V: validation.ObjAt(raw, "bug_class")},
		validation.KV{K: "memories_in_context", V: validation.StrArr(inContext)},
		validation.KV{K: "re_raised", V: validation.StrArr(reRaised)},
		validation.KV{K: "override_declared", V: validation.StrArr(overrideDeclared)},
		validation.KV{K: "not_matched", V: validation.StrArr(notMatched)})
	_, err = campaign.Log("memory.utility", &findingID, &data)
	return err
}
