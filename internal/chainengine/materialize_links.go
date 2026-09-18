package chainengine

import (
	"fmt"
	"sort"

	"websec/internal/findings"
	"websec/internal/validation"
)

// chainLinks recomputes capability continuity from the members themselves.
func chainLinks(members []validation.Value) ([]validation.Value, error) {
	return chainLinksMode(members, false)
}

// chainLinksMode is chainLinks with the B3 switch: an unproven chain stamps
// every link with its FROM member's own best evidence level, so a reader (and
// the report) can see how thin each hop of a hypothesis-level chain is.
func chainLinksMode(members []validation.Value,
	unproven bool) ([]validation.Value, error) {
	out := []validation.Value{}
	for i := 0; i+1 < len(members); i++ {
		a, b := members[i], members[i+1]
		aCaps := setOf(norm(capInput(validation.ObjAt(validation.AsObj(validation.ObjAt(a, "capabilities")), "granted"))))
		bNeeds := setOf(norm(capInput(validation.ObjAt(validation.AsObj(validation.ObjAt(b, "capabilities")), "required"))))
		overlap := []string{}
		for cap := range aCaps {
			if _, ok := bNeeds[cap]; ok {
				overlap = append(overlap, cap)
			}
		}
		if len(overlap) == 0 {
			return nil, fmt.Errorf("capability gap: %s -> %s (grants %s, needs %s)",
				validation.ObjStr(a, "finding_id"), validation.ObjStr(b, "finding_id"),
				validation.PyListRepr(setKeys(aCaps)), validation.PyListRepr(setKeys(bNeeds)))
		}
		sort.Strings(overlap)
		link := validation.VObj(
			kvOf("from_finding", validation.VStr(validation.ObjStr(a, "finding_id"))),
			kvOf("granted", validation.VStr(overlap[0])),
			kvOf("to_finding", validation.VStr(validation.ObjStr(b, "finding_id"))),
			kvOf("required", validation.VStr(overlap[0])),
		)
		if unproven {
			link.O = append(link.O, kvOf("link_evidence",
				validation.VStr(bestEvidenceLevel(a))))
		}
		out = append(out, link)
	}
	return out, nil
}

// bestEvidenceLevel is a member's strongest evidence item, "E0" when it has
// none (a HYPOTHESIS member with no evidence yet). An unknown level is
// skipped rather than fatal: this is a rendering aid, not a gate.
func bestEvidenceLevel(m validation.Value) string {
	best, bestIdx := "E0", 0
	for _, e := range listOf(m, "evidence").A {
		idx, err := findings.LevelIndex(validation.ObjStr(e, "level"))
		if err != nil {
			continue
		}
		if idx > bestIdx {
			best, bestIdx = validation.ObjStr(e, "level"), idx
		}
	}
	return best
}

// chainFloor is the weakest member's best evidence level.
func chainFloor(members []validation.Value) (string, error) {
	floor := ""
	floorIdx := 0
	for _, m := range members {
		best, bestIdx := "E0", 0
		first := true
		for _, e := range listOf(m, "evidence").A {
			idx, err := findings.LevelIndex(validation.ObjStr(e, "level"))
			if err != nil {
				return "", err
			}
			if first || idx > bestIdx {
				best, bestIdx, first = validation.ObjStr(e, "level"), idx, false
			}
		}
		if floor == "" || bestIdx < floorIdx {
			floor, floorIdx = best, bestIdx
		}
	}
	return floor, nil
}
