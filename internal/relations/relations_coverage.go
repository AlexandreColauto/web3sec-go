// relations_coverage.go: the capability-coverage delta and the derived
// 'resembles' report — computed on demand, never stored.
package relations

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"websec/internal/capabilities"
	"websec/internal/chainengine"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- the capability-coverage delta ----------------------------------------

// exploitPath is _exploit_path: the materialized chain the finding is a
// member of (if any), else the finding alone.
func exploitPath(c *state.Campaign, findingID string) ([]string, error) {
	chains, err := chainsOf(c)
	if err != nil {
		return nil, err
	}
	for _, ch := range chains {
		if slices.Contains(strList(validation.ObjAt(ch, "members")), findingID) {
			return strList(validation.ObjAt(ch, "members")), nil
		}
	}
	return []string{findingID}, nil
}

// CapabilityCoverage is capability_coverage: set arithmetic over RECORDED
// capabilities — no code inference.
func CapabilityCoverage(c *state.Campaign, candidateID,
	primitiveID string) (validation.Value, error) {
	cand, err := findings.LoadFinding(c, candidateID)
	if err != nil {
		return validation.VNull(), err
	}
	prim, err := findings.LoadFinding(c, primitiveID)
	if err != nil {
		return validation.VNull(), err
	}
	pathP, err := exploitPath(c, primitiveID)
	if err != nil {
		return validation.VNull(), err
	}
	dependsRaw := map[string]struct{}{}
	for _, fid := range pathP {
		f, err := findings.LoadFinding(c, fid)
		if err != nil {
			return validation.VNull(), err
		}
		for _, lab := range capabilities.Required(f) {
			dependsRaw[lab] = struct{}{}
		}
	}
	pin := validation.ObjStr(validation.ObjAt(cand, "snapshot_ids"), "source")
	provides := map[string]struct{}{}
	codeSourced := map[string]struct{}{}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, f := range all {
		if s := validation.ObjStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" {
			continue
		}
		for _, lab := range capabilities.Granted(f) {
			codeSourced[lab] = struct{}{}
		}
		if validation.ObjStr(validation.ObjAt(f, "snapshot_ids"), "source") == pin {
			for _, lab := range capabilities.Granted(f) {
				provides[lab] = struct{}{}
			}
		}
	}
	depends := map[string]struct{}{}
	for lab := range dependsRaw {
		if _, ok := codeSourced[lab]; !ok {
			continue
		}
		if slices.Contains(chainengine.AttackerBaseline, lab) {
			continue
		}
		depends[lab] = struct{}{}
	}
	missing := []string{}
	for lab := range depends {
		if _, ok := provides[lab]; !ok {
			missing = append(missing, lab)
		}
	}
	sort.Strings(missing)
	satisfied := []string{}
	for lab := range depends {
		if _, ok := provides[lab]; ok {
			satisfied = append(satisfied, lab)
		}
	}
	sort.Strings(satisfied)
	candGranted := capabilities.Granted(cand)
	primGranted := capabilities.Granted(prim)
	overlap := []string{}
	for _, lab := range candGranted {
		if slices.Contains(primGranted, lab) {
			overlap = append(overlap, lab)
		}
	}
	sort.Strings(overlap)
	union := map[string]struct{}{}
	for _, lab := range candGranted {
		union[lab] = struct{}{}
	}
	for _, lab := range primGranted {
		union[lab] = struct{}{}
	}
	var sim validation.Value
	if len(union) > 0 {
		sim = validation.VFloat(validation.PyRound(
			float64(len(overlap))/float64(len(union)), 3))
	} else {
		sim = validation.VNull()
	}
	terminal := false
	for _, lab := range candGranted {
		if capabilities.IsTerminal(lab) {
			terminal = true
			break
		}
	}
	dependsSorted := validation.SortedKeys(depends)
	bits := []string{}
	if len(missing) > 0 {
		bits = append(bits, fmt.Sprintf("the confirmed primitive's exploit "+
			"path required %s; the candidate context no longer provides %s — "+
			"the patch may have removed exactly those capabilities",
			pyReprList(dependsSorted), pyReprList(missing)))
	} else {
		bits = append(bits, "every capability the confirmed primitive "+
			"depended on is still provided by the candidate context")
	}
	if terminal && len(missing) > 0 {
		bits = append(bits, "the candidate still reaches an economic terminal "+
			"state — re-verify whether the missing capabilities are truly gone "+
			"or merely moved")
	}
	classMatch := validation.ObjStr(validation.ObjAt(cand, "root_cause"), "class") ==
		validation.ObjStr(validation.ObjAt(prim, "root_cause"), "class")
	return validation.VObj(
		kv("candidate_id", validation.VStr(candidateID)),
		kv("primitive_id", validation.VStr(primitiveID)),
		kv("class_match", validation.VBool(classMatch)),
		kv("granted_overlap", validation.StrArr(overlap)),
		kv("similarity", sim),
		kv("primitive_depended_on", validation.StrArr(dependsSorted)),
		kv("still_provided", validation.StrArr(satisfied)),
		kv("missing", validation.StrArr(missing)),
		kv("candidate_reaches_terminal", validation.VBool(terminal)),
		kv("advisory", validation.VStr(strings.Join(bits, " ")))), nil
}

// ResemblanceReport is resemblance_report: derived 'resembles' edges —
// computed, never stored.
func ResemblanceReport(c *state.Campaign,
	candidateID string) (validation.Value, error) {
	cand, err := findings.LoadFinding(c, candidateID)
	if err != nil {
		return validation.VNull(), err
	}
	out := []validation.Value{}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, f := range all {
		fid := validation.ObjStr(f, "finding_id")
		if fid == candidateID {
			continue
		}
		if s := validation.ObjStr(f, "status"); s != "CONFIRMED" && s != "CHAIN" {
			continue
		}
		cov, err := CapabilityCoverage(c, candidateID, fid)
		if err != nil {
			return validation.VNull(), err
		}
		classMatch := validation.ObjAt(cov, "class_match").B
		if !classMatch && len(validation.ObjAt(cov, "granted_overlap").A) == 0 {
			continue
		}
		out = append(out, cov)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := out[i], out[j]
		mi, mj := !validation.ObjAt(ci, "class_match").B, !validation.ObjAt(cj, "class_match").B
		if mi != mj {
			return !mi
		}
		si, sj := simOf(ci), simOf(cj)
		if si != sj {
			return si > sj
		}
		return len(validation.ObjAt(ci, "missing").A) < len(validation.ObjAt(cj, "missing").A)
	})
	return validation.VObj(
		kv("candidate_id", validation.VStr(candidateID)),
		kv("candidate_class", validation.ObjAt(validation.ObjAt(cand, "root_cause"), "class")),
		kv("candidate_required", validation.StrArr(capabilities.Required(cand))),
		kv("matches", validation.VArr(out...)),
		kv("note", validation.VStr("derived query — resemblance edges are "+
			"never stored; recomputed on demand so a heuristic can never "+
			"fossilize"))), nil
}

func simOf(v validation.Value) float64 {
	s := validation.ObjAt(v, "similarity")
	if s.Kind == validation.Flt {
		return s.F
	}
	if s.Kind == validation.Int {
		return float64(s.I)
	}
	return 0
}
