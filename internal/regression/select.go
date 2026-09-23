package regression

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// ScaBenchShapes is §3a's four ScaBench target shapes. The other two rows of
// the six (the diagnosed campaign, the already-exploited control target) are
// not picks from the snapshot: they are named separately in the selection.
var ScaBenchShapes = []string{
	"vault-erc4626", "lending-liquidation", "bridge-messaging",
	"non-rollup-l2-or-oracle",
}

// selectMethod is the `method` value the schema pins as a const: the pick is
// greedy set-cover weighted by gold-finding count, and a reader of the file
// must be able to tell that from the file alone.
const selectMethod = "greedy-set-cover-weighted-by-gold-finding-count"

// labelClassFitness is the caveat every selection file carries about the input
// it was computed from, and it is not decoration: the Task 3 label file is the
// derived matcher's output, and the hand review recorded in
// docs/gates/v16-P0.md found the classification materially unfit — 29 of the
// 52 classified rows carry a class the mechanism contradicts, no
// upgrade-initializer row (20) and no flash-loan row (1) is defensible, and 11
// classes are defensible where 14 were produced. Both undefendable classes are
// COVERED by the pick (bakerfi carries flash-loan and upgrade-initializer, and
// upgrade-initializer is the single class of the bridge pick), so 21 of the 40
// covered findings — more than half — are that artifact. The coverage this
// selector reports
// is therefore a lower bound on which classes the suite exercises; it is not
// evidence that a class is real. It rides in the RECORD rather than in a doc
// comment because Task 10 reads the selection by path + sha256 and reports its
// coverage with nothing else in hand.
const labelClassFitness = "the label file's classes are Task 3's derived " +
	"matcher output, and the hand review in docs/gates/v16-P0.md found the " +
	"classification materially unfit (29 of 52 classified rows wrong; no " +
	"upgrade-initializer row and no flash-loan row is defensible, and those " +
	"two artifact classes carry 21 of the covered findings). Coverage here is " +
	"a lower bound on which classes the suite exercises, never evidence that " +
	"a class is real."

// SelectSpec is one selection run.
type SelectSpec struct {
	Labels           validation.Value // the Task 3 label file
	Shapes           map[string]string
	HeldOut          []string
	Picks            int
	DiagnosedProgram string
	ControlProgram   string
}

// candidate is one project's coverage profile.
type candidate struct {
	project string
	shape   string
	classes map[string]int // class -> gold findings in this project
	total   int
}

// profileResult is the snapshot read once: the shaped candidates, each class's
// total gold-finding count (the weight), and the snapshot's total.
type profileResult struct {
	cands   []candidate
	weights map[string]int
	total   int
}

// Select is §3a's picker: greedy set-cover over the derived classes, weighted
// by gold-finding count, constrained to one project per shape and to exactly
// two held-out projects.
//
// The weight of a class is its TOTAL gold-finding count across the snapshot,
// so covering a class that holds many findings is worth more than covering one
// that holds a single finding — §3a's point that "a target with one gold
// finding costs the same checkout and yields almost no signal".
//
// WHAT THIS WEIGHT DOES NOT DO, because the plan's Step 2 test claimed it did:
// it does not buy CLASS coverage. The gain is a sum of weights, so a class
// holding 3 findings loses every slot to one holding 4, and a rare class is
// exactly what a weighted pick drops (TestSelectDropsTheRareClassAndPinsCoverage
// measures it). Weighting buys weighted coverage — how many gold findings the
// six checkouts reach — and the shape constraint is what buys breadth.
//
// Greedy is deterministic here by construction: the argmax breaks ties on the
// project name (ascending), and no map is ever iterated for a decision.
func Select(spec SelectSpec) (validation.Value, error) {
	if spec.Picks == 0 {
		spec.Picks = 6
	}
	if err := checkSelectSpec(spec); err != nil {
		return validation.VNull(), err
	}
	prof := profile(spec.Labels, spec.Shapes)
	if len(prof.cands) < spec.Picks {
		return validation.VNull(), fmt.Errorf(
			"%d project(s) have a shape assigned, fewer than the %d picks — assign "+
				"a shape to more projects", len(prof.cands), spec.Picks)
	}
	chosen, covered, err := greedy(prof.cands, prof.weights, spec.Picks)
	if err != nil {
		return validation.VNull(), err
	}
	picks, heldOutChosen := renderPicks(chosen, spec.HeldOut)
	if heldOutChosen != 2 {
		return validation.VNull(), fmt.Errorf(
			"%d of the 2 held-out projects were picked — a held-out target that is "+
				"not in the suite is not held out from anything; pick again or name "+
				"held-out projects the greedy actually selects", heldOutChosen)
	}
	return selectDoc(spec, picks, coverageOf(covered, prof)), nil
}

// checkSelectSpec is Select's refusals: the pick count, the review flag, the
// hold-out partition and the shape vocabulary.
func checkSelectSpec(spec SelectSpec) error {
	if spec.Picks < 4 || spec.Picks > 6 {
		return fmt.Errorf(
			"§3a selects 4–6 stratified targets; Picks=%d is outside that range",
			spec.Picks)
	}
	if !validation.ObjAt(spec.Labels, "unmapped_reviewed").B {
		return fmt.Errorf(
			"the label file's unmapped bucket has not been reviewed " +
				"(unmapped_reviewed is not true) — §3a calls the bucketing \"our own " +
				"classification, a named source of error\", so selection may not run " +
				"on labels nobody read")
	}
	if len(spec.HeldOut) != 2 {
		return fmt.Errorf(
			"Phase 0 holds out exactly 2 targets by project (§3a); got %d: %v",
			len(spec.HeldOut), spec.HeldOut)
	}
	return checkHeldOutShapes(spec)
}

// checkHeldOutShapes requires every held-out project to be shaped, and every
// shape in the map to be one of §3a's four: a held-out target is still a
// target and must be stratified, and a name with no shape is a typo the pick
// would otherwise only discover as "that project was not picked".
//
// The shape vocabulary is checked over a Go map, whose iteration order is
// randomized, so every invalid entry is collected and the refusal is rendered
// as a SORTED list: with two or more invalid shapes an early return would name
// a different project on each run, which is exactly the non-determinism the
// rest of this file is built to avoid. The held-out loop above iterates a
// slice, so its first refusal is already stable.
func checkHeldOutShapes(spec SelectSpec) error {
	for _, p := range spec.HeldOut {
		if _, ok := spec.Shapes[p]; !ok {
			return fmt.Errorf(
				"held-out project %q has no shape assigned — a held-out target is "+
					"still a target and must be stratified", p)
		}
	}
	bad := []string{}
	for project, shape := range spec.Shapes {
		if !contains(ScaBenchShapes, shape) {
			bad = append(bad, fmt.Sprintf("%q has shape %q", project, shape))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf(
			"project(s) with a shape that is not one of §3a's four ScaBench "+
				"shapes %v: %s", ScaBenchShapes, strings.Join(bad, ", "))
	}
	return nil
}

// profile buckets the label rows by project and computes each class's total
// gold-finding count (the weight) and the snapshot's total.
//
// Invariant it relies on: the label file carries the snapshot's HIGH findings
// only (Task 3's DeriveLabels enforces it), so every row IS a gold finding and
// no severity filter is needed here. If that invariant ever breaks, this
// function silently counts a medium finding as gold and the coverage figure
// stops meaning what §3a means by it.
//
// An unmapped row is information about the rule table, not a class to cover:
// it is never a weight and never a class. It IS still a gold finding, so it
// counts in `total` (the snapshot's) and in the candidate's own gold count —
// the label file is the snapshot's 114 high findings, and a project's
// gold_findings must be that project's high count, not the count the matcher
// happened to classify.
//
// The plan's own profile `continue`d on an unmapped row BEFORE the candidate
// lookup, so it had two real effects on the shaped set, both measured on the
// 2025-08-18 snapshot: (a) a candidate's gold count was its CLASSIFIED count —
// bakerfi 7 reported as 3, kinetiq 3 as 1, initia 4 as 3, starknet-perpetual 2
// as 1 — and (b) a shaped project whose rows are all unmapped was never a
// candidate at all (Cabal, Liquid RON and Telcoin, 3 of the 12 shaped
// projects), so it was invisible to the pick and to the "fewer than the picks"
// guard. It could NOT emit gold_findings=0: the candidate was created inside
// the mapped-row branch and `total++` ran on the same row, so every candidate
// it could report had total >= 1 and the schema's `minimum: 1` was never
// reachable from that path.
func profile(labels validation.Value, shapes map[string]string) profileResult {
	byProject := map[string]*candidate{}
	out := profileResult{weights: map[string]int{}}
	for _, row := range validation.ObjAt(labels, "rows").A {
		project := validation.ObjStr(row, "project")
		class := validation.ObjStr(row, "class")
		mapped := class != "" && class != unmappedClass
		out.total++
		if mapped {
			out.weights[class]++
		}
		shape, shaped := shapes[project]
		if !shaped {
			continue // no shape assigned: not a candidate
		}
		c := candidateFor(byProject, project, shape)
		c.total++
		if mapped {
			c.classes[class]++
		}
	}
	out.cands = sortedCandidates(byProject)
	return out
}

// candidateFor is the project's coverage profile, created on first sight. The
// zero value of a map lookup is a nil *candidate, so the creation cannot be
// folded into the lookup.
func candidateFor(byProject map[string]*candidate, project, shape string) *candidate {
	if c, ok := byProject[project]; ok {
		return c
	}
	c := &candidate{project: project, shape: shape, classes: map[string]int{}}
	byProject[project] = c
	return c
}

// sortedCandidates is the candidate list in project-name order — the order
// every decision below is made in, so nothing depends on map iteration.
func sortedCandidates(byProject map[string]*candidate) []candidate {
	out := make([]candidate, 0, len(byProject))
	for _, c := range byProject {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].project < out[j].project })
	return out
}

// greedy is the two-pass pick. Pass 1 takes one target per shape, in
// ScaBenchShapes order, so the stratification is a CONSTRAINT and not an
// emergent property of the weights. Pass 2 fills the remaining slots by
// global weighted gain.
func greedy(cands []candidate, weights map[string]int, picks int) (
	[]candidate, map[string]bool, error) {
	covered := map[string]bool{}
	chosen := []candidate{}
	for _, shape := range ScaBenchShapes {
		best, ok := bestCandidate(cands, shape, covered, weights, chosen, false)
		if !ok {
			return nil, nil, fmt.Errorf(
				"no project covers shape %q among the shaped projects — §3a's "+
					"composition requires one target of each shape", shape)
		}
		chosen, covered = take(best, chosen, covered)
	}
	for len(chosen) < picks {
		best, ok := bestCandidate(cands, "", covered, weights, chosen, true)
		if !ok {
			return nil, nil, fmt.Errorf(
				"only %d of %d picks could be filled with positive coverage — the "+
					"snapshot's classes are exhausted", len(chosen), picks)
		}
		chosen, covered = take(best, chosen, covered)
	}
	return chosen, covered, nil
}

// take adds one candidate to the pick and marks its classes covered.
func take(c candidate, chosen []candidate, covered map[string]bool) (
	[]candidate, map[string]bool) {
	for class := range c.classes {
		covered[class] = true
	}
	return append(chosen, c), covered
}

// bestCandidate is the greedy step: the unchosen candidate with the highest
// weighted gain over still-uncovered classes, restricted to `shape` when one
// is given. Ties break on project name ASCENDING, so the result never depends
// on iteration order and a re-run of the same input is byte-identical.
//
// requireGain is the one difference between the two passes, and it is
// load-bearing. Pass 2 (requireGain) is an optimization: a filler that adds no
// uncovered class is worth nothing. Pass 1 is NOT: §3a's composition is a
// CONSTRAINT, so a shape whose only candidate's classes the earlier picks
// already covered must still be filled — otherwise the selector refuses a
// snapshot it can serve, with a message ("no project covers shape X") that is
// false. On the real 2025-08-18 snapshot that is not hypothetical: the one
// cross-chain forwarder's only classified class is upgrade-initializer, which
// the vault pick covers, so a gain-gated pass 1 cannot select a suite at all.
func bestCandidate(cands []candidate, shape string, covered map[string]bool,
	weights map[string]int, chosen []candidate, requireGain bool) (candidate, bool) {
	best := candidate{}
	bestGain := -1
	for _, c := range cands {
		if !eligible(c, shape, chosen) {
			continue
		}
		gain := uncoveredGain(c, covered, weights)
		if beats(c, gain, best, bestGain) {
			best, bestGain = c, gain
		}
	}
	if best.project == "" || (requireGain && bestGain <= 0) {
		return candidate{}, false
	}
	return best, true
}

// eligible is the candidate filter: not already chosen, and of the requested
// shape when one is requested.
func eligible(c candidate, shape string, chosen []candidate) bool {
	return !chosenProject(c.project, chosen) && (shape == "" || c.shape == shape)
}

// beats is the argmax comparison: strictly higher gain wins, and an equal gain
// goes to the LOWER project name — the tie-break that makes the pick
// reproducible, stated here once so both passes share it.
func beats(c candidate, gain int, best candidate, bestGain int) bool {
	if gain != bestGain {
		return gain > bestGain
	}
	return best.project != "" && c.project < best.project
}

// chosenProject reports whether a project is already among the picks.
func chosenProject(project string, chosen []candidate) bool {
	for _, c := range chosen {
		if c.project == project {
			return true
		}
	}
	return false
}

// uncoveredGain is one candidate's weight: the sum of the gold-finding counts
// of the classes it carries that nothing chosen yet covers.
func uncoveredGain(c candidate, covered map[string]bool, weights map[string]int) int {
	gain := 0
	for class := range c.classes {
		if !covered[class] {
			gain += weights[class]
		}
	}
	return gain
}

// renderPicks turns the chosen candidates into the picks array, labelling each
// one's partition, and reports how many of the held-out projects were picked.
func renderPicks(chosen []candidate, heldOut []string) ([]validation.Value, int) {
	heldOutSet := map[string]bool{}
	for _, p := range heldOut {
		heldOutSet[p] = true
	}
	picks := make([]validation.Value, 0, len(chosen))
	heldOutChosen := 0
	for _, p := range chosen {
		partition := "dev"
		if heldOutSet[p.project] {
			partition = "held-out"
			heldOutChosen++
		}
		picks = append(picks, pickDoc(p, partition))
	}
	return picks, heldOutChosen
}

// pickDoc is one picks[] entry: the project, its shape, its partition, its own
// gold-finding count and the classes it carries (sorted, so the record is
// stable).
func pickDoc(p candidate, partition string) validation.Value {
	classes := make([]string, 0, len(p.classes))
	for class := range p.classes {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	return validation.VObj(
		kv("project", validation.VStr(p.project)),
		kv("shape", validation.VStr(p.shape)),
		kv("partition", validation.VStr(partition)),
		kv("gold_findings", validation.VInt(int64(p.total))),
		kv("classes", validation.VArr(strVals(classes)...)),
	)
}

// coverageOf is the coverage arithmetic: how many gold findings the picks
// reach, and which classes they leave uncovered. covered_findings counts a
// class's whole weight once the class is covered — the same weight the greedy
// maximised, so the number the record reports is the number the pick chased.
func coverageOf(covered map[string]bool, prof profileResult) validation.Value {
	uncovered := []validation.Value{}
	coveredFindings := 0
	for _, class := range validation.SortedKeys(prof.weights) {
		if covered[class] {
			coveredFindings += prof.weights[class]
			continue
		}
		uncovered = append(uncovered, validation.VStr(class))
	}
	return validation.VObj(
		kv("covered_findings", validation.VInt(int64(coveredFindings))),
		kv("total_findings", validation.VInt(int64(prof.total))),
		kv("covered_classes", validation.VInt(
			int64(len(prof.weights)-len(uncovered)))),
		kv("total_classes", validation.VInt(int64(len(prof.weights)))),
		kv("uncovered_classes", validation.VArr(uncovered...)),
	)
}

// selectDoc is the record: the input's own provenance, the method, the picks,
// the coverage they reach, the input's known-unfit caveat, and the two named
// rows §3a keeps outside the snapshot (the diagnosed campaign as training
// data, the already-exploited control target). created_at comes from
// state.NowIso, the repo's deterministic-time seam (WEBV2_NOW pins it), so the
// record is re-derivable byte-for-byte.
func selectDoc(spec SelectSpec, picks []validation.Value, coverage validation.Value) validation.Value {
	doc := validation.VObj(
		kv("dataset", validation.VStr(validation.ObjStr(spec.Labels, "dataset"))),
		kv("snapshot_date", validation.VStr(
			validation.ObjStr(spec.Labels, "snapshot_date"))),
		kv("method", validation.VStr(selectMethod)),
		kv("picks", validation.VArr(picks...)),
		kv("coverage", coverage),
		kv("held_out", validation.VArr(strVals(spec.HeldOut)...)),
		kv("input_class_fitness", validation.VStr(labelClassFitness)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("schema_version", validation.VInt(1)),
	)
	doc.O = withOptional(doc.O,
		optionalStr{"diagnosed_program", spec.DiagnosedProgram},
		optionalStr{"control_program", spec.ControlProgram})
	return doc
}

// strVals converts a []string to []validation.Value.
func strVals(items []string) []validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return out
}
