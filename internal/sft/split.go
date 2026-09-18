package sft

// split.go ports Task C: the cluster-aware split (no source cluster ever
// straddles the partition) and the mix report (taxonomy vs the 40/30/20/10
// target, pivot share, source mix, partition counts, dedup collisions and
// aggregated warnings).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"websec/internal/validation"
)

// TAXONOMY_TARGETS / HELD_OUT_FLOOR / PIVOT_TARGET_PCT (declaration order is
// the report's key order).
var TaxonomyTargets = []struct {
	Taxonomy string
	Target   float64
}{
	{"confirmed-critical", 40.0},
	{"real-weakness-non-exploitable", 30.0},
	{"invalid-hypothesis", 20.0},
	{"exploitable-below-threshold", 10.0},
}

const (
	// HeldOutFloor is HELD_OUT_FLOOR.
	HeldOutFloor = 0.15
	// PivotTargetPct is PIVOT_TARGET_PCT.
	PivotTargetPct = 33.0
)

// SplitExamples is split_examples: assign whole clusters to training/held-out
// so no source cluster ever straddles the split. Deterministic: cluster order
// is sha256(f"{seed}:{cluster}"); the walk stops filling held-out once its
// share of curated examples reaches 15% (the first cluster always goes to
// held-out when any curated example exists; a single oversized cluster may
// overshoot — whole-cluster beats floor).
func SplitExamples(seed int) (validation.Value, error) {
	store, err := LoadStore()
	if err != nil {
		return validation.VNull(), err
	}
	examples := validation.ObjAt(store, "examples").A
	curated := []validation.Value{}
	for _, e := range examples {
		if validation.ObjStr(e, "status") == "curated" {
			curated = append(curated, e)
		}
	}
	total := len(curated)
	clusterOf := func(e validation.Value) string {
		return validation.ObjStr(validation.ObjAt(e, "source"), "cluster")
	}
	clusters := map[string][]validation.Value{}
	order := []string{}
	for _, e := range curated {
		c := clusterOf(e)
		if _, seen := clusters[c]; !seen {
			order = append(order, c)
		}
		clusters[c] = append(clusters[c], e)
	}
	sort.Slice(order, func(i, j int) bool {
		return clusterDigest(seed, order[i]) < clusterDigest(seed, order[j])
	})
	held := 0
	assign := map[string]string{}
	trainingClusters, heldClusters := 0, 0
	for _, c := range order {
		n := len(clusters[c])
		if held == 0 || (total > 0 && float64(held)/float64(total) < HeldOutFloor) {
			assign[c] = "held-out"
			held += n
			heldClusters++
		} else {
			assign[c] = "training"
			trainingClusters++
		}
	}
	updated := append([]validation.Value(nil), examples...)
	anyCurated := false
	for i, e := range updated {
		if validation.ObjStr(e, "status") != "curated" {
			continue
		}
		anyCurated = true
		updated[i] = setKey(e, "partition", validation.VStr(assign[clusterOf(e)]))
	}
	if anyCurated {
		store = setKey(store, "examples", validation.VArr(updated...))
		if err := SaveStore(store); err != nil {
			return validation.VNull(), err
		}
	}
	training := 0
	for _, c := range order {
		if assign[c] == "training" {
			training += len(clusters[c])
		}
	}
	pct := 0.0
	if total > 0 {
		pct = validation.PyRound(100.0*float64(held)/float64(total), 1)
	}
	unsplit := 0
	for _, e := range examples {
		if validation.ObjStr(e, "status") != "curated" {
			unsplit++
		}
	}
	return validation.VObj(
		validation.KV{K: "training", V: validation.VInt(int64(training))},
		validation.KV{K: "held-out", V: validation.VInt(int64(held))},
		validation.KV{K: "unsplit_drafts", V: validation.VInt(int64(unsplit))},
		validation.KV{K: "held_out_pct", V: validation.VFloat(pct)},
		validation.KV{K: "clusters", V: validation.VObj(
			validation.KV{K: "training",
				V: validation.VInt(int64(trainingClusters))},
			validation.KV{K: "held-out",
				V: validation.VInt(int64(heldClusters))})}), nil
}

func clusterDigest(seed int, cluster string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", seed, cluster)))
	return hex.EncodeToString(sum[:])
}

// MixReport is mix_report: taxonomy mix vs target, pivot share vs ~1/3, source
// mix, partition counts, dedup collisions, aggregated warnings.
func MixReport() (validation.Value, error) {
	s := &mixReportState{}
	if err := s.mixReportLoad(); err != nil {
		return validation.VNull(), err
	}
	s.mixReportTaxonomy()
	s.mixReportPivot()
	s.mixReportSources()
	s.mixReportPartitions()
	s.mixReportCollisions()
	s.mixReportWarnings()
	return s.mixReportRender(), nil
}

// mixReportState carries the store snapshot and the computed report sections
// across the methods of MixReport.
type mixReportState struct {
	examples []validation.Value
	curated  []validation.Value
	n        int

	taxRows         []validation.KV
	pivotShare      float64
	sourceRows      []validation.KV
	partitionCounts map[string]int
	collisions      int
	warnings        []string
}

// mixReportLoad loads the store and filters the curated examples.
func (s *mixReportState) mixReportLoad() error {
	store, err := LoadStore()
	if err != nil {
		return err
	}
	s.examples = validation.ObjAt(store, "examples").A
	s.curated = []validation.Value{}
	for _, e := range s.examples {
		if validation.ObjStr(e, "status") == "curated" {
			s.curated = append(s.curated, e)
		}
	}
	s.n = len(s.curated)
	return nil
}

// mixReportTaxonomy computes the taxonomy-vs-target section.
func (s *mixReportState) mixReportTaxonomy() {
	s.taxRows = []validation.KV{}
	for _, tt := range TaxonomyTargets {
		count := 0
		for _, e := range s.curated {
			if validation.ObjStr(e, "taxonomy") == tt.Taxonomy {
				count++
			}
		}
		pct := 0.0
		if s.n > 0 {
			pct = validation.PyRound(100.0*float64(count)/float64(s.n), 1)
		}
		s.taxRows = append(s.taxRows, validation.KV{K: tt.Taxonomy,
			V: validation.VObj(
				validation.KV{K: "count", V: validation.VInt(int64(count))},
				validation.KV{K: "pct", V: validation.VFloat(pct)},
				validation.KV{K: "target_pct", V: validation.VFloat(tt.Target)},
				validation.KV{K: "gap",
					V: validation.VFloat(validation.PyRound(tt.Target-pct, 1))})})
	}
}

// mixReportPivot computes the pivot share against the ~1/3 target.
func (s *mixReportState) mixReportPivot() {
	withPivot := 0
	for _, e := range s.curated {
		if intOf(validation.ObjAt(validation.ObjAt(e, "structured"), "pivot_count")) >= 1 {
			withPivot++
		}
	}
	s.pivotShare = 0.0
	if s.n > 0 {
		s.pivotShare = validation.PyRound(100.0*float64(withPivot)/float64(s.n), 1)
	}
}

// mixReportSources computes the source-mix section (first-seen key order).
func (s *mixReportState) mixReportSources() {
	s.sourceRows = []validation.KV{}
	sourceSeen := map[string]bool{}
	for _, e := range s.curated {
		k := objStrDefault(validation.ObjAt(e, "source"), "kind", "unknown")
		if !sourceSeen[k] {
			sourceSeen[k] = true
			s.sourceRows = append(s.sourceRows, validation.KV{K: k,
				V: validation.VInt(0)})
		}
	}
	counts := map[string]int{}
	for _, e := range s.curated {
		counts[objStrDefault(validation.ObjAt(e, "source"), "kind", "unknown")]++
	}
	for i := range s.sourceRows {
		s.sourceRows[i].V = validation.VInt(int64(counts[s.sourceRows[i].K]))
	}
}

// mixReportPartitions counts examples per partition (curated vs unsplit).
func (s *mixReportState) mixReportPartitions() {
	s.partitionCounts = map[string]int{"training": 0, "held-out": 0, "unsplit": 0}
	for _, e := range s.examples {
		p := validation.ObjAt(e, "partition")
		if validation.ObjStr(e, "status") != "curated" || p.Kind == validation.Null {
			s.partitionCounts["unsplit"]++
			continue
		}
		s.partitionCounts[p.S]++
	}
}

// mixReportCollisions counts duplicate-signature collisions.
func (s *mixReportState) mixReportCollisions() {
	sigs := map[string]int{}
	for _, e := range s.curated {
		sigs[ExampleSignature(e)]++
	}
	s.collisions = 0
	for _, c := range sigs {
		if c >= 2 {
			s.collisions++
		}
	}
}

// mixReportWarnings aggregates the warn: lint lines of non-rejected examples.
func (s *mixReportState) mixReportWarnings() {
	s.warnings = []string{}
	for _, e := range s.examples {
		if validation.ObjStr(e, "status") == "rejected" {
			continue
		}
		others := []validation.Value{}
		for _, x := range s.curated {
			if validation.ObjStr(x, "id") != validation.ObjStr(e, "id") {
				others = append(others, x)
			}
		}
		for _, r := range LintExample(e, others,
			objStrDefault(e, "status", "draft")) {
			if len(r) >= 5 && r[:5] == "warn:" {
				s.warnings = append(s.warnings, validation.ObjStr(e, "id")+": "+r)
			}
		}
	}
}

// mixReportRender assembles the report object in its locked key order.
func (s *mixReportState) mixReportRender() validation.Value {
	return validation.VObj(
		validation.KV{K: "taxonomy_mix", V: validation.VObj(s.taxRows...)},
		validation.KV{K: "pivot_share_pct", V: validation.VFloat(s.pivotShare)},
		validation.KV{K: "pivot_target_pct", V: validation.VFloat(PivotTargetPct)},
		validation.KV{K: "source_mix", V: validation.VObj(s.sourceRows...)},
		validation.KV{K: "partition_counts", V: validation.VObj(
			validation.KV{K: "training",
				V: validation.VInt(int64(s.partitionCounts["training"]))},
			validation.KV{K: "held-out",
				V: validation.VInt(int64(s.partitionCounts["held-out"]))},
			validation.KV{K: "unsplit",
				V: validation.VInt(int64(s.partitionCounts["unsplit"]))})},
		validation.KV{K: "dedup_collisions", V: validation.VInt(int64(s.collisions))},
		validation.KV{K: "warnings", V: validation.StrArr(s.warnings)})
}
