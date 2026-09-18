// dedup_sweep.go: run_dedup split out of dedup.go — the three-tier sweep
// (technical, root-cause, economic), cross-snapshot flagging and the report.
package dedup

import (
	"slices"
	"sort"
	"websec/internal/findings"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- the sweep -------------------------------------------------------------

type tier1Merge struct{ kept, merged, signature string }
type crossFlag struct{ kept, flagged string }
type tier3Flag struct{ a, b, signature string }
type tier2Cluster struct {
	lineageID  string
	members    []string
	autoMerged []string
}

type sigGroup struct {
	sig     string
	members []validation.Value
}

// RunDedup is run_dedup(campaign, *, auto_merge=True): a full dedup sweep over
// all findings, returning the report dict.
//
// Order stability: findings are processed by created_at then finding_id
// (load_all_findings already returns this order; the explicit re-sort pins the
// contract) — so "the earliest finding is kept" really means earliest-created.
//
// Idempotence: already-terminal findings are excluded from grouping, so a
// second sweep reproduces the first sweep's decisions instead of adding new
// ones.
func RunDedup(campaign *state.Campaign, autoMerge bool) (validation.Value, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	// Non-duplicatable statuses: a finding in one of these cannot legally
	// transition to DUPLICATE (see findings.ALLOWED_TRANSITIONS), so it is
	// excluded from grouping. Merging one would abort the whole sweep with
	// an illegal transition.
	nonDuplicatable := map[string]bool{
		"DUPLICATE": true, "OUT_OF_SCOPE": true, "DISPROVED": true,
		"CHAIN": true, "INFORMATIONAL": true, "SUPERSEDED": true,
	}
	live := make([]validation.Value, 0, len(all))
	for _, f := range all {
		if nonDuplicatable[validation.ObjStr(f, "status")] {
			continue
		}
		live = append(live, f)
	}
	sort.SliceStable(live, func(i, j int) bool {
		ci, cj := validation.ObjStr(live[i], "created_at"), validation.ObjStr(live[j], "created_at")
		if ci != cj {
			return ci < cj
		}
		return validation.ObjStr(live[i], "finding_id") < validation.ObjStr(live[j], "finding_id")
	})

	merged := map[string]bool{}
	tier1, cross, err := tier1Sweep(campaign, live, merged, autoMerge)
	if err != nil {
		return validation.VNull(), err
	}
	tier2, err := tier2Sweep(campaign, live, merged, autoMerge)
	if err != nil {
		return validation.VNull(), err
	}
	tier3, err := tier3Sweep(campaign, live, merged)
	if err != nil {
		return validation.VNull(), err
	}
	untouched := 0
	for _, f := range live {
		if !merged[validation.ObjStr(f, "finding_id")] {
			untouched++
		}
	}
	report := buildReport(tier1, cross, tier2, tier3, untouched)
	data := validation.VObj(
		kv("tier1", validation.VInt(int64(len(tier1)))),
		kv("tier2_clusters", validation.VInt(int64(len(tier2)))),
		kv("tier3_flags", validation.VInt(int64(len(tier3)))),
	)
	if _, err := campaign.Log("dedup.run", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return report, nil
}

// tier1Sweep is the technical-signature pass: the first finding of each
// signature group is kept, later members are auto-merged (or, across
// snapshots, flagged and left LIVE so later tiers can still adjudicate them).
func tier1Sweep(campaign *state.Campaign, live []validation.Value, merged map[string]bool,
	autoMerge bool) ([]tier1Merge, []crossFlag, error) {
	var merges []tier1Merge
	var cross []crossFlag
	for _, g := range groupBySig(live, "technical_signature", nil) {
		if len(g.members) < 2 {
			continue
		}
		keep := g.members[0]
		keepID := validation.ObjStr(keep, "finding_id")
		for _, dup := range g.members[1:] {
			dupID := validation.ObjStr(dup, "finding_id")
			if merged[dupID] || !autoMerge {
				continue
			}
			didMerge, err := autoMergePair(campaign, keep, dup)
			if err != nil {
				return nil, nil, err
			}
			if didMerge {
				merges = append(merges, tier1Merge{kept: keepID, merged: dupID, signature: g.sig})
				merged[dupID] = true
				continue
			}
			// flagged, not merged: the pair needs re-verification against
			// different snapshots — it stays LIVE and still participates in
			// tier-2/3 analysis. Conflating flagged with merged (the old
			// unconditional add) dropped it from every later tier, so a
			// cross-snapshot duplicate could never be adjudicated by the
			// sweep.
			cross = append(cross, crossFlag{kept: keepID, flagged: dupID})
		}
	}
	return merges, cross, nil
}

// tier2Sweep is the root-cause pass: every member of a group is folded into
// one deterministic lineage; members that also share file+function are
// auto-merged into the group's first finding.
func tier2Sweep(campaign *state.Campaign, live []validation.Value, merged map[string]bool,
	autoMerge bool) ([]tier2Cluster, error) {
	var clusters []tier2Cluster
	for _, g := range groupBySig(live, "root_cause_signature", merged) {
		if len(g.members) < 2 {
			continue
		}
		memberIDs := make([]string, 0, len(g.members))
		for _, f := range g.members {
			memberIDs = append(memberIDs, validation.ObjStr(f, "finding_id"))
		}
		lineage := LineageIDFor(g.sig, memberIDs)
		keep := g.members[0]
		for _, f := range g.members {
			if _, err := foldIntoLineageFunc(campaign, validation.ObjStr(f, "finding_id"), lineage); err != nil {
				return nil, err
			}
		}
		cluster := tier2Cluster{lineageID: lineage, members: memberIDs, autoMerged: []string{}}
		handled := map[string]bool{}
		if autoMerge {
			for _, dup := range g.members[1:] {
				if !sameSpot(dup, keep) {
					continue
				}
				didMerge, err := autoMergePair(campaign, keep, dup)
				if err != nil {
					return nil, err
				}
				// Merged or cross-snapshot-flagged: the pair is already
				// adjudicable either way.
				dupID := validation.ObjStr(dup, "finding_id")
				handled[dupID] = true
				if didMerge {
					cluster.autoMerged = append(cluster.autoMerged, dupID)
					merged[dupID] = true
				}
			}
		}
		// D4 (2026-09-10): a same-root-cause pair at DIFFERENT code sites is
		// protected from auto-merge (one code site can host two causes, and one
		// cause can surface at two sites), and NO tier flagged it — tier 1
		// merges exact duplicates, tier 3 needs an economic signature the
		// campaign may never have set. Such a pair was therefore invisible to
		// `resolve-candidate` and each half burned its own proof-of-concept
		// cycle. The lineage is a claim that these findings share a cause, so
		// flag every pair inside it (both directions, so either side can be
		// adjudicated) for a human or model verdict. Flag-only: nothing here
		// merges, and a resolved verdict still comes from resolve-candidate.
		for i, a := range g.members {
			aID := validation.ObjStr(a, "finding_id")
			if handled[aID] {
				continue
			}
			for _, b := range g.members[i+1:] {
				bID := validation.ObjStr(b, "finding_id")
				if aID == bID || handled[bID] {
					continue
				}
				if _, err := flagPossibleDuplicateFunc(campaign, aID, bID); err != nil {
					return nil, err
				}
				if _, err := flagPossibleDuplicateFunc(campaign, bID, aID); err != nil {
					return nil, err
				}
			}
		}
		clusters = append(clusters, cluster)
	}
	return clusters, nil
}

// tier3Sweep is the economic-signature pass: flag-only. Class compatibility
// gates the pair (text similarity between incompatible classes is noise) and
// cross-snapshot pairs are skipped until re-verification.
func tier3Sweep(campaign *state.Campaign, live []validation.Value,
	merged map[string]bool) ([]tier3Flag, error) {
	var flags []tier3Flag
	for _, g := range groupBySig(live, "economic_signature", merged) {
		if len(g.members) < 2 {
			continue
		}
		for i, a := range g.members {
			for _, b := range g.members[i+1:] {
				classA := validation.ObjStr(validation.ObjAt(a, "root_cause"), "class")
				classB := validation.ObjStr(validation.ObjAt(b, "root_cause"), "class")
				if !ClassesCompatible(classA, classB) {
					continue // incompatible classes: text similarity is noise
				}
				// Python reads the active id once per side (short-circuit
				// `or`); the state cannot change mid-sweep, so one read is
				// equivalent.
				active, err := campaign.ActiveSnapshotIDOrNone()
				if err != nil {
					return nil, err
				}
				if snapshot.ReverifyRequired(a, active) || snapshot.ReverifyRequired(b, active) {
					continue // cross-snapshot economic matches need re-verification
				}
				aID, bID := validation.ObjStr(a, "finding_id"), validation.ObjStr(b, "finding_id")
				if _, err := flagPossibleDuplicateFunc(campaign, aID, bID); err != nil {
					return nil, err
				}
				if _, err := flagPossibleDuplicateFunc(campaign, bID, aID); err != nil {
					return nil, err
				}
				flags = append(flags, tier3Flag{a: aID, b: bID, signature: g.sig})
			}
		}
	}
	return flags, nil
}

// autoMergePair is _auto_merge_pair: the later finding becomes DUPLICATE of
// keep. Cross-snapshot duplicates are flagged, not merged — evidence was
// gathered against different code, so the dedup call itself needs
// re-verification. The bool reports whether a merge (as opposed to a
// cross-snapshot flag) happened — Python's `res is not None`.
func autoMergePair(campaign *state.Campaign, keep, dup validation.Value) (bool, error) {
	active, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return false, err
	}
	// Cross-snapshot on EITHER side needs re-verification (mirror the
	// tier-3 check): evidence gathered against different code must be
	// flagged, never auto-merged.
	if snapshot.ReverifyRequired(dup, active) ||
		snapshot.ReverifyRequired(keep, active) {
		dupID, keepID := validation.ObjStr(dup, "finding_id"), validation.ObjStr(keep, "finding_id")
		ids := valueStrings(getDeep(dup, "dedup", "possible_duplicate_of"))
		if !slices.Contains(ids, keepID) {
			ids = append(ids, keepID)
		}
		dup = setDeep(dup, strArray(ids), "dedup", "possible_duplicate_of")
		data := validation.VObj(kv("of", validation.VStr(keepID)))
		if err := findings.SaveThenLog(campaign, &dup, func() error {
			_, lerr := campaign.Log("dedup.cross_snapshot_flagged",
				&dupID, &data)
			return lerr
		}); err != nil {
			return false, err
		}
		return false, nil
	}
	if _, err := markDuplicateFunc(campaign, validation.ObjStr(dup, "finding_id"),
		validation.ObjStr(keep, "finding_id")); err != nil {
		return false, err
	}
	return true, nil
}

// buildReport assembles the report in Python's dict-literal key order.
func buildReport(tier1 []tier1Merge, cross []crossFlag, tier2 []tier2Cluster,
	tier3 []tier3Flag, untouched int) validation.Value {
	merges := validation.VArr()
	for _, m := range tier1 {
		merges.A = append(merges.A, validation.VObj(
			kv("kept", validation.VStr(m.kept)),
			kv("merged", validation.VStr(m.merged)),
			kv("signature", validation.VStr(m.signature)),
		))
	}
	clusters := validation.VArr()
	for _, cl := range tier2 {
		members := validation.VArr()
		for _, id := range cl.members {
			members.A = append(members.A, validation.VStr(id))
		}
		merged := validation.VArr()
		for _, id := range cl.autoMerged {
			merged.A = append(merged.A, validation.VStr(id))
		}
		clusters.A = append(clusters.A, validation.VObj(
			kv("lineage_id", validation.VStr(cl.lineageID)),
			kv("members", members),
			kv("auto_merged", merged),
		))
	}
	flags := validation.VArr()
	for _, fl := range tier3 {
		flags.A = append(flags.A, validation.VObj(
			kv("a", validation.VStr(fl.a)),
			kv("b", validation.VStr(fl.b)),
			kv("signature", validation.VStr(fl.signature)),
		))
	}
	crossFlags := validation.VArr()
	for _, cf := range cross {
		crossFlags.A = append(crossFlags.A, validation.VObj(
			kv("kept", validation.VStr(cf.kept)),
			kv("flagged", validation.VStr(cf.flagged)),
		))
	}
	return validation.VObj(
		kv("tier1_merges", merges),
		kv("tier2_clusters", clusters),
		kv("tier3_flags", flags),
		kv("cross_snapshot_flags", crossFlags),
		kv("untouched", validation.VInt(int64(untouched))),
	)
}
