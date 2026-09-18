// Package dedup ports webv2.dedup: three-tier, Web3-aware deduplication.
//
// Mantis-style dedup collapses findings that share a technical signature or a
// normalized root-cause sentence. Web3 adds a nastier phenomenon: findings
// that are technically unrelated — different files, different bug classes —
// can be the SAME economic vulnerability (missing validation in function A,
// manipulated accounting through function B, and a withdrawal-path bypass
// through function C can all reduce to "attacker-controlled exchange rate
// creates unbacked withdrawal value").
//
// Tiers, cheapest/most-certain first:
//
//  1. technical_signature  — hash(class, path, function, invariant).
//     TRUE duplicate: auto-merge (mark DUPLICATE).
//  2. root_cause_signature — hash of a normalized one-sentence root cause +
//     CWE, set by an LLM normalization pass (this module never generates the
//     sentence). Clusters into a lineage; auto-merge only when the file and
//     function also match.
//  3. economic_signature   — hash of a normalized statement of what the
//     attacker ultimately gains/breaks. NEVER auto-merged: flagged as
//     possible_duplicate_of for critic/human decision, and guarded by a
//     class-compatibility table (incompatible classes cannot be the same
//     economic bug no matter how similar the text looks).
package dedup

import (
	"fmt"
	"math/big"
	"slices"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// kv is the vet-clean keyed KV constructor (unkeyed cross-package literals
// are rejected by go vet). Shared by the tests in this package.
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// EconomicCompatGroups is _ECONOMIC_COMPAT_GROUPS: classes that can plausibly
// share an economic effect. Two classes absent from a common group cannot
// tier-3-match. Exported because taxonomy.py unions these groups when it
// builds the canonical class list (_compat_classes).
var EconomicCompatGroups = [][]string{
	{"oracle-manipulation", "flash-loan", "economic-invariant",
		"share-price-inflation", "precision-rounding", "token-integration",
		"logic-error"},
	{"access-control", "authorization", "upgrade-initializer",
		"centralization-risk", "signature-replay"},
	{"reentrancy", "unchecked-external-call", "logic-error", "dos-griefing"},
	{"bridge-message", "cross-chain-replay", "signature-replay"},
	{"liquidation-logic", "oracle-manipulation", "economic-invariant"},
}

// AssetClassHints is _ASSET_CLASS_HINTS: E-classes that are only meaningful
// when both findings' economic impact touches the same asset-class bucket.
// Exported because taxonomy.py unions these values too. Go maps have no
// iteration order; taxonomy only unions the values into a set, so order is
// not observable.
var AssetClassHints = map[string][]string{
	"share-price": {"share-price-inflation", "precision-rounding", "donation"},
	"liquidation": {"liquidation-logic", "oracle-manipulation"},
	"bridge":      {"bridge-message", "cross-chain-replay"},
	"accounting":  {"economic-invariant", "logic-error", "precision-rounding"},
	"authz":       {"access-control", "authorization", "signature-replay"},
}

// ClassesCompatible is classes_compatible: the same class always matches;
// otherwise both classes must sit in one common compatibility group.
func ClassesCompatible(classA, classB string) bool {
	if classA == classB {
		return true
	}
	for _, group := range EconomicCompatGroups {
		if slices.Contains(group, classA) && slices.Contains(group, classB) {
			return true
		}
	}
	return false
}

// ---- seams into findings.py helpers internal/findings does not export yet ----
//
// mark_duplicate (findings.py:1458), flag_possible_duplicate (:1467) and
// fold_into_lineage (:1451) are not ported. The defaults FAIL LOUDLY: a sweep
// that cannot record its own decision must not look successful. The real
// implementations are installed with the Set* functions once findings exports
// them (they need findings.transition, which is also not ported yet).

// dedupHelperFn is the shared shape of the three findings.py helpers this
// package calls back into.
type dedupHelperFn func(*state.Campaign, string, string) (validation.Value, error)

// notWired is a seam default that fails loudly until a real helper is
// installed: a sweep that cannot record its own decision must not look
// successful.
func notWired(name string) dedupHelperFn {
	return func(*state.Campaign, string, string) (validation.Value, error) {
		return validation.VNull(), fmt.Errorf("dedup: %s is not wired", name)
	}
}

// markDuplicateFunc is the findings.mark_duplicate seam.
var markDuplicateFunc = notWired("findings.mark_duplicate")

// SetMarkDuplicate installs findings.mark_duplicate; nil restores the
// fail-loud default.
func SetMarkDuplicate(fn dedupHelperFn) {
	if fn == nil {
		markDuplicateFunc = notWired("findings.mark_duplicate")
		return
	}
	markDuplicateFunc = fn
}

// flagPossibleDuplicateFunc is the findings.flag_possible_duplicate seam.
var flagPossibleDuplicateFunc = notWired("findings.flag_possible_duplicate")

// SetFlagPossibleDuplicate installs findings.flag_possible_duplicate; nil
// restores the fail-loud default.
func SetFlagPossibleDuplicate(fn dedupHelperFn) {
	if fn == nil {
		flagPossibleDuplicateFunc = notWired("findings.flag_possible_duplicate")
		return
	}
	flagPossibleDuplicateFunc = fn
}

// foldIntoLineageFunc is the findings.fold_into_lineage seam.
var foldIntoLineageFunc = notWired("findings.fold_into_lineage")

// SetFoldIntoLineage installs findings.fold_into_lineage; nil restores the
// fail-loud default.
func SetFoldIntoLineage(fn dedupHelperFn) {
	if fn == nil {
		foldIntoLineageFunc = notWired("findings.fold_into_lineage")
		return
	}
	foldIntoLineageFunc = fn
}

// SetRootCauseSignature is set_root_cause_signature: record tier-2 after an
// LLM normalization pass. The sentence must be target-agnostic
// ('attacker-controlled exchange rate creates unbacked withdrawal value'),
// not a restatement of the file name. cwe nil/"" is Python's falsy check.
// sigLiveGuard refuses a signature on a row the sweep itself will skip:
// recording one is inert bookkeeping that LOOKS like coverage (critic r3).
// The predicate mirrors the sweep's liveness law exactly.
func sigLiveGuard(f validation.Value, findingID string) error {
	if findings.IsTerminal(validation.ObjStr(f, "status")) {
		return fmt.Errorf("cannot record a dedup signature on %s (%s): the "+
			"sweep only ever compares live rows — this would satisfy "+
			"nothing", findingID, validation.ObjStr(f, "status"))
	}
	return nil
}

func SetRootCauseSignature(campaign *state.Campaign, findingID, normalizedSentence string,
	cwe *string) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if err := sigLiveGuard(f, findingID); err != nil {
		return validation.VNull(), err
	}
	sig := findings.TextSignature(normalizedSentence)
	f = setDeep(f, validation.VStr(sig), "dedup", "root_cause_signature")
	if cwe != nil && *cwe != "" {
		f = setDeep(f, validation.VStr(*cwe), "root_cause", "cwe")
	}
	f = setDeep(f, validation.VStr(normalizedSentence), "dedup_meta", "root_cause_sentence")
	// r18 P2: signature stamped with no event = a dedup row the audit
	// can never explain; unwind law applies like everywhere else.
	if err := findings.SaveThenLog(campaign, &f, func() error {
		_, lerr := campaign.Log("dedup.root_cause_set", &findingID, nil)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return f, nil
}

// SetEconomicSignature is set_economic_signature: record tier-3 after an LLM
// normalization pass over the attacker's ultimate economic effect.
func SetEconomicSignature(campaign *state.Campaign, findingID,
	normalizedEffect string) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if err := sigLiveGuard(f, findingID); err != nil {
		return validation.VNull(), err
	}
	sig := findings.TextSignature(normalizedEffect)
	f = setDeep(f, validation.VStr(sig), "dedup", "economic_signature")
	f = setDeep(f, validation.VStr(normalizedEffect), "dedup_meta", "economic_effect_sentence")
	if err := findings.SaveThenLog(campaign, &f, func() error {
		_, lerr := campaign.Log("dedup.economic_set", &findingID, nil)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return f, nil
}

// LineageIDFor is lineage_id_for: a deterministic lineage id, so the same
// cluster gets the same id on every run (a uuid4 id churned on every sweep,
// which made re-runs look like new discoveries).
func LineageIDFor(signature string, memberIDs []string) string {
	sorted := append([]string(nil), memberIDs...)
	sort.Strings(sorted)
	digest := findings.TextSignature("lineage|" + signature + "|" + strings.Join(sorted, "|"))
	if len(digest) > 8 {
		digest = digest[:8]
	}
	return "LIN-" + digest
}

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

// ResolveCandidate is resolve_candidate: adjudicate ONE flagged
// near-duplicate pair (a tier-3 flag) — "same" or "distinct".
//
// The sweep FLAGGED near-duplicate pairs and nothing consumed the flags —
// every candidate still burned a full PoC cycle until a human noticed. This
// is the missing verdict step. The judgment is recorded on BOTH sides of the
// pair (one call resolves the pair), which is what the dedup completion proof
// tracks. "same" additionally merges the younger finding into the older one
// (mark_duplicate) — the expensive cycle is skipped. "distinct" leaves both
// open; the note is the record of why.
func ResolveCandidate(campaign *state.Campaign, findingID, ofFindingID, verdict, note,
	actor string) (validation.Value, error) {
	if verdict != "same" && verdict != "distinct" {
		return validation.VNull(), fmt.Errorf(
			"verdict must be 'same' or 'distinct', got %s", validation.PyReprStr(verdict))
	}
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if !slices.Contains(valueStrings(getDeep(f, "dedup", "possible_duplicate_of")), ofFindingID) {
		// Python raises KeyError(inner); str(KeyError) is repr(inner), which
		// is what the CLI prints, so the error text is that repr.
		inner := fmt.Sprintf("%s has no candidate flag for %s; run the dedup sweep first",
			findingID, validation.PyReprStr(ofFindingID))
		return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(inner))
	}
	stripped := validation.PyStrip(note)
	if note != "" && len([]rune(stripped)) < 5 {
		return validation.VNull(), fmt.Errorf("a candidate verdict note, when given, must be substantive")
	}
	// Both sides are loaded before either is saved (Python builds the whole
	// ((f, of), (load(of), id)) tuple first).
	other, err := findings.LoadFinding(campaign, ofFindingID)
	if err != nil {
		return validation.VNull(), err
	}
	sides := []struct {
		side    validation.Value
		otherID string
	}{{f, ofFindingID}, {other, findingID}}
	sideVals := make([]*validation.Value, 0, len(sides))
	for k := range sides {
		side := setDeep(sides[k].side, validation.VStr(verdict), "dedup",
			"candidate_verdicts", sides[k].otherID)
		if note != "" {
			side = setDeep(side, validation.VStr(stripped), "dedup_meta",
				"candidate_notes", sides[k].otherID)
		}
		sides[k].side = side
		sideVals = append(sideVals, &sides[k].side)
	}
	data := validation.VObj(
		kv("of", validation.VStr(ofFindingID)),
		kv("verdict", validation.VStr(verdict)),
		kv("actor", validation.VStr(actor)),
	)
	// r18 P2: a refused resolve event used to leave BOTH sides stamped
	// with a verdict the ledger never recorded — the pair silently
	// merged in the files only. SaveThenLogMany lands both files with
	// the event or restores both.
	if err := findings.SaveThenLogMany(campaign, sideVals, func() error {
		_, lerr := campaign.Log("dedup.candidate_resolved", &findingID,
			&data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	if verdict == "same" {
		if err := mergeYounger(campaign, f, ofFindingID); err != nil {
			return validation.VNull(), err
		}
		// G1 corroboration law: exactly one side SAST-flagged => the resolved
		// same-root-cause pair is independent corroboration. Same-engine
		// pairs never corroborate — an independent method is the point.
		// Recorded AFTER mergeYounger, on the SURVIVOR, naming the other
		// (merged-away) side: the merge marks one side DUPLICATE and
		// LoadLiveFindings (what ranking reads) drops DUPLICATE records, so a
		// pre-merge write can land on a record no consumer ever sees —
		// exactly what happens when the SAST finding is the older side.
		// Reload both sides: the merge just changed them.
		one, err := findings.LoadFinding(campaign, findingID)
		if err != nil {
			return validation.VNull(), err
		}
		two, err := findings.LoadFinding(campaign, ofFindingID)
		if err != nil {
			return validation.VNull(), err
		}
		oneTooled := len(valueStrings(getDeep(one, "provenance", "sast_tools"))) > 0
		twoTooled := len(valueStrings(getDeep(two, "provenance", "sast_tools"))) > 0
		// The corroboration dies with the duplicate record: it is written ONLY
		// on a survivor that is itself tool-less (the non-tool side the SAST
		// finding corroborates). When the SAST finding is the older side it
		// survives, and a link written on it would name a merged-away model
		// record no consumer can read — the G1 law is directional, so that
		// case records nothing at all (no write, no event).
		_, survivor := pickYoungerOlder(one, two)
		survivorTooled :=
			len(valueStrings(getDeep(survivor, "provenance", "sast_tools"))) > 0
		if oneTooled != twoTooled && !survivorTooled {
			other := one
			if validation.ObjStr(survivor, "finding_id") == validation.ObjStr(one, "finding_id") {
				other = two
			}
			otherID := validation.ObjStr(other, "finding_id")
			sid := validation.ObjStr(survivor, "finding_id")
			corroborated := setDeep(survivor, validation.VStr(otherID),
				"dedup_meta", "corroborated_by")
			data := validation.VObj(kv("of", validation.VStr(otherID)))
			if err := findings.SaveThenLog(campaign, &corroborated,
				func() error {
					_, lerr := campaign.Log("dedup.corroborated", &sid,
						&data)
					return lerr
				}); err != nil {
				return validation.VNull(), err
			}
		}
	}
	return findings.LoadFinding(campaign, findingID)
}

// pickYoungerOlder is resolve_candidate's merge ordering: the older side by
// created_at survives; an exact created_at tie breaks to the lower finding_id
// (the same (created_at, finding_id) order LoadAllFindings sorts by). Returns
// (younger, older). resolve_candidate's merge and its corroboration link both
// consume it, so there is only one ordering rule.
func pickYoungerOlder(a, b validation.Value) (validation.Value, validation.Value) {
	ca, cb := validation.ObjStr(a, "created_at"), validation.ObjStr(b, "created_at")
	if ca < cb {
		return b, a
	}
	if ca > cb {
		return a, b
	}
	if validation.ObjStr(a, "finding_id") < validation.ObjStr(b, "finding_id") {
		return b, a
	}
	return a, b
}

// mergeYounger is resolve_candidate's `same` tail: reload the flagged
// partner, pick the younger side by created_at (ties -> higher finding_id, so
// the lower id survives), and merge it into the older one unless it is already
// DUPLICATE.
func mergeYounger(campaign *state.Campaign, f validation.Value, ofFindingID string) error {
	other, err := findings.LoadFinding(campaign, ofFindingID)
	if err != nil {
		return err
	}
	younger, older := pickYoungerOlder(f, other)
	if validation.ObjStr(younger, "status") == "DUPLICATE" {
		return nil
	}
	_, err = markDuplicateFunc(campaign, validation.ObjStr(younger, "finding_id"), validation.ObjStr(older, "finding_id"))
	return err
}

// ---- local Value helpers (findings' equivalents are unexported) -------------

// getDeep is a chain of dict.get: Null as soon as a step is missing or is not
// an object (Python's (d.get(k1) or {}).get(k2)).
func getDeep(root validation.Value, keys ...string) validation.Value {
	cur := root
	for _, k := range keys {
		if cur.Kind != validation.Obj {
			return validation.VNull()
		}
		cur = validation.ObjAt(cur, k)
	}
	return cur
}

// setDeep is Python's d.setdefault(k1, {})[k2] = v chain: missing
// intermediate objects are created, an existing key keeps its position.
func setDeep(root validation.Value, v validation.Value, keys ...string) validation.Value {
	if len(keys) == 0 {
		return v
	}
	child := validation.VObj()
	for _, kv := range root.O {
		if kv.K == keys[0] && kv.V.Kind == validation.Obj {
			child = kv.V
			break
		}
	}
	child = setDeep(child, v, keys[1:]...)
	root.O = validation.SetOrAppend(root.O, keys[0], child)
	return root
}

// sigAt is (f.get("dedup") or {}).get(key) when truthy: the signature string,
// or "" for a falsy value (absent, null, empty).
func sigAt(f validation.Value, key string) string {
	if v := getDeep(f, "dedup", key); v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// groupBySig buckets findings by one dedup signature, preserving the first
// appearance order of each signature (Python dict iteration order).
func groupBySig(live []validation.Value, key string, exclude map[string]bool) []sigGroup {
	var groups []sigGroup
	index := map[string]int{}
	for _, f := range live {
		sig := sigAt(f, key)
		if sig == "" {
			continue
		}
		if exclude != nil && exclude[validation.ObjStr(f, "finding_id")] {
			continue
		}
		i, ok := index[sig]
		if !ok {
			i = len(groups)
			index[sig] = i
			groups = append(groups, sigGroup{sig: sig})
		}
		groups[i].members = append(groups[i].members, f)
	}
	return groups
}

// valueStrings is the string elements of a list value (finding ids; a
// non-list or non-string element cannot pass the finding schema).
func valueStrings(v validation.Value) []string {
	if v.Kind != validation.Arr {
		return nil
	}
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

// strArray builds a JSON array value from strings.
func strArray(items []string) validation.Value {
	arr := validation.VArr()
	for _, s := range items {
		arr.A = append(arr.A, validation.VStr(s))
	}
	return arr
}

// containsStr is Python's `x in list`.

// sameSpot is the tier-2 same_spot test: the first affected path AND function
// match ((f.get("affected") or [{}])[0] on both sides).
func sameSpot(dup, keep validation.Value) bool {
	dupFirst, keepFirst := firstAffected(dup), firstAffected(keep)
	return pyEqual(validation.ObjAt(dupFirst, "path"), validation.ObjAt(keepFirst, "path")) &&
		pyEqual(validation.ObjAt(dupFirst, "function"), validation.ObjAt(keepFirst, "function"))
}

// firstAffected is (f.get("affected") or [{}])[0]: the first affected entry,
// or an empty object when affected is missing or empty (both fields then
// compare as Python None).
func firstAffected(f validation.Value) validation.Value {
	arr := validation.ObjAt(f, "affected")
	if arr.Kind == validation.Arr && len(arr.A) > 0 {
		return arr.A[0]
	}
	return validation.VObj()
}

// pyEqual is Python == on two decoded JSON values: numbers compare across
// int/float, containers element-wise, objects key-insensitively to order.
func pyEqual(a, b validation.Value) bool {
	if isNum(a) && isNum(b) {
		return ratOf(a).Cmp(ratOf(b)) == 0
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Null:
		return true
	case validation.Bool:
		return a.B == b.B
	case validation.Str:
		return a.S == b.S
	case validation.Arr:
		if len(a.A) != len(b.A) {
			return false
		}
		for i := range a.A {
			if !pyEqual(a.A[i], b.A[i]) {
				return false
			}
		}
		return true
	case validation.Obj:
		if len(a.O) != len(b.O) {
			return false
		}
		for _, kv := range a.O {
			if !pyEqual(kv.V, validation.ObjAt(b, kv.K)) {
				return false
			}
		}
		return true
	}
	return false
}

// isNum reports whether v is an int or a float (Python's numeric kinds).
func isNum(v validation.Value) bool {
	return v.Kind == validation.Int || v.Kind == validation.Flt
}

// ratOf is the exact rational value of a number (big ints included).
func ratOf(v validation.Value) *big.Rat {
	if v.Kind == validation.Flt {
		return new(big.Rat).SetFloat64(v.F)
	}
	text := validation.IntText(v)
	if r, ok := new(big.Rat).SetString(text); ok {
		return r
	}
	return new(big.Rat)
}

// pyStrip is Python's str.strip() with no argument: trim str.isspace()
// characters from both ends.

// pySpace is Py_UNICODE_ISSPACE: the Unicode White_Space property plus the
// ASCII file separators U+001C-U+001F (Python's str.isspace() says true
// there, unicode.IsSpace does not).
