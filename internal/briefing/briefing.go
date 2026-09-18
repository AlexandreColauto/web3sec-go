// Package briefing is webv2.briefing: the operator cockpit — one
// deterministic synthesis of the whole campaign, plus the attention ledger
// and the concrete prioritized next_actions list.
//
// Discipline (I1): this is a PURE VIEW. It mutates nothing — no phase
// moves, no stage ledger writes, no gate saves, no minting, no log events.
// The bounty gate runs with save=False; everything else is a load. A brief
// must be safe to run at any point, in any state, including an empty
// campaign.
package briefing

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"websec/internal/audit"
	"websec/internal/bounty"
	"websec/internal/chainengine"
	"websec/internal/classweights"
	"websec/internal/completion"
	"websec/internal/costs"
	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/learning"
	"websec/internal/orchestrator"
	"websec/internal/pipeline"
	"websec/internal/planner"
	"websec/internal/playbooks"
	"websec/internal/probes"
	"websec/internal/protocolgraph"
	"websec/internal/relations"
	"websec/internal/risk"
	"websec/internal/roles"
	"websec/internal/sandbox"
	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
	"websec/internal/version"
	"websec/internal/wilson"
)

var confirmedStatuses = map[string]bool{"CONFIRMED": true, "CHAIN": true}

var junkStatuses = map[string]bool{
	"DUPLICATE": true, "OUT_OF_SCOPE": true, "INFORMATIONAL": true,
	"SUPERSEDED": true,
}

// Materializable is _materializable: proposals whose members are all
// confirmed and that are not yet materialized.
func Materializable(campaign *state.Campaign) ([]validation.Value, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	byID := map[string]validation.Value{}
	superIDs := map[string]bool{}
	for _, f := range all {
		byID[validation.ObjStr(f, "finding_id")] = f
		if validation.ObjStr(f, "status") == "CHAIN" {
			superIDs[validation.ObjStr(f, "finding_id")] = true
		}
	}
	memberSets := [][]string{}
	// r43a: an absent chains/ directory is a campaign with nothing
	// materialized; a chains/ directory that cannot be listed refuses — the
	// old `if dirExists(...)` guard read an unreadable store as "no chains".
	paths, err := validation.ListPrefixedOptional(campaign.ChainsDir,
		"CHAIN-", ".json")
	if err != nil {
		return nil, fmt.Errorf("the chain store %s cannot be listed: %v",
			campaign.ChainsDir, err)
	}
	sort.Strings(paths)
	for _, p := range paths {
		doc, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		memberSets = append(memberSets, strListOf(validation.ObjAt(doc, "members")))
	}
	props, err := chainengine.FindChains(campaign, 2)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, prop := range props {
		members := strListOf(validation.ObjAt(prop, "members"))
		skip := false
		for _, m := range members {
			if superIDs[m] {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		for _, ms := range memberSets {
			if len(ms) > 0 && subsetOf(ms, members) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		ok := true
		for _, m := range members {
			f, found := byID[m]
			if !found || !confirmedStatuses[validation.ObjStr(f, "status")] {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		out = append(out, validation.VObj(
			kv("members", validation.StrArr(members)),
			kv("capabilities", validation.ObjAt(prop, "capabilities")),
			kv("action", validation.VStr("materialize_chain("+
				validation.PyListRepr(members)+")"))))
	}
	return out, nil
}

// GateDeficits is _gate_deficits: findings alive but not confirmed, with the
// exact gate deficit standing between them and CONFIRMED, ordered by
// risk.work_order_key.
func GateDeficits(campaign *state.Campaign) ([]validation.Value, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	type pair struct {
		key risk.WorkOrderKey
		row validation.Value
	}
	rows := []pair{}
	for _, f := range all {
		st := validation.ObjStr(f, "status")
		if confirmedStatuses[st] || junkStatuses[st] {
			continue
		}
		deficit := findings.EvidenceDeficit(f, "CONFIRMED", campaign)
		if deficit == nil {
			continue
		}
		level, err := findings.FindingLevel(f)
		if err != nil {
			return nil, err
		}
		key, err := risk.WorkOrderKeyFor(f)
		if err != nil {
			return nil, err
		}
		rows = append(rows, pair{key, validation.VObj(
			kv("finding_id", validation.ObjAt(f, "finding_id")),
			kv("title", validation.ObjAt(f, "title")),
			kv("status", validation.ObjAt(f, "status")),
			kv("level", validation.VStr(level)),
			kv("deficit", validation.VStr(*deficit)))})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].key.Less(rows[j].key)
	})
	out := make([]validation.Value, len(rows))
	for i, r := range rows {
		out[i] = r.row
	}
	return out, nil
}

// Reachability is _reachability: live findings whose CONFIRMED floor is
// E5/E6 and structurally unreachable in this campaign.
func Reachability(campaign *state.Campaign) ([]validation.Value, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	type pair struct {
		key risk.WorkOrderKey
		row validation.Value
	}
	rows := []pair{}
	for _, f := range all {
		st := validation.ObjStr(f, "status")
		if junkStatuses[st] {
			continue
		}
		classVal := validation.ObjAt(validation.ObjAt(f, "root_cause"), "class")
		class := ""
		if classVal.Kind == validation.Str {
			class = classVal.S
		}
		floor := findings.RequiredLevelForCampaign(campaign, "CONFIRMED", class)
		floorIdx, err := findings.LevelIndex(floor)
		if err != nil {
			return nil, err
		}
		e5, _ := findings.LevelIndex("E5")
		if floorIdx < e5 {
			continue
		}
		level, err := findings.FindingLevel(f)
		if err != nil {
			return nil, err
		}
		levelIdx, err := findings.LevelIndex(level)
		if err != nil {
			return nil, err
		}
		if levelIdx >= floorIdx {
			continue
		}
		var bugClass *string
		if classVal.Kind == validation.Str {
			bugClass = &class
		}
		diag, err := findings.ReachabilityDiagnostic(campaign, floor, bugClass)
		if err != nil {
			return nil, err
		}
		if len(diag) == 0 {
			continue
		}
		key, err := risk.WorkOrderKeyFor(f)
		if err != nil {
			return nil, err
		}
		var classOut validation.Value
		if bugClass != nil {
			classOut = validation.VStr(*bugClass)
		} else {
			classOut = validation.VNull()
		}
		rows = append(rows, pair{key, validation.VObj(
			kv("finding_id", validation.ObjAt(f, "finding_id")),
			kv("title", validation.ObjAt(f, "title")),
			kv("status", validation.ObjAt(f, "status")),
			kv("bug_class", classOut),
			kv("floor", validation.VStr(floor)),
			kv("level", validation.VStr(level)),
			kv("missing", validation.StrArr(diag)))})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].key.Less(rows[j].key)
	})
	out := make([]validation.Value, len(rows))
	for i, r := range rows {
		out[i] = r.row
	}
	return out, nil
}

// MemoryRecallHints is _memory_recall_hints: findings one gate clause from
// CONFIRMED whose VERIFIED graph-memory recall is still missing.
func MemoryRecallHints(campaign *state.Campaign) ([]string, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	type pair struct {
		key risk.WorkOrderKey
		id  string
	}
	rows := []pair{}
	for _, f := range all {
		st := validation.ObjStr(f, "status")
		if st != "POSSIBLE" && st != "PROVISIONALLY_VALID" {
			continue
		}
		v := validation.AsObj(validation.ObjAt(f, "verification"))
		if validation.ObjStr(v, "critic_verdict") != "confirmed" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(v, "reproduction"), "status") != "reproduced" {
			continue
		}
		level, err := findings.FindingLevel(f)
		if err != nil {
			return nil, err
		}
		li, err := findings.LevelIndex(level)
		if err != nil {
			return nil, err
		}
		e4, _ := findings.LevelIndex("E4")
		if li < e4 {
			continue
		}
		id := validation.ObjStr(f, "finding_id")
		fail, err := findings.MemoryCheckFails(campaign, id)
		if err != nil {
			return nil, err
		}
		if fail == nil {
			continue
		}
		key, err := risk.WorkOrderKeyFor(f)
		if err != nil {
			return nil, err
		}
		rows = append(rows, pair{key, id})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key.Less(rows[j].key) })
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.id
	}
	return out, nil
}

// ---- critical-hunt sections ------------------------------------------------

// chArtifact reads one critical-hunt artifact. nil means the artifact is
// genuinely ABSENT — the section it feeds is legitimately empty.
//
// r45a: the old body returned nil for EVERY stat/ReadJson error, so
// `chmod 000 archetype_prescreen.json` (or a torn document, or an ENOTDIR
// path) rendered as "this campaign has no prescreen" — a section silently
// dropped while the file the operator owns sat right there. Only
// os.IsNotExist is absence; every other error is a read failure this call
// could not perform, and it is DISCLOSED by name and errno through
// readProblems (BuildBrief folds those into the top-level problems block the
// cockpit prints). The section is still omitted — but no longer as a
// falsehood.
func chArtifact(campaign *state.Campaign, name string,
	readProblems *[]string) *validation.Value {
	p := filepath.Join(campaign.ArtifactsDir, name)
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		note(readProblems, unreadableNote(name, err))
		return nil
	}
	doc, err := validation.ReadJson(p)
	if err != nil {
		note(readProblems, unreadableNote(name, err))
		return nil
	}
	return &doc
}

// unreadableNote is the r45a wording for a file that EXISTS but could not be
// read: it names the file and the errno, and says plainly that the section is
// omitted rather than absent (the fix for the fold, not a cosmetic rewording).
func unreadableNote(name string, err error) string {
	return fmt.Sprintf("%s could not be read: %v — section omitted, not absent",
		name, err)
}

// unreadableSection is the same disclosure as a section value: the caller
// promotes the named message into the problems block and does NOT render the
// section, so no ranking/table is ever computed from input that was not read.
func unreadableSection(name string, err error) validation.Value {
	return validation.VObj(kv("unreadable",
		validation.VStr(unreadableNote(name, err))))
}

// noteProblem appends a read-failure disclosure to the top-level problems
// block unless the very same sentence is already there: two independent
// readers can fail on the same file (the critical-hunt reader of
// structural_index.json and the criticality ranker), and a diagnostic list
// that repeats one sentence verbatim reads as two problems.
func noteProblem(problems []string, msg string) []string {
	for _, have := range problems {
		if have == msg {
			return problems
		}
	}
	return append(problems, msg)
}

// unavailableLine is the in-section disclosure for the two line views
// (TrackedSurfaces, ChainAssumptions): their signature IS the display list
// the cockpit prints, so a read failure is a named line in that list —
// rendered exactly where the section would have been.
func unavailableLine(name string, err error, what string) string {
	return fmt.Sprintf("- UNAVAILABLE: %s could not be read: %v — %s",
		name, err, what)
}

// freshOrNone is roles._fresh_artifact's staleness rule: an artifact is
// current only while its recorded snapshot_id matches the active pin.
func freshOrNone(campaign *state.Campaign, data validation.Value) bool {
	if data.Kind != validation.Obj {
		return false
	}
	active, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return false
	}
	return nullableStrEqual(validation.ObjAt(data, "snapshot_id"), active)
}

func note(problems *[]string, msg string) {
	if problems != nil {
		*problems = append(*problems, msg)
	}
}

// ChPrescreen is _ch_prescreen.
func ChPrescreen(campaign *state.Campaign,
	problems *[]string, readProblems *[]string) (*validation.Value, error) {
	raw := chArtifact(campaign, "archetype_prescreen.json", readProblems)
	if raw == nil {
		return nil, nil
	}
	if raw.Kind != validation.Obj {
		note(problems, "archetype_prescreen.json malformed: not an object — "+
			"section omitted")
		return nil, nil
	}
	if !freshOrNone(campaign, *raw) {
		return nil, nil
	}
	results := validation.ObjAt(*raw, "results")
	if results.Kind != validation.Arr {
		note(problems, "archetype_prescreen.json malformed ('results' is "+
			"not a list) — section omitted")
		return nil, nil
	}
	matched := validation.ObjAt(*raw, "matched_ids")
	if matched.Kind != validation.Arr {
		note(problems, "archetype_prescreen.json malformed ('matched_ids' "+
			"is not a list) — section omitted")
		return nil, nil
	}
	forced := []validation.Value{}
	near := []validation.KV{}
	for _, r := range results.A {
		if r.Kind != validation.Obj {
			continue
		}
		if pyTruthyInt64Only(validation.ObjAt(r, "forced")) {
			forced = append(forced, validation.ObjAt(r, "id"))
		}
		if !pyTruthyInt64Only(validation.ObjAt(r, "match")) &&
			pyTruthyInt64Only(validation.ObjAt(r, "near_matches")) {
			near = append(near, validation.KV{K: validation.ObjStr(r, "id"),
				V: validation.ObjAt(r, "near_matches")})
		}
	}
	out := validation.VObj(
		kv("matched", matched),
		kv("forced", validation.VArr(forced...)),
		kv("near_matches", validation.VObj(near...)))
	return &out, nil
}

// ChForkdiff is _ch_forkdiff.
func ChForkdiff(campaign *state.Campaign,
	problems *[]string, readProblems *[]string) (*validation.Value, error) {
	raw := chArtifact(campaign, "fork_diff.json", readProblems)
	if raw == nil {
		return nil, nil
	}
	if raw.Kind != validation.Obj {
		note(problems, "fork_diff.json malformed: not an object — "+
			"section omitted")
		return nil, nil
	}
	if !freshOrNone(campaign, *raw) {
		return nil, nil
	}
	extra := validation.ObjAt(*raw, "extra_selectors")
	if extra.Kind != validation.Arr {
		note(problems, "fork_diff.json malformed ('extra_selectors' is not "+
			"a list) — section omitted")
		return nil, nil
	}
	if len(extra.A) > 10 {
		extra.A = extra.A[:10]
	}
	out := validation.VObj(
		kv("matched_baseline", validation.ObjAt(*raw, "matched_baseline")),
		kv("summary", validation.ObjAt(*raw, "diff_summary")),
		kv("extra_selectors", extra))
	return &out, nil
}

// ChRecency is _ch_recency.
func ChRecency(campaign *state.Campaign,
	problems *[]string, readProblems *[]string) ([]validation.Value, error) {
	raw := chArtifact(campaign, "recency.json", readProblems)
	if raw == nil {
		return []validation.Value{}, nil
	}
	if raw.Kind != validation.Obj {
		note(problems, "recency.json malformed: not an object — "+
			"section omitted")
		return []validation.Value{}, nil
	}
	if !freshOrNone(campaign, *raw) {
		return []validation.Value{}, nil
	}
	hot := validation.ObjAt(*raw, "hot_files")
	if hot.Kind == validation.Null {
		return []validation.Value{}, nil
	}
	if hot.Kind != validation.Arr {
		note(problems, "recency.json malformed ('hot_files' is not a list) — "+
			"section omitted")
		return []validation.Value{}, nil
	}
	out := []validation.Value{}
	skipped := 0
	items := hot.A
	if len(items) > 10 {
		items = items[:10]
	}
	for _, r := range items {
		if r.Kind != validation.Obj {
			skipped++
			continue
		}
		path := validation.ObjAt(r, "path")
		score := validation.ObjAt(r, "score")
		pathOut := validation.VStr("?")
		if path.Kind == validation.Str {
			pathOut = path
		}
		scoreOut := validation.VFloat(0.0)
		if score.Kind == validation.Int || score.Kind == validation.Flt ||
			score.Kind == validation.Bool {
			scoreOut = score
		}
		out = append(out, validation.VObj(
			kv("path", pathOut), kv("score", scoreOut),
			kv("days_ago", validation.ObjAt(r, "days_ago"))))
		if path.Kind == validation.Null || score.Kind == validation.Null {
			skipped++
		}
	}
	if skipped > 0 {
		plural := "entries"
		if skipped == 1 {
			plural = "entry"
		}
		note(problems, fmt.Sprintf("recency.json: %d hot-file %s missing "+
			"keys — shown with defaults", skipped, plural))
	}
	return out, nil
}

// ChAmplifiers is _ch_amplifiers.
func ChAmplifiers(campaign *state.Campaign, problems *[]string,
	readProblems *[]string) validation.Value {
	empty := func() validation.Value {
		return validation.VObj(kv("detected", validation.VObj()),
			kv("boosted_classes", validation.VArr()))
	}
	raw := chArtifact(campaign, "structural_index.json", readProblems)
	if raw == nil {
		return empty()
	}
	if raw.Kind != validation.Obj {
		note(problems, "structural_index.json malformed: not an object — "+
			"amplifier section omitted")
		return empty()
	}
	if !freshOrNone(campaign, *raw) {
		return empty()
	}
	detected := structidx.AmplifierSignals(*raw)
	if detected.Kind != validation.Obj {
		note(problems, "amplifier signals malformed: not an object — "+
			"amplifier section omitted")
		return empty()
	}
	boosted := []validation.Value{}
	classes, err := playbooks.AvailablePlaybooks()
	if err != nil {
		note(problems, fmt.Sprintf("playbook boost mapping failed (%s) — "+
			"boosted classes omitted", err))
		classes = nil
	}
	for _, cls := range classes {
		pb, found, err := playbooks.PlaybookForClass(cls)
		if err != nil {
			note(problems, fmt.Sprintf("playbook boost mapping failed (%s) — "+
				"boosted classes omitted", err))
			boosted = []validation.Value{}
			break
		}
		if !found {
			continue
		}
		det := map[string]bool{}
		for _, k := range detected.O {
			det[k.K] = true
		}
		hit := []string{}
		seen := map[string]bool{}
		for _, a := range listAt(pb, "amplifiers") {
			if a.Kind == validation.Str && det[a.S] && !seen[a.S] {
				seen[a.S] = true
				hit = append(hit, a.S)
			}
		}
		sort.Strings(hit)
		if len(hit) > 0 {
			boosted = append(boosted, validation.VObj(
				kv("bug_class", validation.VStr(cls)),
				kv("amplifiers", validation.StrArr(hit))))
		}
	}
	counts := []validation.KV{}
	for _, k := range detected.O {
		n := 0
		if k.V.Kind == validation.Arr {
			n = len(k.V.A)
		}
		counts = append(counts, validation.KV{K: k.K,
			V: validation.VInt(int64(n))})
	}
	return validation.VObj(kv("detected", validation.VObj(counts...)),
		kv("boosted_classes", validation.VArr(boosted...)))
}

// toolFlagVerdicts is the fixed census order of the G1 tool-flags block. A
// finding whose verification.critic_verdict is absent or outside this list
// lands in "pending" (the critic has not ruled yet).
var toolFlagVerdicts = []string{"confirmed", "disproved", "pending", "possible",
	"duplicate", "out_of_scope", "informational"}

// ChToolFlags is the G1 advisory block: a view-time census of the findings
// that carry non-empty provenance.sast_tools (the detector hypotheses), by
// critic verdict, plus the detector ids that corroborated a model finding
// (dedup_meta.corroborated_by). Returns Null — so the caller attaches no
// key and a campaign without detector findings renders byte-identical —
// when nothing carries detector provenance. Never stored, never scored.
func ChToolFlags(campaign *state.Campaign, problems *[]string) validation.Value {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		note(problems, fmt.Sprintf("tool flags: findings unreadable (%s) — "+
			"section omitted", err))
		return validation.VNull()
	}
	tooled := []validation.Value{}
	for _, f := range all {
		if len(listAt(validation.ObjAt(f, "provenance"), "sast_tools")) > 0 {
			tooled = append(tooled, f)
		}
	}
	if len(tooled) == 0 {
		return validation.VNull()
	}
	bucketOf := func(verdict string) string {
		for _, v := range toolFlagVerdicts {
			if v == verdict {
				return verdict
			}
		}
		return "pending"
	}
	counts := map[string]int{}
	for _, f := range tooled {
		counts[bucketOf(validation.ObjStr(validation.ObjAt(f, "verification"), "critic_verdict"))]++
	}
	buckets := []validation.KV{}
	for _, v := range toolFlagVerdicts {
		if n := counts[v]; n > 0 {
			buckets = append(buckets, kv(v, validation.VInt(int64(n))))
		}
	}
	seen := map[string]bool{}
	corroborated := []string{}
	for _, f := range all {
		by := validation.ObjStr(validation.ObjAt(f, "dedup_meta"), "corroborated_by")
		if by != "" && !seen[by] {
			seen[by] = true
			corroborated = append(corroborated, by)
		}
	}
	sort.Strings(corroborated)
	return validation.VObj(
		kv("total", validation.VInt(int64(len(tooled)))),
		kv("by_verdict", validation.VObj(buckets...)),
		kv("corroborated", validation.StrArr(corroborated)))
}

// ChInvariants is _ch_invariants.
func ChInvariants(campaign *state.Campaign,
	problems *[]string) validation.Value {
	degraded := func() validation.Value {
		return validation.VObj(kv("total", validation.VInt(0)),
			kv("by_verification_status", validation.VObj()),
			kv("unverified_model", validation.VArr()))
	}
	links, err := invariants.LoadLinks(campaign)
	if err != nil {
		note(problems, fmt.Sprintf("invariant registry unreadable (%s) — "+
			"invariant section omitted", err))
		return degraded()
	}
	reg := validation.ObjAt(links, "invariants")
	if reg.Kind == validation.Null && !validation.HasKey(links, "invariants") {
		reg = validation.VObj()
	}
	if reg.Kind != validation.Obj {
		note(problems, "invariant registry unreadable (invariant registry is "+
			"not an object) — invariant section omitted")
		return degraded()
	}
	byStatus := []validation.KV{}
	index := map[string]int{}
	unverified := []string{}
	for _, e := range reg.O {
		if e.V.Kind != validation.Obj {
			continue
		}
		st := validation.ObjStr(e.V, "status")
		if st == "" {
			st = "UNVERIFIED"
		}
		if i, ok := index[st]; ok {
			byStatus[i].V = validation.VInt(byStatus[i].V.I + 1)
		} else {
			index[st] = len(byStatus)
			byStatus = append(byStatus, validation.KV{K: st,
				V: validation.VInt(1)})
		}
		// A confirming verdict is CHECKED_AGAINST_CODE or CONTRADICTED (B3:
		// CONTRADICTED = the invariant is falsified by code, i.e. the attack
		// works — the strongest confirmation). Only model invariants with a
		// NON-confirming status are "unverified" and owed a check.
		if validation.ObjStr(e.V, "source") == "model" &&
			validation.ObjStr(e.V, "status") != "CHECKED_AGAINST_CODE" &&
			validation.ObjStr(e.V, "status") != "CONTRADICTED" {
			unverified = append(unverified, e.K)
		}
	}
	sort.Strings(unverified)
	return validation.VObj(
		kv("total", validation.VInt(int64(len(reg.O)))),
		kv("by_verification_status", validation.VObj(byStatus...)),
		kv("unverified_model", validation.StrArr(unverified)))
}

// ---- attention ledger (B4/D7) ----------------------------------------------

var isoInTextRe = regexp.MustCompile(
	`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?` +
		`(?:[+-]\d{2}:?\d{2}|Z)?`)

// FormatAge is format_age: compact, locale-free age.
func FormatAge(seconds float64) string {
	s := int64(seconds)
	if seconds < 0 {
		s = 0
	}
	switch {
	case s >= 86400:
		return fmt.Sprintf("%dd%dh", s/86400, (s%86400)/3600)
	case s >= 3600:
		return fmt.Sprintf("%dh%dm", s/3600, (s%3600)/60)
	case s >= 60:
		return fmt.Sprintf("%dm", s/60)
	}
	return fmt.Sprintf("%ds", s)
}

var isoLayouts = []string{
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05",
	"2006-01-02T15:04",
	"2006-01-02",
}

// ParseISO is _parse_iso: a tz-aware time from an ISO string, or nil. Naive
// stamps are read as UTC.
func ParseISO(ts string) *time.Time {
	if strings.TrimSpace(ts) == "" {
		return nil
	}
	s := strings.TrimSpace(ts)
	for _, layout := range isoLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			if t.Location() == time.UTC {
				return &t
			}
			u := t.UTC()
			return &u
		}
	}
	// Python's fromisoformat also accepts a trailing fractional part with
	// more than 9 digits and offsets without a colon; normalize both.
	if i := strings.IndexByte(s, '.'); i >= 0 {
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j-i-1 > 9 {
			s = s[:i+1+9] + s[j:]
		}
	}
	for _, layout := range isoLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			if t.Location() == time.UTC {
				return &t
			}
			u := t.UTC()
			return &u
		}
	}
	return nil
}

// age is _age: (seconds, rendered) or (nil, nil) when the stamp is unusable.
func age(now time.Time, ts string) (*int64, *string) {
	dt := ParseISO(ts)
	if dt == nil {
		return nil, nil
	}
	secs := int64(now.Sub(*dt).Seconds())
	if secs < 0 {
		secs = 0
	}
	txt := FormatAge(float64(secs))
	return &secs, &txt
}

// ageSortKey is _age_sort_key: oldest first; unknown sorts last.
func ageSortKey(secs *int64) int64 {
	if secs == nil {
		return 1
	}
	return -*secs
}

// firstStamp is _first_stamp: the first parseable candidate.
func firstStamp(candidates ...string) *string {
	for _, ts := range candidates {
		if ParseISO(ts) != nil {
			out := ts
			return &out
		}
	}
	return nil
}

func invariantsRankKey(item validation.Value) (bool, int64, string) {
	return !pyTruthyInt64Only(validation.ObjAt(item, "high_consequence")),
		ageSortKey(intPtr(validation.ObjAt(item, "age_seconds"))),
		validation.ObjStr(item, "invariant_id")
}

func leadRankKey(item validation.Value) (int, int64, string) {
	high := pyTruthyInt64Only(validation.ObjAt(item, "high_consequence"))
	kind := validation.ObjStr(item, "kind")
	cls := 2
	if kind == "queue" && high {
		cls = 0
	} else if kind == "invariant" && high {
		cls = 1
	}
	ident := validation.ObjStr(item, "priority_id")
	if ident == "" {
		ident = validation.ObjStr(item, "invariant_id")
	}
	if ident == "" {
		ident = "?"
	}
	return cls, ageSortKey(intPtr(validation.ObjAt(item, "age_seconds"))), ident
}

func entryTimestamp(entry validation.Value) *string {
	ts := validation.ObjStr(entry, "updated_at")
	if ParseISO(ts) != nil {
		out := ts
		return &out
	}
	m := isoInTextRe.FindString(validation.ObjStr(entry, "modified_by"))
	if m == "" {
		return nil
	}
	return &m
}

// priorityInvariant is _priority_invariant.
func priorityInvariant(priority, reg validation.Value) (string, *string, bool) {
	norm := map[string]validation.Value{}
	keys := map[string]string{}
	for _, e := range reg.O {
		if e.V.Kind != validation.Obj {
			continue
		}
		k := invariants.NormalizeInvID(e.K)
		norm[k] = e.V
		keys[k] = e.K
	}
	var bestRank *[2]any
	var bestKey string
	var bestSev *string
	bestHigh := false
	for _, raw := range listAt(priority, "invariant_ids") {
		if raw.Kind != validation.Str {
			continue
		}
		normID := invariants.NormalizeInvID(raw.S)
		key := raw.S
		entry := validation.VNull()
		if k, ok := keys[normID]; ok {
			key = k
			entry = norm[normID]
		}
		sevV := validation.ObjAt(entry, "severity_if_broken")
		var sev *string
		if sevV.Kind == validation.Str {
			s := sevV.S
			sev = &s
		}
		kind := validation.ObjStr(entry, "kind")
		high := (sev != nil && *sev == "critical") || kind == "liveness"
		rank := [2]any{!high, key}
		if bestRank == nil || rankLess(rank, *bestRank) {
			r := rank
			bestRank = &r
			bestKey = key
			bestSev = sev
			bestHigh = high
		}
	}
	if bestRank == nil {
		return "", nil, false
	}
	return bestKey, bestSev, bestHigh
}

func rankLess(a, b [2]any) bool {
	ab, bb := a[0].(bool), b[0].(bool)
	if ab != bb {
		return !ab
	}
	return a[1].(string) < b[1].(string)
}

func regOrEmpty(campaign *state.Campaign) validation.Value {
	links, err := invariants.LoadLinks(campaign)
	if err != nil {
		return validation.VObj()
	}
	reg := validation.ObjAt(links, "invariants")
	if reg.Kind != validation.Obj {
		return validation.VObj()
	}
	return reg
}

// AttentionLedger is attention_ledger: the queue/invariant debt ledger, aged
// against the brief's own generated_at.
func AttentionLedger(campaign *state.Campaign, now string,
	campaignID *string, closed bool) (validation.Value, error) {
	cid := campaign.CampaignID
	if campaignID != nil && *campaignID != "" {
		cid = *campaignID
	}
	nowDT := ParseISO(now)
	if nowDT == nil {
		t := time.Now().UTC()
		nowDT = &t
	}
	reg := regOrEmpty(campaign)
	queue := validation.VObj(
		kv("total", validation.VInt(0)), kv("worked", validation.VInt(0)),
		kv("untouched", validation.VInt(0)), kv("oldest", validation.VNull()),
		kv("line", validation.VNull()))
	invariantsBlock := validation.VObj(
		kv("total", validation.VInt(0)), kv("unverified", validation.VInt(0)),
		kv("high_consequence", validation.VInt(0)),
		kv("items", validation.VArr()), kv("line", validation.VNull()))
	ledger := validation.VObj(
		kv("as_of", validation.VStr(now)),
		kv("suppressed", validation.VNull()),
		kv("queue", queue), kv("invariants", invariantsBlock),
		kv("ranked", validation.VArr()), kv("lines", validation.VArr()))

	// -- queue debt
	plan, planErr := planner.LoadPlanReadonly(campaign)
	if planErr != nil {
		plan = validation.VNull()
	}
	if plan.Kind == validation.Obj {
		priorities := []validation.Value{}
		for _, p := range listAt(plan, "priorities") {
			if p.Kind == validation.Obj {
				priorities = append(priorities, p)
			}
		}
		untouched := []validation.Value{}
		for _, p := range priorities {
			st := validation.ObjStr(p, "status")
			dispositioned := false
			for _, d := range planner.ProbeRowDispositioned {
				if st == d {
					dispositioned = true
					break
				}
			}
			if !dispositioned {
				untouched = append(untouched, p)
			}
		}
		setKey(&queue, "total", validation.VInt(int64(len(priorities))))
		setKey(&queue, "worked", validation.VInt(
			int64(len(priorities)-len(untouched))))
		setKey(&queue, "untouched", validation.VInt(int64(len(untouched))))
		if len(untouched) > 0 {
			planT0 := validation.ObjStr(plan, "created_at")
			if planT0 == "" {
				planT0 = validation.ObjStr(plan, "generated_at")
			}
			type row struct {
				secs *int64
				pid  string
				age  *string
				p    validation.Value
			}
			rows := []row{}
			for _, p := range untouched {
				secs, ageTxt := age(*nowDT, deref(firstStamp(
					validation.ObjStr(p, "created_at"), validation.ObjStr(p, "generated_at"),
					validation.ObjStr(p, "opened_at"), planT0)))
				pid := validation.ObjStr(p, "id")
				if pid == "" {
					pid = "?"
				}
				rows = append(rows, row{secs, pid, ageTxt, p})
			}
			sort.SliceStable(rows, func(i, j int) bool {
				ki, kj := ageSortKey(rows[i].secs), ageSortKey(rows[j].secs)
				if ki != kj {
					return ki < kj
				}
				return rows[i].pid < rows[j].pid
			})
			r := rows[0]
			invID, severity, high := priorityInvariant(r.p, reg)
			suffix := ""
			if invID != "" {
				suffix = ", " + invID
				if severity != nil {
					suffix += " " + *severity
				}
			}
			ageTxt := "unknown"
			if r.age != nil {
				ageTxt = *r.age
			}
			command := fmt.Sprintf("webv2 answered %s %s answered "+
				"--reason R --actor A", cid, r.pid)
			if pyTruthyInt64Only(validation.ObjAt(r.p, "probe")) {
				command += " --anchor FIELD"
			}
			line := fmt.Sprintf("questions worked %d/%d — oldest untouched: "+
				"%s (%s%s)", intField(queue, "worked"), intField(queue, "total"),
				r.pid, ageTxt, suffix)
			var sevOut validation.Value
			if severity != nil {
				sevOut = validation.VStr(*severity)
			} else {
				sevOut = validation.VNull()
			}
			var invOut validation.Value
			if invID != "" {
				invOut = validation.VStr(invID)
			} else {
				invOut = validation.VNull()
			}
			var secsOut validation.Value = validation.VNull()
			if r.secs != nil {
				secsOut = validation.VInt(*r.secs)
			}
			oldest := validation.VObj(
				kv("priority_id", validation.VStr(r.pid)),
				kv("age", validation.VStr(ageTxt)),
				kv("age_seconds", secsOut),
				kv("invariant_id", invOut),
				kv("severity", sevOut),
				kv("high_consequence", validation.VBool(high)),
				kv("command", validation.VStr(command)),
				kv("line", validation.VStr(line+" — "+command)),
				kv("action", validation.VStr(fmt.Sprintf("work the oldest "+
					"untouched question %s (%s%s): %s", r.pid, ageTxt,
					suffix, command))))
			setKey(&queue, "oldest", oldest)
			setKey(&queue, "line", validation.ObjAt(oldest, "line"))
		}
	}

	// -- invariant debt
	st, err := campaign.State()
	if err != nil {
		return validation.VNull(), err
	}
	campaignStart := validation.ObjStr(st, "created_at")
	items := []validation.Value{}
	for _, e := range reg.O {
		if e.V.Kind != validation.Obj {
			continue
		}
		status := validation.ObjStr(e.V, "status")
		if status == "" {
			status = "UNVERIFIED"
		}
		if status != "UNVERIFIED" {
			continue
		}
		sevV := validation.ObjAt(e.V, "severity_if_broken")
		kindV := validation.ObjAt(e.V, "kind")
		ts := deref(entryTimestamp(e.V))
		if ts == "" {
			ts = campaignStart
		}
		secs, ageTxt := age(*nowDT, ts)
		ageText := "unknown"
		if ageTxt != nil {
			ageText = *ageTxt
		}
		command := fmt.Sprintf("webv2 invariant-verify %s %s --exec EXEC-*",
			cid, e.K)
		var secsOut validation.Value = validation.VNull()
		if secs != nil {
			secsOut = validation.VInt(*secs)
		}
		high := (sevV.Kind == validation.Str && sevV.S == "critical") ||
			(kindV.Kind == validation.Str && kindV.S == "liveness")
		line := fmt.Sprintf("verify %s (unverified %s): %s", e.K, ageText,
			command)
		items = append(items, validation.VObj(
			kv("kind", validation.VStr("invariant")),
			kv("invariant_id", validation.VStr(e.K)),
			kv("age", validation.VStr(ageText)),
			kv("age_seconds", secsOut),
			kv("severity_if_broken", sevV),
			kv("invariant_kind", kindV),
			kv("high_consequence", validation.VBool(high)),
			kv("command", validation.VStr(command)),
			kv("line", validation.VStr(line)),
			kv("action", validation.VStr(line))))
	}
	sort.SliceStable(items, func(i, j int) bool {
		hi, ki, ii := invariantsRankKey(items[i])
		hj, kj, ij := invariantsRankKey(items[j])
		if hi != hj {
			return !hi
		}
		if ki != kj {
			return ki < kj
		}
		return ii < ij
	})
	dictEntries := int64(0)
	for _, e := range reg.O {
		if e.V.Kind == validation.Obj {
			dictEntries++
		}
	}
	highCount := int64(0)
	for _, it := range items {
		if pyTruthyInt64Only(validation.ObjAt(it, "high_consequence")) {
			highCount++
		}
	}
	setKey(&invariantsBlock, "total", validation.VInt(dictEntries))
	setKey(&invariantsBlock, "unverified", validation.VInt(int64(len(items))))
	setKey(&invariantsBlock, "high_consequence", validation.VInt(highCount))
	setKey(&invariantsBlock, "items", validation.VArr(items...))
	if len(items) > 0 {
		top := items[0]
		setKey(&invariantsBlock, "line", validation.VStr(fmt.Sprintf(
			"invariants: %d UNVERIFIED (liveness/critical first, with age) — "+
				"verify %s (unverified %s): %s", len(items),
			validation.ObjStr(top, "invariant_id"), validation.ObjStr(top, "age"),
			validation.ObjStr(top, "command"))))
	}

	// -- the ordering list
	ranked := []validation.Value{}
	for _, it := range items {
		ranked = append(ranked, it)
	}
	if validation.ObjAt(queue, "oldest").Kind == validation.Obj {
		oldest := validation.ObjAt(queue, "oldest")
		ranked = append(ranked, validation.VObj(
			kv("kind", validation.VStr("queue")),
			kv("priority_id", validation.ObjAt(oldest, "priority_id")),
			kv("age", validation.ObjAt(oldest, "age")),
			kv("age_seconds", validation.ObjAt(oldest, "age_seconds")),
			kv("invariant_id", validation.ObjAt(oldest, "invariant_id")),
			kv("severity_if_broken", validation.ObjAt(oldest, "severity")),
			kv("high_consequence", validation.ObjAt(oldest, "high_consequence")),
			kv("command", validation.ObjAt(oldest, "command")),
			kv("line", validation.ObjAt(oldest, "line")),
			kv("action", validation.ObjAt(oldest, "action"))))
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		ci, ki, ii := leadRankKey(ranked[i])
		cj, kj, ij := leadRankKey(ranked[j])
		if ci != cj {
			return ci < cj
		}
		if ki != kj {
			return ki < kj
		}
		return ii < ij
	})
	setKey(&ledger, "ranked", validation.VArr(ranked...))

	// -- printable block
	lines := []string{}
	if validation.ObjAt(queue, "line").Kind == validation.Str {
		lines = append(lines, validation.ObjAt(queue, "line").S)
	}
	if validation.ObjAt(invariantsBlock, "line").Kind == validation.Str {
		lines = append(lines, validation.ObjAt(invariantsBlock, "line").S)
		named := ""
		if len(items) > 0 {
			named = validation.ObjStr(items[0], "invariant_id")
		}
		for _, it := range items {
			if pyTruthyInt64Only(validation.ObjAt(it, "high_consequence")) &&
				validation.ObjStr(it, "invariant_id") != named {
				lines = append(lines, validation.ObjStr(it, "line"))
			}
		}
	}
	setKey(&ledger, "lines", validation.StrArr(lines))

	if closed {
		suppressDebt(&ledger)
	}
	return ledger, nil
}

func suppressDebt(ledger *validation.Value) {
	setKey(ledger, "suppressed", validation.VStr("campaign closed by "+
		"decision — no debt nagging (closed-cockpit discipline)"))
	setKey(ledger, "lines", validation.VArr())
	setKey(ledger, "ranked", validation.VArr())
	queue := validation.ObjAt(*ledger, "queue")
	setKey(&queue, "line", validation.VNull())
	oldest := validation.ObjAt(queue, "oldest")
	if oldest.Kind == validation.Obj {
		setKey(&oldest, "line", validation.VNull())
		setKey(&oldest, "action", validation.VNull())
		setKey(&queue, "oldest", oldest)
	}
	setKey(ledger, "queue", queue)
	invariantsBlock := validation.ObjAt(*ledger, "invariants")
	setKey(&invariantsBlock, "line", validation.VNull())
	items := listAt(invariantsBlock, "items")
	for i := range items {
		setKey(&items[i], "line", validation.VNull())
		setKey(&items[i], "action", validation.VNull())
	}
	setKey(&invariantsBlock, "items", validation.VArr(items...))
	setKey(ledger, "invariants", invariantsBlock)
}

// ---- bounty view -----------------------------------------------------------

// Bounty is _bounty: CONFIRMED findings through the gate (save=False — the
// brief must not write).
func Bounty(campaign *state.Campaign) (validation.Value, error) {
	st, err := campaign.State()
	if err != nil {
		return validation.VNull(), err
	}
	policyPath := validation.ObjStr(st, "policy_path")
	if policyPath == "" {
		return validation.VObj(kv("policy", validation.VNull()),
			kv("evaluated", validation.VArr())), nil
	}
	// r45: an unreadable policy file is NOT an absent policy. NotExist keeps
	// rendering policy:null (a campaign with no policy loaded); any other
	// stat error refuses naming the path, instead of claiming the operator
	// never loaded one.
	if _, serr := os.Stat(policyPath); serr != nil {
		if !os.IsNotExist(serr) {
			return validation.VNull(), fmt.Errorf(
				"the bounty policy %s cannot be read: %v", policyPath, serr)
		}
		return validation.VObj(kv("policy", validation.VNull()),
			kv("evaluated", validation.VArr())), nil
	}
	policy, err := bounty.LoadPolicy(policyPath)
	if err != nil {
		return validation.VNull(), err
	}
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	type pair struct {
		key risk.WorkOrderKey
		row validation.Value
	}
	rows := []pair{}
	for _, f := range all {
		if !confirmedStatuses[validation.ObjStr(f, "status")] {
			continue
		}
		res, err := bounty.EvaluateBountyGate(campaign,
			validation.ObjStr(f, "finding_id"), policy, false)
		if err != nil {
			return validation.VNull(), err
		}
		blocking := listAt(res, "blocking_reasons")
		if blocking == nil {
			blocking = []validation.Value{}
		}
		key, err := risk.WorkOrderKeyFor(f)
		if err != nil {
			return validation.VNull(), err
		}
		rows = append(rows, pair{key, validation.VObj(
			kv("finding_id", validation.ObjAt(f, "finding_id")),
			kv("title", validation.ObjAt(f, "title")),
			kv("eligible", validation.ObjAt(res, "eligible")),
			kv("submission_ready", validation.ObjAt(res, "submission_ready")),
			kv("blocking_reasons", validation.VArr(blocking...)))})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].key.Less(rows[j].key)
	})
	evaluated := make([]validation.Value, len(rows))
	for i, r := range rows {
		evaluated[i] = r.row
	}
	return validation.VObj(kv("policy", validation.VStr(filepath.Base(policyPath))),
		kv("evaluated", validation.VArr(evaluated...))), nil
}

// TrackedSurfaces is the G9 opaque-surface view: one display line per
// protocol-model component (`- <kind> <path|url>:
// <in_scope|out-of-scope><, paid>`, via protocolgraph.ComponentSurfaceLines).
// A missing model file (or a model with no components) yields no lines —
// the caller presence-gates on len, so a component-free campaign's brief
// bytes are unchanged. Findings may anchor on these surfaces; structidx
// never indexes them.
//
// r45a: a model that EXISTS but could not be read is NOT "no components": the
// old body returned nil for every stat/ReadJson error, so `chmod 000
// protocol_model.json` made the whole block disappear from the cockpit. The
// read failure is now a named UNAVAILABLE line this caller prints in place of
// the block; genuine absence still yields no lines at all.
func TrackedSurfaces(campaign *state.Campaign) []string {
	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	const what = "tracked surfaces unknown, not absent"
	if _, err := os.Stat(modelPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []string{unavailableLine("protocol_model.json", err, what)}
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return []string{unavailableLine("protocol_model.json", err, what)}
	}
	return protocolgraph.ComponentSurfaceLines(model)
}

// ChainAssumptions is the G10 assumption-table view: one display line per
// AssumptionTable row plus one per gap, via the shared
// protocolgraph.RenderAssumptionLines builder (the same bytes the report
// renders, so the two can never drift apart).
//
// Presence-gated (the Task 4 law): the block renders ONLY when
// len(rows) > 0 AND (any row carries a non-null detail OR len(gaps) > 0).
// A row carries detail when any non-chain field is non-null. A chains-only
// legacy model (no assumptions, no BRIDGES-touch gaps) yields no lines —
// the caller gates on len, so a legacy campaign's brief bytes are
// unchanged. Findings never anchor on these lines; structidx never indexes
// them.
//
// r45a: a model that EXISTS but could not be read must not render as "no
// assumptions declared" — the same fold as TrackedSurfaces above, with the
// same fix: a named UNAVAILABLE line instead of a silently missing section.
func ChainAssumptions(campaign *state.Campaign) []string {
	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	const what = "the assumption table is unknown, not empty"
	if _, err := os.Stat(modelPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []string{unavailableLine("protocol_model.json", err, what)}
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return []string{unavailableLine("protocol_model.json", err, what)}
	}
	rows, gaps := protocolgraph.AssumptionTable(model)
	if len(rows) == 0 {
		return nil
	}
	hasDetail := false
	for _, r := range rows {
		for _, pair := range r.O {
			if pair.K == "chain" {
				continue
			}
			if pair.V.Kind != validation.Null {
				hasDetail = true
				break
			}
		}
		if hasDetail {
			break
		}
	}
	if !hasDetail && len(gaps) == 0 {
		return nil
	}
	return protocolgraph.RenderAssumptionLines(rows, gaps)
}

// BuildBrief is build_brief: the full briefing.
func BuildBrief(campaign *state.Campaign, deepAudit bool,
	now *string) (validation.Value, error) {
	st, err := campaign.State()
	if err != nil {
		return validation.VNull(), err
	}
	generatedAt := state.NowIso()
	if now != nil {
		generatedAt = *now
	}
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	counts := []validation.KV{}
	index := map[string]int{}
	for _, f := range all {
		s := validation.ObjStr(f, "status")
		if i, ok := index[s]; ok {
			counts[i].V = validation.VInt(counts[i].V.I + 1)
		} else {
			index[s] = len(counts)
			counts = append(counts, validation.KV{K: s,
				V: validation.VInt(1)})
		}
	}

	o := orchestrator.New(campaign)
	e6, err := o.IndependentVerificationQueue()
	if err != nil {
		return validation.VNull(), err
	}
	byID := map[string]validation.Value{}
	for _, f := range all {
		byID[validation.ObjStr(f, "finding_id")] = f
	}
	e6List := append([]validation.Value{}, e6.A...)
	type e6key struct {
		mandatory bool
		key       risk.WorkOrderKey
	}
	keys := make([]e6key, len(e6List))
	for i, q := range e6List {
		f, ok := byID[validation.ObjStr(q, "finding_id")]
		if !ok {
			f = validation.VObj(kv("finding_id", validation.ObjAt(q, "finding_id")))
		}
		k, err := risk.WorkOrderKeyFor(f)
		if err != nil {
			return validation.VNull(), err
		}
		keys[i] = e6key{pyTruthyInt64Only(validation.ObjAt(q, "mandatory")), k}
	}
	sort.SliceStable(e6List, func(i, j int) bool {
		if keys[i].mandatory != keys[j].mandatory {
			return keys[i].mandatory
		}
		return keys[i].key.Less(keys[j].key)
	})
	e6 = validation.VArr(e6List...)

	chains, err := Materializable(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	terminal, err := chainengine.TerminalReport(campaign, nil)
	if err != nil {
		return validation.VNull(), err
	}
	bountyView, err := Bounty(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	deficits, err := GateDeficits(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	reach, err := Reachability(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	memPending, err := MemoryRecallHints(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	corpusRecall, err := findings.CorpusRecallGaps(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	pendingMem, err := learning.PendingMemory(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	relView, err := relations.GraphView(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	relCheck, err := relations.VerifyRelations(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	yieldRep, err := costs.YieldReport(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	advice, err := costs.AllocationAdvice(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	budget, err := costs.BudgetStatus(campaign)
	if err != nil {
		return validation.VNull(), err
	}

	huntProblems := []string{}

	// r45a: read failures get their own sink. huntProblems keeps its existing
	// semantics (Python's critical_hunt.problems: malformed-input notes only),
	// while readProblems is folded into the top-level problems block — the one
	// diagnostic list the cockpit prints — so a section that is omitted
	// because its input could not be READ is disclosed instead of rendering
	// as a section that is legitimately empty.
	readProblems := []string{}

	// feedback-triage A5: the stage ledger also carries sub-stage rows the
	// orchestrator emits per pass (discovery-specialist,
	// hypothesis-triage, dedup-normalization, independent-reproduction,
	// ...). Those are not among the canonical pipeline stages, so counting
	// every done row let the cockpit report "stages 19/17". The denominator
	// is len(pipeline.StageIDs), so the numerator must count the same
	// top-level set.
	topLevel := make(map[string]bool, len(pipeline.StageIDs))
	for _, id := range pipeline.StageIDs {
		topLevel[id] = true
	}
	stages := validation.AsObj(validation.ObjAt(st, "stages"))
	stagesDone := int64(0)
	for _, s := range stages.O {
		if topLevel[s.K] && validation.ObjStr(s.V, "status") == "done" {
			stagesDone++
		}
	}
	var elapsedOut validation.Value = validation.VNull()
	if created := validation.ObjStr(st, "created_at"); created != "" {
		if t0 := ParseISO(created); t0 != nil {
			elapsedOut = validation.VFloat(validation.PythonRound(
				time.Since(*t0).Seconds()/3600, 1))
		}
	}

	problems := []string{}
	liveFindings := []validation.Value{}
	for _, f := range all {
		if !junkStatuses[validation.ObjStr(f, "status")] {
			liveFindings = append(liveFindings, f)
		}
	}
	if len(liveFindings) > 0 && intField(relView, "edge_count") == 0 &&
		validation.ObjStr(st, "phase") != "COMPLETE" {
		problems = append(problems, "the graph was never written — mint its "+
			"deterministic edges: webv2 relations "+
			campaign.CampaignID+" --rebuild")
	}

	prescreen, err := ChPrescreen(campaign, &huntProblems, &readProblems)
	if err != nil {
		return validation.VNull(), err
	}
	forkDiff, err := ChForkdiff(campaign, &huntProblems, &readProblems)
	if err != nil {
		return validation.VNull(), err
	}
	recency, err := ChRecency(campaign, &huntProblems, &readProblems)
	if err != nil {
		return validation.VNull(), err
	}
	amplifiers := ChAmplifiers(campaign, &huntProblems, &readProblems)
	toolFlags := ChToolFlags(campaign, &huntProblems)
	invSection := ChInvariants(campaign, &huntProblems)
	// r45a: the artifacts above exist but could not be read — say so in the
	// cockpit-visible problems list instead of letting the sections vanish.
	for _, msg := range readProblems {
		problems = noteProblem(problems, msg)
	}
	stale, err := roles.StaleArtifacts(campaign)
	if err != nil {
		return validation.VNull(), err
	}

	terminals := []validation.Value{}
	for _, p := range listAt(terminal, "shortest_by_terminal") {
		terminals = append(terminals, validation.VObj(
			kv("path", validation.ObjAt(p, "path")),
			kv("terminal_capability", validation.ObjAt(p, "terminal_capability")),
			kv("capital_usd", validation.ObjAt(p, "total_capital_required_usd"))))
	}
	pmOut := []validation.Value{}
	for _, m := range pendingMem {
		pmOut = append(pmOut, validation.VObj(
			kv("memory_id", validation.ObjAt(m, "memory_id")),
			kv("kind", validation.ObjAt(m, "kind")),
			kv("status", validation.ObjAt(m, "status")),
			kv("pattern", validation.ObjAt(m, "pattern")),
			kv("finding_id", validation.ObjAt(m, "finding_id"))))
	}
	byKind := []validation.KV{}
	for _, k := range validation.AsObj(validation.ObjAt(relView, "by_kind")).O {
		n := 0
		if k.V.Kind == validation.Arr {
			n = len(k.V.A)
		}
		byKind = append(byKind, validation.KV{K: k.K, V: validation.VInt(int64(n))})
	}
	var snapshotOut validation.Value = validation.VNull()
	if sid, err := campaign.ActiveSnapshotIDOrNone(); err == nil && sid != nil {
		snapshotOut = validation.VStr(*sid)
	}
	campaignBlock := validation.VObj(
		kv("campaign_id", validation.VStr(campaign.CampaignID)),
		kv("program", validation.ObjAt(st, "program")),
		kv("phase", validation.ObjAt(st, "phase")),
		kv("closed", validation.VBool(validation.ObjStr(st, "phase") == "COMPLETE")),
		kv("completed_by", validation.ObjAt(st, "completed_by")),
		kv("completed_reason", validation.ObjAt(st, "completed_reason")),
		kv("pass", validation.ObjAt(validation.ObjAt(st, "budget"), "pass")),
		kv("discovery_slots_left", validation.VInt(
			intField(validation.ObjAt(st, "budget"), "max_discovery_findings")-
				intField(validation.ObjAt(st, "budget"), "discovery_findings_so_far"))),
		kv("active_snapshot", snapshotOut),
		kv("stages_done", validation.VInt(stagesDone)),
		kv("stages_total", validation.VInt(int64(len(pipeline.StageIDs)))),
		kv("elapsed_hours", elapsedOut))

	findingsBlock := validation.VObj(
		kv("total", validation.VInt(int64(len(all)))),
		kv("by_status", validation.VObj(counts...)),
		kv("materializable_chains", validation.VArr(chains...)),
		kv("gate_deficits", validation.VArr(deficits...)),
		kv("structurally_unreachable", validation.VArr(reach...)),
		kv("memory_recall_pending", validation.StrArr(memPending)))

	// G1 tool flags: the advisory block is attached only when it has
	// content (validation.Null means no finding carries detector
	// provenance), so a campaign without detector findings keeps
	// byte-identical brief output — the additive convention.
	huntBlock := validation.VObj(
		kv("prescreen", ptrOrNull(prescreen)),
		kv("fork_diff", ptrOrNull(forkDiff)),
		kv("recency_top", validation.VArr(recency...)),
		kv("amplifiers", amplifiers),
		kv("invariant_verification", invSection),
		kv("stale_artifacts", validation.VArr(stale...)),
		kv("problems", validation.StrArr(huntProblems)))
	if toolFlags.Kind != validation.Null {
		setKey(&huntBlock, "tool_flags", toolFlags)
	}

	brief := validation.VObj(
		kv("generated_at", validation.VStr(generatedAt)),
		kv("campaign", campaignBlock),
		kv("findings", findingsBlock),
		kv("corpus_recall", corpusRecall),
		kv("terminals", validation.VArr(terminals...)),
		kv("independent_verification_queue", e6),
		kv("bounty", bountyView),
		kv("pending_memory", validation.VArr(pmOut...)),
		kv("relations", validation.VObj(
			kv("edge_count", validation.ObjAt(relView, "edge_count")),
			kv("by_kind", validation.VObj(byKind...)),
			kv("drift_problems", validation.ObjAt(relCheck, "problems")))),
		kv("problems", validation.StrArr(problems)),
		kv("economics", validation.VObj(
			kv("totals", validation.ObjAt(yieldRep, "totals")),
			kv("budget", budget),
			kv("allocation_advice", validation.VArr(advice...)),
			kv("note", validation.VStr("advisory only — never gates a "+
				"status (the cost ceiling halts the pipeline, it does not "+
				"gate findings)")))),
		kv("critical_hunt", huntBlock))

	// G13 cost attribution, presence-gated (the additive convention): a
	// campaign with zero lens-carrying cost rows and no plan lens data
	// keeps byte-identical brief output — no lens_yield key at all.
	if lensYield, err := costs.LensYield(campaign); err != nil {
		return validation.VNull(), err
	} else if len(lensYield) > 0 {
		econ := validation.ObjAt(brief, "economics")
		setKey(&econ, "lens_yield", validation.VArr(lensYield...))
		setKey(&brief, "economics", econ)
	}

	if deepAudit {
		// Python's `from . import audit` registers every section at import
		// time; the port registers them through audit.Setup().
		audit.Setup()
		report, err := audit.AuditCampaign(campaign)
		if err != nil {
			return validation.VNull(), err
		}
		shared, err := sharedmem.VerifySharedStore(campaign.Root)
		if err != nil {
			return validation.VNull(), err
		}
		integProblems := []validation.KV{}
		for _, sec := range validation.AsObj(validation.ObjAt(report, "sections")).O {
			if pyTruthyInt64Only(validation.ObjAt(sec.V, "problems")) {
				integProblems = append(integProblems, validation.KV{K: sec.K,
					V: validation.ObjAt(sec.V, "problems")})
			}
		}
		if pyTruthyInt64Only(validation.ObjAt(shared, "problems")) {
			integProblems = append(integProblems, validation.KV{
				K: "shared_store", V: validation.ObjAt(shared, "problems")})
		}
		setKey(&brief, "integrity", validation.VObj(
			kv("ok", validation.VBool(pyTruthyInt64Only(validation.ObjAt(report, "ok")) &&
				pyTruthyInt64Only(validation.ObjAt(shared, "ok")))),
			kv("summary", validation.VStr(audit.AuditSummaryLine(report))),
			kv("problems", validation.VObj(integProblems...)),
			kv("shared_store", shared)))
	} else {
		chain, err := campaign.VerifyLog()
		if err != nil {
			return validation.VNull(), err
		}
		chainProblems := []validation.Value{}
		if !chain.OK {
			for _, p := range chain.Problems {
				chainProblems = append(chainProblems, validation.VStr(p))
			}
		}
		setKey(&brief, "integrity", validation.VObj(
			kv("ok", validation.VBool(chain.OK)),
			kv("events_checked", validation.VInt(int64(chain.Events))),
			kv("note", validation.VStr("event-log chain checked (fast); run "+
				"`webv2 brief --deep` (or `webv2 audit`) for the full "+
				"integrity check — artifact re-hashes, exec hashes, "+
				"snapshot trees")),
			kv("problems", validation.VArr(chainProblems...))))
	}

	// divergence gate state
	plan, planErr := planner.LoadPlanReadonly(campaign)
	if planErr != nil {
		setKey(&brief, "divergence", validation.VNull())
	} else {
		div, err := planner.DivergenceStatusFor(campaign, plan, nil)
		if err != nil {
			return validation.VNull(), err
		}
		setKey(&brief, "divergence", div)
	}

	// the mechanical candidate surface (A4)
	summary, err := probes.SurfaceSummary(campaign, nil)
	if err != nil || summary == nil {
		setKey(&brief, "probe_surface", validation.VNull())
	} else {
		setKey(&brief, "probe_surface", *summary)
	}

	// G9 opaque surfaces (Task 6): the model's tracked-but-opaque
	// component surfaces, one display line per component. Presence-gated
	// (the additive convention): a campaign whose model carries no
	// components gains no key at all.
	if surfaces := TrackedSurfaces(campaign); len(surfaces) > 0 {
		setKey(&brief, "tracked_surfaces", validation.StrArr(surfaces))
	}

	// G10 assumption table (Task 4): the model's per-hop declared table
	// plus ASSUMPTION GAP lines, one display line per row/gap. Presence-
	// gated (the additive convention): a chains-only legacy campaign
	// gains no key at all.
	if lines := ChainAssumptions(campaign); len(lines) > 0 {
		setKey(&brief, "chain_assumption_lines", validation.StrArr(lines))
	}

	// B4 disposition review: high-risk rows (tier 0 / gap >= 3) dismissed
	// with dismissal vocabulary — the closures the operator should re-check.
	// Presence-gated (the additive convention): the key exists only when
	// something is flagged, so a clean campaign's brief bytes are unchanged
	// (the print layer also gates on non-empty).
	if flags, derr := planner.DispositionReview(campaign, plan); derr == nil &&
		len(flags) > 0 {
		rev := validation.VArr()
		for _, f := range flags {
			phrases := validation.VArr()
			for _, ph := range f.Phrases {
				phrases.A = append(phrases.A, validation.VStr(ph))
			}
			rev.A = append(rev.A, validation.VObj(
				kv("priority", validation.VStr(f.Priority)),
				kv("row_id", validation.VStr(f.RowID)),
				kv("tier", validation.VInt(f.Tier)),
				kv("assertion_gap", validation.VInt(f.Gap)),
				kv("reason", validation.VStr(f.Reason)),
				kv("phrases", phrases)))
		}
		setKey(&brief, "disposition_review", rev)
	}

	// criticality coverage (task 8)
	//
	// r45a: criticalityBlock answers "the section is omitted, as when the
	// model is absent" for a model or structural index that EXISTS but could
	// not be read. It now hands that failure back as an `unreadable`
	// disclosure instead of (model) silently dropping the section or (index)
	// ranking criticality against a fabricated empty index; the message goes
	// into the problems block, and the section itself stays unset.
	crit, critOK, critErr := criticalityBlock(campaign, all, plan, planErr)
	if critErr != nil {
		return validation.VNull(), critErr
	}
	if msg := validation.ObjStr(crit, "unreadable"); msg != "" {
		problems = noteProblem(problems, msg)
		// The problems key was captured when `brief` was built, above; this
		// disclosure is discovered after that, so the block is re-set (key
		// position kept — the key already exists) rather than lost.
		setKey(&brief, "problems", validation.StrArr(problems))
	}
	if critOK {
		setKey(&brief, "criticality", crit)
	}

	att, err := AttentionLedger(campaign, generatedAt, &campaign.CampaignID,
		pyTruthyInt64Only(validation.ObjAt(campaignBlock, "closed")))
	if err != nil {
		return validation.VNull(), err
	}
	setKey(&brief, "attention", att)

	actions, err := NextActions(brief, campaign)
	if err != nil {
		return validation.VNull(), err
	}
	setKey(&brief, "next_actions", validation.StrArr(actions))
	return brief, nil
}

// criticalityBlock is build_brief's criticality section. ok=false means the
// section is omitted (Python's `except Exception: pass`).
//
// r45a: ok=false is the genuine-absence answer only. A protocol_model.json or
// structural_index.json that EXISTS but could not be read (chmod 000, EISDIR,
// ENOTDIR, a torn document) is a read failure: the old body folded it into
// "no model" (section silently gone) or into a fabricated EMPTY index, which
// ranked every component as uncovered from structure it never read. Both now
// return the `unreadable` disclosure, which BuildBrief names in the problems
// block; no ranking is computed from unread input.
func criticalityBlock(campaign *state.Campaign, all []validation.Value,
	plan validation.Value, planErr error) (validation.Value, bool, error) {
	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	if _, err := os.Stat(modelPath); err != nil {
		if os.IsNotExist(err) {
			return validation.VNull(), false, nil
		}
		return unreadableSection("protocol_model.json", err), false, nil
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return unreadableSection("protocol_model.json", err), false, nil
	}
	indexPath := filepath.Join(campaign.ArtifactsDir, "structural_index.json")
	var index validation.Value
	foundIndex := false
	if _, err := os.Stat(indexPath); err != nil {
		if !os.IsNotExist(err) {
			return unreadableSection("structural_index.json", err), false, nil
		}
		// genuinely absent: the empty default below is the documented shape
		// for a campaign that never wrote an index.
	} else {
		doc, rerr := validation.ReadJson(indexPath)
		if rerr != nil {
			return unreadableSection("structural_index.json", rerr), false, nil
		}
		index, foundIndex = doc, true
	}
	if !foundIndex {
		index = validation.VObj(kv("nodes", validation.VArr()),
			kv("edges", validation.VArr()))
	}
	ranked := structidx.CriticalityRank(model, index)
	compBlobs := []string{}
	if planErr == nil && plan.Kind == validation.Obj {
		for _, p := range listAt(plan, "priorities") {
			if p.Kind != validation.Obj {
				continue
			}
			for _, c := range listAt(p, "components") {
				if c.Kind == validation.Str {
					compBlobs = append(compBlobs, c.S)
				} else {
					compBlobs = append(compBlobs, validation.PyRepr(c))
				}
			}
		}
	}
	findingBlobs := []string{}
	for _, f := range all {
		for _, a := range listAt(f, "affected") {
			if a.Kind != validation.Obj {
				continue
			}
			findingBlobs = append(findingBlobs, validation.ObjStr(a, "contract"))
			findingBlobs = append(findingBlobs, validation.ObjStr(a, "path"))
		}
	}
	execBlobs := []string{}
	// r44a: this used to be `if recs, err := ...; err == nil`, which swallowed
	// the whole error class. AllExecs folds a genuinely ABSENT execs/ store
	// into an empty list with a nil error, so the tolerant shape already
	// covers absence — and a non-nil error can only mean the store could not
	// be listed. Swallowing THAT would drop every exec blob and let the
	// coverage pass below assert components "uncovered" from evidence it
	// never read: a read error is a refusal, not "not found", so it
	// propagates (the caller renders it).
	recs, err := sandbox.AllExecs(campaign)
	if err != nil {
		return validation.VNull(), false, err
	}
	{
		for _, rec := range recs {
			if rec.Kind != validation.Obj {
				continue
			}
			for _, key := range []string{"command", "workdir", "finding_id",
				"artifact_id"} {
				v := validation.ObjAt(rec, key)
				if v.Kind == validation.Str {
					execBlobs = append(execBlobs, v.S)
				} else {
					execBlobs = append(execBlobs, "")
				}
			}
		}
	}
	coverage := []validation.KV{}
	uncovered := []validation.Value{}
	seen := map[string]bool{}
	for _, r := range ranked {
		name := validation.ObjStr(r, "contract")
		if !seen[name] {
			seen[name] = true
			covered := false
			pool := append(append(append([]string{}, compBlobs...),
				findingBlobs...), execBlobs...)
			for _, b := range pool {
				if hitName(name, b) {
					covered = true
					break
				}
			}
			coverage = append(coverage, validation.KV{K: name,
				V: validation.VBool(covered)})
			if validation.ObjStr(r, "tier") == "consensus-critical" && !covered {
				uncovered = append(uncovered, validation.VStr(name))
			}
		}
	}
	return validation.VObj(
		kv("ranking", validation.VArr(ranked...)),
		kv("coverage", validation.VObj(coverage...)),
		kv("uncovered_consensus_critical",
			validation.VArr(uncovered...))), true, nil
}

func hitName(name, blob string) bool {
	if name == "" {
		return false
	}
	re, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(name) + `\b`)
	if err != nil {
		return false
	}
	idx := re.FindStringIndex(blob)
	if idx == nil {
		return false
	}
	_ = idx
	return true
}

// ---- next actions ----------------------------------------------------------

func integrityDetail(integ validation.Value) string {
	probs := validation.ObjAt(integ, "problems")
	if probs.Kind == validation.Obj {
		parts := []string{}
		for _, kvp := range probs.O {
			parts = append(parts, kvp.K+": "+validation.PyRepr(kvp.V))
		}
		out := ""
		for i, s := range parts {
			if i > 0 {
				out += "; "
			}
			out += s
		}
		return out
	}
	parts := []string{}
	for _, p := range probs.A {
		if p.Kind == validation.Str {
			parts = append(parts, p.S)
		} else {
			parts = append(parts, validation.PyRepr(p))
		}
	}
	out := ""
	for i, s := range parts {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

// webv2Action renders one copyable next action: the command first, the
// reason as a shell comment. Task 7's law is render-boundary-wide (review
// round 1, I-2): every line briefing.go mints must be pasteable, so prose
// rides the `# reason` suffix instead of leading the line.
func webv2Action(command, reason string) string {
	if reason == "" {
		return command
	}
	return command + "  # " + noParens(reason)
}

// noParens keeps interpolated prose inside a `# reason` comment from
// tripping the no-parenthesis law — the plan's own test regex is `\(` and
// it reads the whole line; brackets carry the same meaning to an operator.
func noParens(s string) string {
	return strings.NewReplacer("(", "[", ")", "]").Replace(s)
}

// boxLocalCap is the box's E-cap for the reachability line: E4 — the local
// execution ceiling the environment records. envgo's profileMaxLevel gives
// every isolated container profile E4 and the doctor's e4_capable list names
// exactly those profiles; E5+ is a fork run, which is what the line's "fork
// required" clause names. Read, not probed: `docker info` inside a pure view
// would turn the cockpit host-dependent and hang it for up to the probe's
// 20s timeout on a wedged daemon — `webv2 env doctor` is the probe.
//
// ponytail: constant, not a live probe; wire envgo's e4_capable in when the
// brief gains a cached environment block (the value only moves on a box that
// cannot run containers at all, which `env doctor` already reports).
const boxLocalCap = "E4"

// openFindingClasses is the set of bug classes the campaign's open findings
// carry: the classes a CONFIRMED move could still target. findings.IsTerminal
// is the shared dead-row predicate, so a disproved or superseded row is not
// open work. The read is not fail-soft — the brief already fails on the same
// store (Reachability).
func openFindingClasses(campaign *state.Campaign) ([]string, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	classes := []string{}
	for _, f := range all {
		if findings.IsTerminal(validation.ObjStr(f, "status")) {
			continue
		}
		cls := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class")
		if cls == "" || seen[cls] {
			continue
		}
		seen[cls] = true
		classes = append(classes, cls)
	}
	return classes, nil
}

// ReachabilityLine renders the evidence-reachability advisory: which of the
// campaign's open bug classes can reach CONFIRMED on this box (floor at or
// below cap) and which need a fork. Reachable classes lead, fork-required
// classes follow, each group alphabetized, one class per clause with its own
// floor. An empty class list renders nothing. Pure prose, advisory only: no
// gate, proof or phase transition reads it.
func ReachabilityLine(classes []string, cap string) string {
	reachable, forked := []string{}, []string{}
	for _, c := range classes {
		if findings.ReachableLocally(c, cap) {
			reachable = append(reachable, c)
		} else {
			forked = append(forked, c)
		}
	}
	sort.Strings(reachable)
	sort.Strings(forked)
	clauses := make([]string, 0, len(classes))
	for _, c := range reachable {
		clauses = append(clauses, "CONFIRMED locally reachable for "+c+
			" (floor "+findings.ClassConfirmFloor(c)+")")
	}
	for _, c := range forked {
		clauses = append(clauses, "fork required for "+c+
			" (floor "+findings.ClassConfirmFloor(c)+" > "+cap+")")
	}
	if len(clauses) == 0 {
		return ""
	}
	return "evidence reachability: " + strings.Join(clauses, "; ")
}

// NextActions is _next_actions: the prioritized, concrete work list.
// nextActionsCtx carries the shared context of the NextActions split: the
// brief being rendered, the campaign, the two brief sub-objects the sections
// read, the resolved campaign id used by the open-branch mints, and the
// action list being accumulated plus the two identity sets the attention
// sections populate and the generic filter consumes.
type nextActionsCtx struct {
	brief    validation.Value
	campaign *state.Campaign
	cb       validation.Value
	integ    validation.Value
	cid      string
	actions  []string
	// the attention ledger leads the queue
	attentionLead map[string]bool
	// the attention-minted lines themselves: the generic filter must not
	// count them as "something else to do" (they carry no `# reason` — the
	// ledger block already renders the prose beside the command)
	attentionLines map[string]bool
}

// NextActions is webv2.briefing next_actions: the concrete prioritized
// command list. Each section below is one cohesive block of the original
// body, in the original order.
func NextActions(brief validation.Value, campaign *state.Campaign) ([]string, error) {
	nx := &nextActionsCtx{
		brief:          brief,
		campaign:       campaign,
		cb:             validation.AsObj(validation.ObjAt(brief, "campaign")),
		integ:          validation.AsObj(validation.ObjAt(brief, "integrity")),
		actions:        []string{},
		attentionLead:  map[string]bool{},
		attentionLines: map[string]bool{},
	}
	closed, err := nx.nextActionsClosed()
	if err != nil {
		return nil, err
	}
	if closed {
		return nx.actions, nil
	}

	// cid for every open-branch mint: the campaign pointer may be nil
	// (hand-built briefs), the brief's own campaign_id is the fallback.
	nx.cid = lensActionCampaign(brief, campaign)

	nx.nextActionsColdProbe()
	if err := nx.nextActionsReachability(); err != nil {
		return nil, err
	}
	nx.nextActionsProbeRows()
	nx.nextActionsLensRouting()
	nx.nextActionsSkew()
	nx.nextActionsCriticality()
	nx.nextActionsPlanPriorities()
	nx.nextActionsAttention()
	nx.nextActionsDivergenceGate()
	nx.nextActionsInvariantDebt()
	nx.nextActionsIntegrity()
	nx.nextActionsCostCeiling()
	nx.nextActionsChains()
	nx.nextActionsE6Queue()
	nx.nextActionsMemoryRecall()
	nx.nextActionsCorpusRecall()
	nx.nextActionsUnreachable()
	nx.nextActionsBountyGate()
	nx.nextActionsGateDeficits()
	nx.nextActionsPendingMemory()
	nx.nextActionsTerminals()
	if err := nx.nextActionsGenericFallback(); err != nil {
		return nil, err
	}
	nx.nextActionsLensYield()
	return nx.actions, nil
}

// nextActionsClosed renders the closed-pass branch: the integrity-first
// doctor line, the completion summary and the open completion proofs. It
// reports whether the pass was closed — the action list is then final.
func (n *nextActionsCtx) nextActionsClosed() (bool, error) {
	if objBool(n.cb, "closed") {
		cid := n.campaign.CampaignID
		if validation.ObjAt(n.integ, "ok").Kind == validation.Bool && !validation.ObjAt(n.integ, "ok").B {
			n.actions = append(n.actions, webv2Action("webv2 doctor "+cid,
				"FIX INTEGRITY FIRST — trust issue, fix even though the "+
					"pass is closed: "+integrityDetail(n.integ)))
		}
		st, err := n.campaign.State()
		if err != nil {
			return false, err
		}
		who := validation.ObjStr(st, "completed_by")
		if who == "" {
			who = "operator"
		}
		why := validation.ObjStr(st, "completed_reason")
		if why == "" {
			why = "no reason recorded"
		}
		n.actions = append(n.actions, webv2Action("webv2 status "+cid,
			fmt.Sprintf("pass marked COMPLETE by %s — %s; the pass is "+
				"closed by decision — resume by running a stage command, "+
				"e.g. webv2 run", who, why)))
		proofs, err := completion.AllProofStatus(n.campaign)
		if err != nil {
			return false, err
		}
		openProofs := []string{}
		for _, pr := range proofs.O {
			if pr.V.Kind != validation.Obj {
				continue
			}
			if !objBool(pr.V, "authoritative") || objBool(pr.V, "done") {
				continue
			}
			openProofs = append(openProofs, pr.K)
		}
		limit := len(openProofs)
		if limit > 6 {
			limit = 6
		}
		for _, stage := range openProofs[:limit] {
			// the per-proof missing-item prose the old line inlined is
			// exactly what `prove --stage` prints (Task 7's trade-off)
			n.actions = append(n.actions, webv2Action(
				"webv2 prove "+cid+" --stage "+stage,
				"open completion proof — noted, NOT blocking"))
		}
		return true, nil
	}
	return false, nil
}

// nextActionsColdProbe appends the Task 11 cold-probe-surface line.
func (n *nextActionsCtx) nextActionsColdProbe() {
	// Task 11: the cold probe surface. DISCOVERY is the phase whose whole
	// point is a mechanical pass over the probe surface, and every later
	// gate reads what that pass emitted — a campaign running DISCOVERY with
	// no `probes run --emit` on record is working an unprobed surface. The
	// line is standing and advisory: it names the exact command and clears
	// the moment the emit is on record. It gates nothing.
	if n.campaign != nil && validation.ObjStr(n.cb, "phase") == "DISCOVERY" {
		if emitted, err := probes.Emitted(n.campaign); err == nil && !emitted {
			n.actions = append(n.actions, webv2Action(
				"webv2 probes "+n.cid+" run --emit",
				"cold probe surface — DISCOVERY is running with no probe "+
					"emit on record, so the mechanical surface is unprobed"))
		}
	}
}

// nextActionsReachability appends the Task 3 evidence-reachability line.
func (n *nextActionsCtx) nextActionsReachability() error {
	// Task 3 (defect 5): evidence reachability. G-01's accepted classes floor
	// at E4 (dos-griefing, logic-error) and this box reaches E4 locally — the
	// cockpit never said so, so CONFIRMED read as out of reach when it was
	// not. Rendered immediately after the cold-probe warning; advisory only
	// (no gate, proof or phase transition reads it) and silent when no open
	// finding carries a class.
	if n.campaign != nil {
		classes, err := openFindingClasses(n.campaign)
		if err != nil {
			return err
		}
		if line := ReachabilityLine(classes, boxLocalCap); line != "" {
			n.actions = append(n.actions, line)
		}
	}
	return nil
}

// nextActionsProbeRows renders the probe-surface section: the ranked open
// rows lead, promoted rows mint an `answered` obligation, the rest mint an
// emit.
func (n *nextActionsCtx) nextActionsProbeRows() {
	// probe surface: the ranked open rows lead
	if ps := validation.ObjAt(n.brief, "probe_surface"); ps.Kind == validation.Obj {
		rows := listAt(ps, "open_rows")
		sorted := append([]validation.Value{}, rows...)
		sort.SliceStable(sorted, func(i, j int) bool {
			return probes.RankKeyOf(sorted[i]).Less(probes.RankKeyOf(sorted[j]))
		})
		for _, r := range sorted {
			rid := validation.ObjStr(r, "row_id")
			where := orQuestion(validation.ObjStr(r, "lens")) + " " +
				orQuestion(validation.ObjStr(r, "axis"))
			name := validation.ObjStr(r, "name")
			if name == "" {
				name = validation.ObjStr(r, "probe")
			}
			if validation.ObjAt(r, "priority_id").Kind == validation.Str &&
				validation.ObjAt(r, "priority_id").S != "" {
				why := strings.Join(strings.Fields(validation.ObjStr(r, "why")), " ")
				if len([]rune(why)) > 80 {
					why = string([]rune(why)[:77]) + "…"
				}
				// a promoted row IS a plan priority: the attention queue
				// works its oldest untouched question with the same verb
				n.actions = append(n.actions, webv2Action("webv2 answered "+n.cid+
					" "+validation.ObjStr(r, "priority_id")+
					" answered --reason <reason> --actor <actor>",
					fmt.Sprintf("work probe row %s — %s: %s — %s",
						rid, where, name, why)))
			} else {
				n.actions = append(n.actions, webv2Action(
					"webv2 probes "+n.cid+" run --emit",
					fmt.Sprintf("emit probe row %s — %s: %s — emitting it "+
						"turns it into a plan obligation", rid, where, name)))
			}
		}
	}
}

// nextActionsLensRouting renders the M6 per-lens routing lines.
func (n *nextActionsCtx) nextActionsLensRouting() {
	// M6 (framework eval): an untouched lens names its mechanical table.
	// The G-01 miss showed the failure mode — the brief nagged "questions
	// worked 0/48" but never said L-03 was the unworked street nor that
	// `enforce prevStateRoot` walks it. Per-lens probe closure already
	// rides the brief's divergence block, so a lens with open rows and
	// zero dispositions gets one routing line to the table that reads the
	// structural index directly (no surface needed). L-02 has no table
	// verb — its trust rows are already listed per-row above.
	if div := validation.ObjAt(n.brief, "divergence"); div.Kind == validation.Obj {
		for _, l := range listAt(div, "lenses") {
			lid := validation.ObjStr(l, "id")
			table, ok := lensMechanicalTable[lid]
			if !ok || lensDispositioned(validation.ObjStr(l, "status")) {
				continue
			}
			probe := validation.ObjAt(l, "probe")
			if probe.Kind != validation.Obj {
				// A surface exists but carries none of this lens's
				// axes — the reduced-quota shape. The --emit refresh is
				// already named by the divergence missing entries;
				// route to the table instead.
				if ps := validation.ObjAt(n.brief, "probe_surface"); ps.Kind == validation.Obj {
					n.actions = append(n.actions, webv2Action(
						fmt.Sprintf(table, n.cid),
						lid+" has no probe surface for its axes — "+
							"work it directly off the index"))
				}
				continue
			}
			if objBool(probe, "closed") {
				continue
			}
			disp := intField(probe, "dispositioned")
			open := intField(probe, "open")
			if disp != 0 || open == 0 {
				continue
			}
			n.actions = append(n.actions, webv2Action(fmt.Sprintf(table, n.cid),
				fmt.Sprintf("%s open with 0/%d rows dispositioned, %d "+
					"open — run the mechanical table before theorizing",
					lid, intField(probe, "rows"), open)))
		}
	}
}

// nextActionsSkew appends the DEFECT-2 framework-skew line.
func (n *nextActionsCtx) nextActionsSkew() {
	// DEFECT-2 follow-up: framework skew. The snapshot's pin event records
	// the build that produced it; a different running build may carry
	// different probe semantics (the eval's stale-binary case: the defect
	// was fixed in checkout while the binary still crashed). Both sides
	// known and different is the only loud case — old campaigns without
	// the key and unstamped builds stay silent (the grandfather rule).
	if n.campaign != nil {
		if line := skewAction(n.brief, n.campaign); line != "" {
			n.actions = append(n.actions, line)
		}
	}
}

// nextActionsCriticality renders the criticality-coverage section.
func (n *nextActionsCtx) nextActionsCriticality() {
	// criticality coverage
	if crit := validation.ObjAt(n.brief, "criticality"); crit.Kind == validation.Obj {
		for _, name := range listAt(crit, "uncovered_consensus_critical") {
			n.actions = append(n.actions, webv2Action("webv2 run "+n.cid,
				fmt.Sprintf("open %s — consensus-critical, untouched by "+
					"any priority/finding/exec", valueText(name))))
		}
	}
}

// nextActionsPlanPriorities renders the plan-priority section: the Task 10
// open-question rows and the open SIBLING priorities, off one readonly load.
func (n *nextActionsCtx) nextActionsPlanPriorities() {
	// The plan's own priorities carry two open-work families that must reach
	// the cockpit: the open-question rows Task 10 mints, and open SIBLING
	// priorities (the disproof-sibling rule: a DISPROVED lifecycle finding
	// names its adjacent unchecked property, which spawns an OPEN priority
	// carrying sibling_of — the neighborhood stays open until the sibling is
	// worked). One readonly load serves both. Guarded like the criticality
	// block: plan-less/model-less campaigns get zero new lines.
	if n.campaign != nil {
		if plan, err := planner.LoadPlanReadonly(n.campaign); err == nil {
			// Task 10's Law ends "brief shows it" (independent Phase C
			// review, docs/sdd/task-10-12-review.md, Task 10 finding 1):
			// the minted `resolve open question Q-…: <text>` row was visible
			// only through `webv2 plan --json` and the queue-debt counts, so
			// the question's own text never reached the brief. It now renders
			// its own line — the id and the text, command-first per the
			// Task 7 law, pointing at the plan JSON that shows the row and
			// its rank. `status` is the clear condition: answering the
			// priority closes it, and the line goes with it.
			for _, p := range listAt(plan, "priorities") {
				text := validation.ObjStr(p, "question")
				if validation.ObjStr(p, "status") != "open" ||
					!strings.HasPrefix(text, "resolve open question ") {
					continue
				}
				if id := validation.ObjStr(p, "id"); id != "" &&
					!strings.Contains(text, id) {
					text = "resolve open question " + id + ": " + text
				}
				n.actions = append(n.actions, webv2Action(
					"webv2 plan "+n.cid+" --json", text))
			}
			for _, p := range listAt(plan, "priorities") {
				if validation.ObjStr(p, "status") == "open" &&
					validation.ObjStr(p, "sibling_of") != "" {
					pid := validation.ObjStr(p, "id")
					cmd := "webv2 run " + n.cid
					if pid != "" {
						cmd = "webv2 answered " + n.cid + " " + pid +
							" answered --reason <reason> --actor <actor>"
					}
					n.actions = append(n.actions, webv2Action(cmd, fmt.Sprintf(
						"work sibling of %s: %s", validation.ObjStr(p, "sibling_of"),
						validation.ObjStr(p, "question"))))
				}
			}
		}
	}
}

// nextActionsAttention renders the attention-ledger section: the top-ranked
// commands lead, then remaining queue rows not already led.
func (n *nextActionsCtx) nextActionsAttention() {
	if att := validation.ObjAt(n.brief, "attention"); att.Kind == validation.Obj {
		ranked := listAt(att, "ranked")
		lead := ranked
		if len(lead) > 2 {
			lead = lead[:2]
		}
		for _, item := range lead {
			if cmd := validation.ObjStr(item, "command"); cmd != "" {
				n.actions = append(n.actions, cmd)
				n.attentionLines[cmd] = true
			}
			ident := validation.ObjStr(item, "priority_id")
			if ident == "" {
				ident = validation.ObjStr(item, "invariant_id")
			}
			n.attentionLead[ident] = true
		}
		for _, item := range ranked[minInt(2, len(ranked)):] {
			if validation.ObjStr(item, "kind") == "queue" &&
				validation.ObjStr(item, "command") != "" &&
				!n.attentionLead[validation.ObjStr(item, "priority_id")] {
				cmd := validation.ObjStr(item, "command")
				n.actions = append(n.actions, cmd)
				n.attentionLines[cmd] = true
			}
		}
	}
}

// nextActionsDivergenceGate renders the divergence-gate section.
func (n *nextActionsCtx) nextActionsDivergenceGate() {
	// the divergence gate
	if div := validation.ObjAt(n.brief, "divergence"); div.Kind == validation.Obj &&
		!objBool(div, "closed") {
		missing := listAt(div, "missing")
		if len(missing) > 3 {
			missing = missing[:3]
		}
		for _, m := range missing {
			what := []rune(validation.ObjStr(m, "what"))
			if len(what) > 80 {
				what = what[:80]
			}
			n.actions = append(n.actions, webv2Action(
				"webv2 probes "+n.cid+" run --emit",
				fmt.Sprintf("divergence gate open — %s: %s",
					validation.ObjStr(m, "subject"), string(what))))
		}
	}
}

// nextActionsInvariantDebt renders the remaining high-consequence
// invariant-debt section.
func (n *nextActionsCtx) nextActionsInvariantDebt() {
	// remaining high-consequence invariant debt
	if att := validation.ObjAt(n.brief, "attention"); att.Kind == validation.Obj {
		items := listAt(validation.AsObj(validation.ObjAt(att, "invariants")), "items")
		for _, item := range items {
			if objBool(item, "high_consequence") &&
				validation.ObjStr(item, "command") != "" &&
				!n.attentionLead[validation.ObjStr(item, "invariant_id")] {
				cmd := validation.ObjStr(item, "command")
				n.actions = append(n.actions, cmd)
				n.attentionLines[cmd] = true
			}
		}
	}
}

// nextActionsIntegrity appends the doctor line for unchecked-deep integrity.
func (n *nextActionsCtx) nextActionsIntegrity() {
	// integrity, if not checked deep
	if validation.ObjAt(n.integ, "ok").Kind == validation.Bool && !validation.ObjAt(n.integ, "ok").B {
		n.actions = append(n.actions, webv2Action("webv2 doctor "+n.cid,
			"FIX INTEGRITY FIRST: "+integrityDetail(n.integ)))
	}
}

// nextActionsCostCeiling renders the cost-ceiling section.
func (n *nextActionsCtx) nextActionsCostCeiling() {
	// cost ceiling
	if econ := validation.ObjAt(n.brief, "economics"); econ.Kind == validation.Obj {
		b := validation.AsObj(validation.ObjAt(econ, "budget"))
		spent := validation.ObjAt(b, "spent_usd")
		limit := validation.ObjAt(b, "max_total_cost_usd")
		if spent.Kind != validation.Null && limit.Kind != validation.Null &&
			floatOf(spent) > floatOf(limit) {
			n.actions = append(n.actions, webv2Action(
				"webv2 budget "+n.cid+" --set <max-usd> --actor <actor>",
				fmt.Sprintf("cost ceiling exceeded: $%s spent vs $%s "+
					"limit — raise max_total_cost_usd or stop; the "+
					"pipeline will not run past the ceiling",
					pyCommaFloat(floatOf(spent), 2),
					pyCommaFloat(floatOf(limit), 2))))
		}
	}
}

// nextActionsChains renders the materializable-chains section.
func (n *nextActionsCtx) nextActionsChains() {
	// chains ready to materialize
	for _, ch := range listAt(validation.ObjAt(n.brief, "findings"), "materializable_chains") {
		members := strListOf(validation.ObjAt(ch, "members"))
		cmd := "webv2 run " + n.cid
		if len(members) >= 2 {
			cmd = "webv2 chain " + n.cid + " " + strings.Join(members, " ")
		}
		n.actions = append(n.actions, webv2Action(cmd,
			"materialize chain — all members confirmed, not yet a chain"))
	}
}

// nextActionsE6Queue renders the independent-verification (E6) queue.
func (n *nextActionsCtx) nextActionsE6Queue() {
	// the E6 queue
	for _, q := range listAt(n.brief, "independent_verification_queue") {
		need := "E6"
		if v := validation.ObjAt(q, "effective_floor"); v.Kind == validation.Str {
			need = v.S
		} else if v.Kind == validation.Null {
			need = "None"
		}
		tag := "defence in depth"
		if objBool(q, "mandatory") {
			tag = "MANDATORY, effective floor " + need
		}
		fid := validation.ObjStr(q, "finding_id")
		n.actions = append(n.actions, webv2Action("webv2 verify "+n.cid+
			" --finding "+fid+" --exec <EXEC-id> --verifier <verifier>"+
			" --description <description>",
			fmt.Sprintf("independently verify %s at %s, needs %s — %s",
				fid, validation.ObjStr(q, "evidence_level"), need, tag)))
	}
}

// nextActionsMemoryRecall renders the pending memory-recall section.
func (n *nextActionsCtx) nextActionsMemoryRecall() {
	// memory recall
	for _, fid := range listAt(validation.ObjAt(n.brief, "findings"), "memory_recall_pending") {
		n.actions = append(n.actions, webv2Action("webv2 recall "+n.cid+
			" --finding "+valueText(fid),
			"memory recall pending — critic + repro already in place"))
	}
}

// nextActionsCorpusRecall renders the B3/D2 corpus-recall disclosure.
func (n *nextActionsCtx) nextActionsCorpusRecall() {
	// corpus recall (B3/D2): a recorded check that cites no structurally-
	// overlapping row still closes the gate clause, so the operator is told.
	cr := validation.ObjAt(n.brief, "corpus_recall")
	if cr.Kind == validation.Obj && objInt(cr, "irrelevant_checks") != 0 {
		irrelevant := objInt(cr, "irrelevant_checks")
		fids := strListOf(validation.ObjAt(cr, "findings"))
		first := "?"
		if len(fids) > 0 {
			first = fids[0]
		}
		more := ""
		if len(fids) > 1 {
			more = fmt.Sprintf(" — %d more findings", len(fids)-1)
		}
		detail := ""
		labelOnly := objInt(cr, "label_only_checks")
		if labelOnly != 0 {
			labels := strings.Join(aliasSuffixLabels(
				strListOf(validation.ObjAt(cr, "discounted"))), ", ")
			if labels == "" {
				labels = "-"
			}
			verb := "share"
			if labelOnly == 1 {
				verb = "shares"
			}
			detail = fmt.Sprintf(" — %d %s only a non-discriminative class "+
				"label %s: the corpus has rows in that class, the label "+
				"alone is not lineage overlap", labelOnly, verb, labels)
		}
		noun, verb := "checks", "cite"
		if irrelevant == 1 {
			noun, verb = "check", "cites"
		}
		n.actions = append(n.actions, webv2Action("webv2 recall "+n.cid+
			" --finding "+first,
			fmt.Sprintf("corpus: %d memory %s %s no overlapping row%s%s",
				irrelevant, noun, verb, detail, more)))
	}
}

// nextActionsUnreachable renders the structurally-unreachable section.
func (n *nextActionsCtx) nextActionsUnreachable() {
	// structurally unreachable findings
	for _, r := range listAt(validation.ObjAt(n.brief, "findings"), "structurally_unreachable") {
		floor := validation.ObjStr(r, "floor")
		floorArg := floor
		if floorArg == "" || floorArg == "None" {
			floorArg = "<E4-E7>"
		}
		n.actions = append(n.actions, webv2Action("webv2 floors "+n.cid+
			" set --actor <actor> --reason <reason> <class_> "+floorArg,
			fmt.Sprintf("%s is structurally stuck at %s, effective floor %s"+
				": %s — pin the target or record the decision",
				validation.ObjStr(r, "finding_id"), validation.ObjStr(r, "level"),
				orQuestion(floor),
				strings.Join(strListOf(validation.ObjAt(r, "missing")), "; "))))
	}
}

// nextActionsBountyGate renders the bounty-gate section.
func (n *nextActionsCtx) nextActionsBountyGate() {
	// bounty gate
	if bv := validation.ObjAt(n.brief, "bounty"); bv.Kind == validation.Obj {
		for _, x := range listAt(bv, "evaluated") {
			fid := validation.ObjStr(x, "finding_id")
			if objBool(x, "submission_ready") {
				// submission itself happens off-CLI; the report is the
				// command step that precedes it
				n.actions = append(n.actions, webv2Action("webv2 report "+n.cid,
					"submit "+fid+" — gate passed, submission ready"))
				continue
			}
			if objBool(x, "eligible") {
				n.actions = append(n.actions, webv2Action("webv2 run "+n.cid,
					fmt.Sprintf("finish %s for submission: %s", fid,
						strings.Join(strListOf(validation.ObjAt(x, "blocking_reasons")),
							"; "))))
			}
		}
	}
}

// nextActionsGateDeficits renders the gate-deficits section.
func (n *nextActionsCtx) nextActionsGateDeficits() {
	// gate deficits
	for _, d := range listAt(validation.ObjAt(n.brief, "findings"), "gate_deficits") {
		n.actions = append(n.actions, webv2Action("webv2 run "+n.cid, fmt.Sprintf(
			"advance %s — %s, %s: %s", validation.ObjStr(d, "finding_id"),
			validation.ObjStr(d, "status"), validation.ObjStr(d, "level"), validation.ObjStr(d, "deficit"))))
	}
}

// nextActionsPendingMemory renders the pending-memory-promotion section.
func (n *nextActionsCtx) nextActionsPendingMemory() {
	// pending memory promotion
	for _, m := range listAt(n.brief, "pending_memory") {
		n.actions = append(n.actions, webv2Action("webv2 memory "+n.cid+
			" --approve "+validation.ObjStr(m, "memory_id"),
			fmt.Sprintf("human decision on %s — %s/%s: approve or reject",
				validation.ObjStr(m, "memory_id"), validation.ObjStr(m, "kind"),
				validation.ObjStr(m, "status"))))
	}
}

// nextActionsTerminals renders the terminal-states section.
func (n *nextActionsCtx) nextActionsTerminals() {
	// terminal states
	for _, t := range listAt(n.brief, "terminals") {
		path := strListOf(validation.ObjAt(t, "path"))
		cmd := "webv2 terminals " + n.cid
		if len(path) > 0 {
			// the work command: demonstrate the terminal capability on the
			// last finding of the path
			cmd = "webv2 exploit " + n.cid + " " + path[len(path)-1] + " --paid"
		}
		n.actions = append(n.actions, webv2Action(cmd, fmt.Sprintf(
			"terminal state reachable: -> %s via %s — capital $%s",
			validation.ObjStr(t, "terminal_capability"), strings.Join(path, " -> "),
			pyCommaFloat(floatOf(validation.ObjAt(t, "capital_usd")), 0))))
	}
}

// nextActionsGenericFallback filters out the section-specific lines and, when
// nothing generic remains, falls back to the orchestrator's next actions.
func (n *nextActionsCtx) nextActionsGenericFallback() error {
	generic := []string{}
	for _, a := range n.actions {
		// M6 lens-routing lines ("L-03 open with ...", "L-04 has no probe
		// surface ...") are surface-derived mechanical work, same family
		// as the probe-row actions — they must not count as "something
		// else to do", or they would suppress the phase-guidance fallback
		// on exactly the untouched-surface campaigns they route. The
		// markers ride the `# reason` suffix now that every minted line
		// leads with its command (I-2); attention-ledger lines carry no
		// reason — they are excluded by identity.
		if n.attentionLines[a] {
			continue
		}
		reason := ""
		if i := strings.Index(a, "  # "); i >= 0 {
			reason = a[i+4:]
		}
		if !hasAnyPrefix(reason, "work probe row ", "emit probe row ",
			"L-01 ", "L-03 ", "L-04 ",
			"divergence gate open — ") {
			generic = append(generic, a)
		}
	}
	surfacePresent := validation.ObjAt(n.brief, "probe_surface").Kind != validation.Null
	if len(generic) == 0 &&
		(len(n.actions) == 0 || surfacePresent) {
		extra, err := orchestrator.NextActions(n.campaign)
		if err != nil {
			return err
		}
		for _, a := range extra.A {
			if a.Kind == validation.Str {
				n.actions = append(n.actions, a.S)
			}
		}
	}
	return nil
}

// nextActionsLensYield appends the G17 per-lens batting-average lines.
func (n *nextActionsCtx) nextActionsLensYield() {
	// G17 tactic batting average (advisory render, policy-gated OFF plus
	// presence-gated): one line per lens with verdict-resolved data. The
	// rows come from the brief's own economics.lens_yield block — the
	// same T22 join the queue gate consumes — so the gate, the table,
	// and this line can never disagree. Presence gate: a real lens
	// (never "unattributed") with n_planned>0 renders; anything thinner
	// has no average to report. Appended last: advisory lines never
	// suppress or reorder the standing actions. Renders only — gates
	// nothing.
	if bounty.AutoTuneForCampaign(n.campaign) {
		if econ := validation.ObjAt(n.brief, "economics"); econ.Kind == validation.Obj {
			for _, r := range listAt(econ, "lens_yield") {
				lens := validation.ObjStr(r, "lens")
				if lens == "" || lens == "unattributed" {
					continue
				}
				planned := objInt(r, "n_planned")
				confirmed := objInt(r, "n_confirmed")
				if planned <= 0 {
					continue
				}
				// the advisory stat rides the lens's mechanical-table
				// command where one exists — a weak average is worked by
				// walking the table, exactly like the M6 routing
				cmd := "webv2 run " + n.cid
				if table, ok := lensMechanicalTable[lens]; ok {
					cmd = fmt.Sprintf(table, n.cid)
				}
				n.actions = append(n.actions, webv2Action(cmd, "lens "+lens+
					" batting average — "+
					wilson.Format(int(confirmed), int(planned),
						"precision")))
			}
		}
	}
}

// lensMechanicalTable is the M6 map: lens id -> the mechanical table verb
// that reads the structural index directly, with one %s slot for the
// campaign id. L-02 (trust-assumption) has no table verb and stays out —
// its rows are worked per-row. L-01 routes to enforce because cursors,
// sentinels and accumulators are storage variables: the enforcement table
// shows where each is written, read and guarded, by stage.
var lensMechanicalTable = map[string]string{
	"L-01": "webv2 enforce %s <cursor-variable>",
	"L-03": "webv2 enforce %s <variable>",
	"L-04": "webv2 symmetry %s",
}

// lensDispositioned is the lens-status half of
// planner.ProbeRowDispositioned: a lens entry closes under the same
// terminal dispositions as a probe row.
func lensDispositioned(status string) bool {
	for _, d := range planner.ProbeRowDispositioned {
		if status == d {
			return true
		}
	}
	return false
}

// lensActionCampaign is the campaign id for mechanical-table commands: the
// live campaign when present, else the brief's own record, else the same
// placeholder the gate uses for an unknown campaign.
func lensActionCampaign(brief validation.Value, campaign *state.Campaign) string {
	if campaign != nil && campaign.CampaignID != "" {
		return campaign.CampaignID
	}
	if id := validation.ObjStr(validation.ObjAt(brief, "campaign"), "campaign_id"); id != "" {
		return id
	}
	return "<campaign>"
}

// skewAction is the DEFECT-2 line: the active snapshot's pin event records
// the framework build that produced it, and the running binary names its
// own via internal/version. Both known and different is the only loud
// case. A silent "" covers every honest unknown: old campaigns without the
// key, no active snapshot, no event log to read, and unstamped builds.
func skewAction(brief validation.Value, campaign *state.Campaign) string {
	if !version.Known() {
		return ""
	}
	running := version.Commit()
	sid := validation.ObjStr(validation.ObjAt(brief, "campaign"), "active_snapshot")
	if sid == "" {
		return ""
	}
	pinned := pinBuild(campaign, sid)
	if pinned == "" || pinned == running {
		return ""
	}
	return webv2Action("webv2 snap "+campaign.CampaignID+" <target>",
		fmt.Sprintf("framework skew: snapshot %s pinned with build %s "+
			"but running build %s — probe-surface semantics may differ; "+
			"re-pin or run the pinning build", sid, pinned, running))
}

// pinBuild is the framework_build the snapshot's pin event recorded, or ""
// when the campaign predates the key (or the log cannot be read).
func pinBuild(campaign *state.Campaign, sid string) string {
	events, err := campaign.Events()
	if err != nil {
		return ""
	}
	for _, e := range events {
		if validation.ObjStr(e, "type") != "snapshot.pinned" || validation.ObjStr(e, "ref") != sid {
			continue
		}
		if b := validation.ObjStr(validation.ObjAt(e, "data"), "framework_build"); b != "" {
			return b
		}
	}
	return ""
}

// aliasSuffixLabels maps aliasSuffixLabel over a label list (G12 display:
// the stored corpus_recall.discounted keys are never rewritten, only the
// rendered line gains the pinned OWASP id).
func aliasSuffixLabels(labels []string) []string {
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		out = append(out, aliasSuffixLabel(l))
	}
	return out
}

// aliasSuffixLabel renders one discounted class label for display: the bare
// machine key ("bug_class=reentrancy") plus its pinned OWASP id when the
// class carries an alias ("bug_class=reentrancy [OWASP SC05]"), bare
// otherwise (presence-gated, zero byte move for unmapped classes).
func aliasSuffixLabel(label string) string {
	if cls, ok := strings.CutPrefix(label, "bug_class="); ok {
		if sfx := classweights.ClassAliasSuffix(cls); sfx != "" {
			return label + " " + sfx
		}
	}
	return label
}
