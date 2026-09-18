package briefing

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/playbooks"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

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
