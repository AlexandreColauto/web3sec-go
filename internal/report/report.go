// Package report is webv2.report: the deterministic markdown report — a
// VIEW over the finding IR. The report is generated FROM the finding
// objects, never the reverse: edit findings, regenerate the report.
//
// I1: the ONE sanctioned mutation is generate() re-running the bounty gate
// (a stale submission_ready flag is a stale claim) and registering the
// report artifact + logging report.generated. Everything else reads.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"websec/internal/bounty"
	"websec/internal/completion"
	"websec/internal/coverage"
	"websec/internal/economics"
	"websec/internal/findings"
	"websec/internal/forkpoc"
	"websec/internal/immunize"
	"websec/internal/learning"
	"websec/internal/maximization"
	"websec/internal/planner"
	"websec/internal/pricing"
	"websec/internal/privileged"
	"websec/internal/probes"
	"websec/internal/relations"
	"websec/internal/state"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V
		}
	}
	return validation.VNull()
}

func hasKey(v validation.Value, key string) bool {
	for _, pair := range v.O {
		if pair.K == key {
			return true
		}
	}
	return false
}

func objStr(v validation.Value, key string) string {
	f := objAt(v, key)
	if f.Kind == validation.Str {
		return f.S
	}
	return ""
}

func listAt(v validation.Value, key string) []validation.Value {
	f := objAt(v, key)
	if f.Kind != validation.Arr {
		return nil
	}
	return f.A
}

func asObj(v validation.Value) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VObj()
	}
	return v
}

func pyTruthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

func pyStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
}

func strList(v validation.Value) []string {
	out := []string{}
	for _, e := range v.A {
		out = append(out, pyStr(e))
	}
	return out
}

// constraintNote is _constraint_note: one recorded privilege entry,
// annotated with the constraints it states. Reported, never inferred.
func constraintNote(c validation.Value) string {
	text := objStr(c, "capability")
	if text == "" {
		text = objStr(c, "mechanism")
	}
	if text == "" {
		text = "unspecified privilege"
	}
	notes := []string{}
	if objAt(c, "timelocked").Kind == validation.Bool &&
		objAt(c, "timelocked").B {
		notes = append(notes, "timelocked")
	}
	t := objAt(c, "multisig_threshold")
	if t.Kind == validation.Int {
		notes = append(notes, strconv.FormatInt(t.I, 10)+"-of-n multisig")
	}
	if objAt(c, "can_drain").Kind == validation.Bool &&
		objAt(c, "can_drain").B {
		notes = append(notes, "model claims can_drain")
	}
	if len(notes) > 0 {
		return text + " (" + strings.Join(notes, ", ") + ")"
	}
	return text
}

// count is _count: "{n} {singular}" with plain English pluralization.
func count(n int, singular string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %ss", n, singular)
}

// PrivilegedSection is privileged_section: the 3.1 privileged-actor track as
// a report section. MUST STAY READ-ONLY over campaign state.
func PrivilegedSection(campaign *state.Campaign) ([]string, error) {
	modelPtr := privileged.LoadProtocolModel(campaign)
	if modelPtr == nil || modelPtr.Kind != validation.Obj ||
		!pyTruthy(objAt(*modelPtr, "privileges")) {
		return nil, nil
	}
	if len(privileged.PrivilegedRoles(*modelPtr)) == 0 {
		return nil, nil
	}
	ex, err := privileged.PrivilegedExposure(campaign)
	if err != nil {
		return nil, err
	}
	L := []string{"## Privileged-actor exposure", "",
		"Separate attacker track: bounded privileged roles as explicit baselines;",
		"the unprivileged-EOA results above are unaffected by this section.", ""}
	for _, r := range listAt(ex, "roles") {
		head := fmt.Sprintf("- **%s** (`%s`) — band: `%s`", objStr(r, "role"),
			objStr(r, "role_label"), objStr(r, "exposure_band"))
		direct := listAt(r, "direct")
		chains := listAt(r, "terminal_chains")
		if len(direct) == 0 && len(chains) == 0 {
			L = append(L, head+"; no terminal paths recorded")
			continue
		}
		notes := []string{}
		for _, c := range listAt(r, "constraints") {
			notes = append(notes, constraintNote(c))
		}
		L = append(L, head+"; constraints: "+strings.Join(notes, ", "))
		if len(direct) > 0 {
			best := direct[0]
			L = append(L, fmt.Sprintf("  - direct: %s, best: %s -> %s",
				count(len(direct), "path"),
				strings.Join(strList(objAt(best, "path")), " -> "),
				objStr(best, "terminal_capability")))
		}
		if len(chains) > 0 {
			best := chains[0]
			L = append(L, fmt.Sprintf("  - chains: %s, best: %s -> %s",
				count(len(chains), "multi-step path"),
				strings.Join(strList(objAt(best, "path")), " -> "),
				objStr(best, "terminal_capability")))
		} else {
			L = append(L, "  - chains: 0 multi-step paths")
		}
	}
	L = append(L, "")
	return L, nil
}

// ProbeSurfaceSection is probe_surface_section: the mechanical candidate
// plane, rendered. Empty when the campaign never ran `webv2 probes`.
func ProbeSurfaceSection(campaign *state.Campaign) ([]string, error) {
	surfacePtr, err := probes.CampaignSurface(campaign)
	if err != nil {
		return nil, err
	}
	if surfacePtr == nil {
		return nil, nil
	}
	surface := *surfacePtr
	summaryPtr, err := probes.SurfaceSummary(campaign, nil)
	if err != nil {
		return nil, err
	}
	if summaryPtr == nil {
		return nil, nil
	}
	summary := *summaryPtr
	var planPtr *validation.Value
	if plan, err := planner.LoadPlanReadonly(campaign); err == nil {
		planPtr = &plan
	}
	disp := probes.RowDispositions(planPtr, surface)
	indexPtr, err := probes.CampaignIndex(campaign)
	if err != nil {
		return nil, err
	}
	var index validation.Value = validation.VNull()
	if indexPtr != nil {
		index = *indexPtr
	}
	blanks := probes.BlankEntries(campaign)
	L := []string{"## Mechanical candidate surface", ""}
	L = append(L, fmt.Sprintf("- ranked candidate rows: **%d** (%d "+
		"dispositioned, %d open)", intAt(summary, "rows"),
		intAt(summary, "dispositioned"), intAt(summary, "open")))
	staleNote := ""
	if pyTruthy(objAt(summary, "stale")) {
		staleNote = " — **STALE**: the structural index has moved since this " +
			"surface was built; re-run `webv2 probes " + campaign.CampaignID +
			" run` and re-disposition what moved"
	}
	L = append(L, fmt.Sprintf("- surface `index_sha`: `%s`%s",
		pyStr(objAt(surface, "index_sha")), staleNote))
	L = append(L, "")
	for _, row := range listAt(surface, "rows") {
		rid := objStr(row, "row_id")
		d := asObj(objAt(disp, rid))
		anchors := "—"
		if pairs := probes.RowAnchorPairs(row, &index); len(pairs) > 0 {
			anchors = strings.Join(pairs, ", ")
		}
		var state string
		switch {
		case pyTruthy(objAt(d, "dispositioned")):
			state = "**" + objStr(d, "status") + "**"
			if objStr(d, "reason") != "" {
				state += ": " + objStr(d, "reason")
			}
			a := asObj(objAt(d, "anchor"))
			if len(a.O) > 0 {
				state += fmt.Sprintf(" (anchor `%s` = %s)",
					objStr(a, "field"), pyStr(objAt(a, "ref")))
			}
		case objStr(d, "status") != "" && objStr(d, "status") != "open":
			state = "open (" + objStr(d, "status") + ")"
		case objStr(d, "priority_id") != "":
			state = "open"
		default:
			state = "open (not emitted)"
		}
		L = append(L, fmt.Sprintf("- `%s` %s (%s %s) tier %s, gap %s, "+
			"anchors %s — %s", rid, objStr(row, "probe"), objStr(row, "axis"),
			objStr(row, "lens"), pyStr(objAt(row, "tier")),
			pyStr(objAt(row, "assertion_gap")), anchors, state))
	}
	L = append(L, "")
	for _, entry := range blanks {
		L = append(L, fmt.Sprintf("- blank attested: %s cites `%s` — %s (%s)",
			objStr(entry, "axis"), objStr(entry, "anchor_blind"),
			objStr(entry, "reason"), objStr(entry, "actor")))
	}
	if len(blanks) > 0 {
		L = append(L, "")
	}
	return L, nil
}

func intAt(v validation.Value, key string) int64 {
	f := objAt(v, key)
	if f.Kind == validation.Int {
		return f.I
	}
	return 0
}

// Generate is generate(): write report.md, register/refresh the artifact and
// log report.generated. Returns the report path.
func Generate(campaign *state.Campaign) (string, error) {
	st, err := campaign.State()
	if err != nil {
		return "", err
	}
	policyPath := objStr(st, "policy_path")
	if policyPath != "" && fileExists(policyPath) {
		policy, err := bounty.LoadPolicy(policyPath)
		if err != nil {
			return "", err
		}
		all, err := findings.LoadAllFindings(campaign)
		if err != nil {
			return "", err
		}
		for _, f := range all {
			status := objStr(f, "status")
			if status != "CONFIRMED" && status != "CHAIN" {
				continue
			}
			if _, err := bounty.EvaluateBountyGate(campaign,
				objStr(f, "finding_id"), policy, true); err != nil {
				return "", err
			}
		}
	}
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return "", err
	}
	chainPaths, _ := filepath.Glob(filepath.Join(campaign.ChainsDir, "CHAIN-*.json"))
	sort.Strings(chainPaths)
	chains := []validation.Value{}
	for _, p := range chainPaths {
		doc, err := validation.ReadJson(p)
		if err != nil {
			return "", err
		}
		chains = append(chains, doc)
	}
	mem, err := learning.AllMemory(campaign)
	if err != nil {
		return "", err
	}

	evts, err := campaign.Events()
	if err != nil {
		return "", err
	}
	var headHash validation.Value = validation.VNull()
	if len(evts) > 0 {
		if h := objAt(evts[len(evts)-1], "event_hash"); h.Kind != validation.Null {
			headHash = h
		}
	}

	L := []string{}
	L = append(L, "<!-- state-head: "+pyStr(headHash)+" -->")
	L = append(L, "# Security Research Report — "+objStr(st, "program"))
	L = append(L, "")
	L = append(L, fmt.Sprintf("- campaign: `%s`", objStr(st, "campaign_id")))
	L = append(L, fmt.Sprintf("- phase: **%s** (pass %s)", objStr(st, "phase"),
		pyStr(objAt(asObj(objAt(st, "budget")), "pass"))))
	L = append(L, fmt.Sprintf("- active snapshot: `%s`",
		pyStr(objAt(st, "active_snapshot_id"))))
	L = append(L, fmt.Sprintf("- generated: %s", state.NowIso()))
	L = append(L, "")

	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	if fileExists(modelPath) {
		model, err := validation.ReadJson(modelPath)
		if err != nil {
			return "", err
		}
		econ := economics.EconomicSummary(model)
		L = append(L, "## Protocol economics")
		L = append(L, "")
		if gaps := listAt(econ, "equation_gaps"); len(gaps) > 0 {
			L = append(L, "| equation | missing |")
			L = append(L, "|---|---|")
			shown := gaps
			if len(shown) > 12 {
				shown = shown[:12]
			}
			for _, g := range shown {
				eq := []rune(objStr(g, "equation"))
				if len(eq) > 60 {
					eq = eq[:60]
				}
				L = append(L, fmt.Sprintf("| `%s` | %s |", string(eq),
					strings.Join(strList(objAt(g, "missing")), ", ")))
			}
			L = append(L, "")
		}
		if risky := listAt(econ, "risky_assets"); len(risky) > 0 {
			names := []string{}
			shown := risky
			if len(shown) > 6 {
				shown = shown[:6]
			}
			for _, a := range shown {
				names = append(names, objStr(a, "asset"))
			}
			L = append(L, fmt.Sprintf("- risky assets "+
				"(fee-on-transfer/rebasing/odd-decimals): %d — %s", len(risky),
				strings.Join(names, ", ")))
		}
		gaps := len(listAt(econ, "equation_gaps"))
		L = append(L, fmt.Sprintf("> %d equation(s) with no enforcement or "+
			"no known break path — the economic model is unfinished, not safe",
			gaps))
		L = append(L, "")
	}

	covPath := filepath.Join(campaign.ArtifactsDir, "coverage.json")
	if fileExists(covPath) {
		cov, err := validation.ReadJson(covPath)
		if err != nil {
			return "", err
		}
		s := asObj(objAt(cov, "summary"))
		if len(s.O) > 0 {
			L = append(L, "## Coverage")
			L = append(L, "")
			L = append(L, "| metric | value |")
			L = append(L, "|---|---|")
			for _, k := range s.O {
				if k.K == "unknown_note" {
					continue
				}
				L = append(L, fmt.Sprintf("| %s | %s |",
					strings.ReplaceAll(k.K, "_", " "), pyStr(k.V)))
			}
			L = append(L, "")
			note := "unknown ≠ secure"
			if v := objAt(s, "unknown_note"); v.Kind != validation.Null {
				note = pyStr(v)
			}
			L = append(L, "> "+note)
			L = append(L, "")
			thin, err := coverage.ThinCoverage(campaign, 2)
			if err != nil {
				return "", err
			}
			if len(thin) > 0 {
				L = append(L, "### Thin coverage (fewer than 2 trajectories)")
				L = append(L, "")
				shown := thin
				if len(shown) > 20 {
					shown = shown[:20]
				}
				for _, t := range shown {
					trajs := strings.Join(strList(objAt(t, "trajectories")), ", ")
					if trajs == "" {
						trajs = "none"
					}
					L = append(L, fmt.Sprintf("- `%s` — status %s, "+
						"trajectories: %s", objStr(t, "path"),
						objStr(t, "status"), trajs))
				}
				L = append(L, "")
			}
		}
	}

	priv, err := PrivilegedSection(campaign)
	if err != nil {
		return "", err
	}
	L = append(L, priv...)
	ps, err := ProbeSurfaceSection(campaign)
	if err != nil {
		return "", err
	}
	L = append(L, ps...)

	confirmed := []validation.Value{}
	chainF := []validation.Value{}
	ready := []validation.Value{}
	disproved, duplicates, outOfScope := 0, 0, 0
	for _, f := range all {
		switch objStr(f, "status") {
		case "CONFIRMED":
			confirmed = append(confirmed, f)
		case "CHAIN":
			chainF = append(chainF, f)
		case "DISPROVED":
			disproved++
		case "DUPLICATE":
			duplicates++
		case "OUT_OF_SCOPE":
			outOfScope++
		}
		if pyTruthy(objAt(asObj(objAt(f, "bounty")), "submission_ready")) {
			ready = append(ready, f)
		}
	}

	L = append(L, "## Results")
	L = append(L, "")
	if len(confirmed) > 0 {
		type clsCount struct {
			cls string
			n   int
		}
		order := []string{}
		counts := map[string]int{}
		for _, f := range confirmed {
			cls := objStr(objAt(f, "root_cause"), "class")
			if cls == "" {
				cls = "unclassified"
			}
			if _, ok := counts[cls]; !ok {
				order = append(order, cls)
			}
			counts[cls]++
		}
		rows := []clsCount{}
		for _, c := range order {
			rows = append(rows, clsCount{c, counts[c]})
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
		parts := []string{}
		for _, r := range rows {
			parts = append(parts, fmt.Sprintf("%d %s", r.n, r.cls))
		}
		L = append(L, fmt.Sprintf("- **confirmed: %d** — %s", len(confirmed),
			strings.Join(parts, ", ")))
	} else {
		L = append(L, "- **confirmed: 0**")
	}
	L = append(L, fmt.Sprintf("- chains materialized: **%d**", len(chains)))
	L = append(L, fmt.Sprintf("- disproved: %d  - duplicates: %d  "+
		"- out-of-scope: %d", disproved, duplicates, outOfScope))
	L = append(L, "")
	if policyPath != "" {
		L = append(L, fmt.Sprintf("- submission (bounty gate): **%d** of %d "+
			"confirmed are submission-ready — the gate measures submission "+
			"packaging (patch immunization, program policy), not finding severity",
			len(ready), len(confirmed)))
		L = append(L, "")
	}

	planPath := filepath.Join(campaign.ArtifactsDir, "campaign_plan.json")
	if fileExists(planPath) {
		plan, err := validation.ReadJson(planPath)
		if err != nil {
			plan = validation.VObj()
		}
		priorities := listAt(plan, "priorities")
		if len(priorities) > 0 {
			L = append(L, "## Answer quality")
			L = append(L, "")
			flagged := []string{}
			answered, na, openN := 0, 0, 0
			for _, p := range priorities {
				status := objStr(p, "status")
				ref := objAt(p, "closed_ref")
				reason := objStr(p, "closed_reason")
				sib := ""
				if objStr(p, "sibling_of") != "" {
					sib = " (sibling of " + objStr(p, "sibling_of") + ")"
				}
				question := []rune(objStr(p, "question"))
				if len(question) > 100 {
					question = question[:100]
				}
				// An empty-string closed_ref is "no usable ref" too, not just
				// an absent (null) one.
				noRef := ref.Kind == validation.Null ||
					(ref.Kind == validation.Str && ref.S == "")
				if status == "answered" && noRef {
					why := "no reason recorded"
					if reason != "" {
						why = "reason recorded, but no exec/finding/artifact " +
							"ref links it"
					}
					flagged = append(flagged, fmt.Sprintf("- **%s** (answered, "+
						"no evidence ref)%s: %s — %s", objStr(p, "id"), sib,
						string(question), why))
				} else if (status == "not-applicable" ||
					status == "deprioritized") && reason == "" {
					flagged = append(flagged, fmt.Sprintf("- **%s** (%s, no "+
						"reason)%s: %s", objStr(p, "id"), status, sib,
						string(question)))
				}
				switch status {
				case "answered":
					answered++
				case "not-applicable":
					na++
				case "open":
					openN++
				}
			}
			L = append(L, fmt.Sprintf("- plan: %d priorities — %d answered, "+
				"%d not-applicable, %d still open", len(priorities), answered,
				na, openN))
			for _, p := range priorities {
				if objStr(p, "status") == "open" && objStr(p, "sibling_of") != "" {
					question := []rune(objStr(p, "question"))
					if len(question) > 100 {
						question = question[:100]
					}
					L = append(L, fmt.Sprintf("- **%s** (open, sibling of %s): %s",
						objStr(p, "id"), objStr(p, "sibling_of"), string(question)))
				}
			}
			if len(flagged) > 0 {
				L = append(L, fmt.Sprintf("- **%d closure(s) lack evidence** "+
					"(flagged):", len(flagged)))
				L = append(L, flagged...)
			} else {
				L = append(L, "- all closed priorities carry a reason; every "+
					"'answered' priority is linked to evidence (ref or finding)")
			}
			L = append(L, "")
		}
	}

	clusterView, err := relations.RootCauseClusters(campaign)
	if err != nil {
		return "", err
	}
	if clusters := listAt(clusterView, "clusters"); len(clusters) > 0 {
		L = append(L, "## Root-cause clusters")
		L = append(L, "")
		for _, cl := range clusters {
			members := listAt(cl, "members")
			L = append(L, fmt.Sprintf("### `%s` — %d findings share this "+
				"root cause", objStr(cl, "class"), len(members)))
			L = append(L, "")
			if objStr(cl, "description") != "" {
				L = append(L, "- root cause: "+objStr(cl, "description"))
			}
			subs := listAt(cl, "subclusters")
			if len(subs) >= 2 {
				L = append(L, "- **one bug, several gates** — a fix at one "+
					"attack surface does NOT close the others; each surface "+
					"below needs its own fix (and its own verification)")
			}
			for _, sc := range subs {
				locs := []string{}
				for _, p := range strList(objAt(sc, "locations")) {
					locs = append(locs, "`"+p+"`")
				}
				fids := []string{}
				for _, m := range strList(objAt(sc, "finding_ids")) {
					fids = append(fids, "`"+m+"`")
				}
				line := fmt.Sprintf("- a fix at %s closes %s",
					strings.Join(locs, ", "), strings.Join(fids, ", "))
				if imm := strList(objAt(sc, "immunized")); len(imm) > 0 {
					quoted := []string{}
					for _, i := range imm {
						quoted = append(quoted, "`"+i+"`")
					}
					line += " (immunized: " + strings.Join(quoted, ", ") + ")"
				}
				L = append(L, line)
			}
			for _, e := range listAt(cl, "attested_causation") {
				L = append(L, fmt.Sprintf("- attested causation: `%s` "+
					"caused_by `%s` (attested by %s)", objStr(e, "src"),
					objStr(e, "dst"), objStr(e, "actor")))
			}
			L = append(L, "")
		}
	}

	var planPtr *validation.Value
	if plan, err := planner.LoadPlanReadonly(campaign); err == nil {
		planPtr = &plan
	}
	if planPtr != nil && len(listAt(*planPtr, "lenses")) > 0 {
		plan := *planPtr
		div, err := planner.DivergenceStatusFor(campaign, plan, nil)
		if err != nil {
			return "", err
		}
		lines := []string{"", "## Hypothesis lenses", ""}
		named := strList(objAt(div, "named_classes"))
		namedTxt := strings.Join(named, ", ")
		if namedTxt == "" {
			namedTxt = "none"
		}
		lines = append(lines, fmt.Sprintf("Bug classes named: %d (min %d): %s",
			len(named), planner.MinDistinctClasses, namedTxt))
		lines = append(lines, "")
		for _, l := range listAt(plan, "lenses") {
			reason := strings.TrimSpace(objStr(l, "closed_reason"))
			tail := ""
			if reason != "" {
				r := []rune(reason)
				if len(r) > 120 {
					r = r[:120]
				}
				tail = " — " + string(r)
			}
			ref := ""
			if objStr(l, "closed_ref") != "" {
				ref = " [ref: " + objStr(l, "closed_ref") + "]"
			}
			fam := fmt.Sprintf(" [families: %s; attested: %s]",
				strings.Join(strList(objAt(l, "families")), ", "),
				strings.Join(strList(objAt(l, "families_checked")), ", "))
			reopen := ""
			if objStr(l, "reopen_reason") != "" {
				reopen = " (REOPENED: " + objStr(l, "reopen_reason") + ")"
			}
			lines = append(lines, fmt.Sprintf("- %s %s (%s): %s%s%s%s%s",
				objStr(l, "id"), objStr(l, "lens"), objStr(l, "surface"),
				objStr(l, "status"), tail, ref, fam, reopen))
			for _, s := range listAt(l, "symmetry") {
				lines = append(lines, fmt.Sprintf("    - %s -> %s",
					objStr(s, "family"),
					strings.Join(strList(objAt(s, "primitives")), ", ")))
			}
		}
		L = append(L, strings.Join(lines, "\n"))
	}

	sortedConfirmed := append([]validation.Value{}, confirmed...)
	sort.SliceStable(sortedConfirmed, func(i, j int) bool {
		return riskScore(sortedConfirmed[i]) > riskScore(sortedConfirmed[j])
	})
	for _, f := range sortedConfirmed {
		sec, err := findingSection(campaign, f, "CONFIRMED", all)
		if err != nil {
			return "", err
		}
		L = append(L, sec...)
	}

	for _, ch := range chains {
		var sf validation.Value
		foundSF := false
		for _, f := range chainF {
			if objStr(objAt(f, "dedup_meta"), "chain_id") == objStr(ch, "chain_id") {
				sf = f
				foundSF = true
				break
			}
		}
		L = append(L, fmt.Sprintf("### CHAIN: %s", objStr(ch, "title")))
		L = append(L, "")
		L = append(L, fmt.Sprintf("- id: `%s` — status %s, evidence floor %s",
			objStr(ch, "chain_id"), objStr(ch, "status"),
			pyStr(objAt(ch, "evidence_floor"))))
		quoted := []string{}
		for _, m := range strList(objAt(ch, "members")) {
			quoted = append(quoted, "`"+m+"`")
		}
		L = append(L, "- members: "+strings.Join(quoted, ", "))
		if objStr(ch, "narrative") != "" {
			L = append(L, "- narrative: "+objStr(ch, "narrative"))
		}
		for _, lnk := range listAt(ch, "capability_links") {
			L = append(L, fmt.Sprintf("- `%s` grants *%s* → `%s` requires it",
				objStr(lnk, "from_finding"), objStr(lnk, "granted"),
				objStr(lnk, "to_finding")))
		}
		if foundSF {
			L = append(L, fmt.Sprintf("- super-finding: `%s`",
				objStr(sf, "finding_id")))
		}
		L = append(L, "")
	}

	dismissed := []validation.Value{}
	for _, f := range all {
		switch objStr(f, "status") {
		case "DISPROVED", "OUT_OF_SCOPE", "DUPLICATE":
			dismissed = append(dismissed, f)
		}
	}
	if len(dismissed) > 0 {
		L = append(L, "## Dismissed candidates (with reasons)")
		L = append(L, "")
		for _, f := range dismissed {
			hist := listAt(f, "history")
			last := validation.VObj()
			if len(hist) > 0 {
				last = asObj(hist[len(hist)-1])
			}
			L = append(L, fmt.Sprintf("- `%s` **%s** — %s",
				objStr(f, "finding_id"), objStr(f, "status"), objStr(f, "title")))
			reason := "n/a"
			if v := objAt(last, "reason"); v.Kind != validation.Null {
				reason = pyStr(v)
			}
			L = append(L, "  - reason: "+reason)
		}
		L = append(L, "")
	}

	if len(mem) > 0 {
		L = append(L, "## Learning queue")
		L = append(L, "")
		L = append(L, "| id | kind | status | promotion |")
		L = append(L, "|---|---|---|---|")
		for _, m := range mem {
			L = append(L, fmt.Sprintf("| `%s` | %s | %s | %s |",
				objStr(m, "memory_id"), objStr(m, "kind"), objStr(m, "status"),
				objStr(m, "promotion_status")))
		}
		pending := 0
		for _, m := range mem {
			if objStr(m, "promotion_status") == "pending" {
				pending++
			}
		}
		if pending > 0 {
			L = append(L, "")
			L = append(L, fmt.Sprintf("> %d candidate(s) awaiting human "+
				"approval — nothing enters long-term memory without it.",
				pending))
		}
		L = append(L, "")
	}

	out := filepath.Join(campaign.Dir, "report.md")
	if err := os.WriteFile(out, []byte(strings.Join(L, "\n")+"\n"), 0o644); err != nil {
		return "", err
	}
	if _, err := campaign.RegisterOrRefresh("report", out, "", nil,
		"report regenerated (view over current findings)"); err != nil {
		return "", err
	}
	data := validation.VObj(kv("path", validation.VStr(out)))
	if _, err := campaign.Log("report.generated", nil, &data); err != nil {
		return "", err
	}
	return out, nil
}

// immunizationWaived reports whether an explicit immunization waiver covers
// this finding (subject '*' waives the whole stage). B1: mirrors the
// fork-PoC waiver check so a waived immunization renders as a caveat.
func immunizationWaived(campaign *state.Campaign, f validation.Value) bool {
	waivers, err := completion.Waivers(campaign, "immunization")
	if err != nil {
		return false
	}
	for _, w := range waivers {
		subj := objStr(w, "subject")
		if subj == "*" || subj == objStr(f, "finding_id") {
			return true
		}
	}
	return false
}

func riskScore(f validation.Value) float64 {
	v := asObj(objAt(asObj(objAt(f, "risk")), "validated"))
	s := objAt(v, "score")
	switch s.Kind {
	case validation.Int:
		return float64(s.I)
	case validation.Flt:
		return s.F
	}
	return 0
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// getOr is Python's d.get(key, default) as a string render.
func getOr(v validation.Value, key, def string) string {
	if !hasKey(v, key) {
		return def
	}
	return pyStr(objAt(v, key))
}

// pyCommaAuto is Python's f"{v:,}": thousands separators, no forced decimals.
func pyCommaAuto(v validation.Value) string {
	switch v.Kind {
	case validation.Int:
		return commaInt(validation.IntText(v))
	case validation.Flt:
		s := validation.PythonFloat(v.F)
		return commaFloatText(s)
	}
	return pyStr(v)
}

func commaInt(digits string) string {
	neg := strings.HasPrefix(digits, "-")
	if neg {
		digits = digits[1:]
	}
	out := commaGroups(digits)
	if neg {
		return "-" + out
	}
	return out
}

func commaFloatText(s string) string {
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	intPart, frac := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, frac = s[:i], s[i:]
	} else if i := strings.IndexAny(s, "eE"); i >= 0 {
		intPart, frac = s[:i], s[i:]
	}
	out := commaGroups(intPart) + frac
	if neg {
		return "-" + out
	}
	return out
}

func commaGroups(digits string) string {
	var b strings.Builder
	for i, c := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// pyPercent0 is Python's f"{x:.0%}".
func pyPercent0(x float64) string {
	return strconv.FormatFloat(x*100, 'f', 0, 64) + "%"
}

var evidenceOrder = []string{"E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7"}

func evidenceIndex(level string) int {
	for i, l := range evidenceOrder {
		if l == level {
			return i
		}
	}
	return -1
}

// findingSection is report.generate's finding_section closure.
func findingSection(campaign *state.Campaign, f validation.Value, heading string,
	all []validation.Value) ([]string, error) {
	out := []string{}
	rc := asObj(objAt(f, "root_cause"))
	out = append(out, fmt.Sprintf("### %s: %s", heading, objStr(f, "title")))
	out = append(out, "")
	out = append(out, fmt.Sprintf("- id: `%s` — status **%s** (trajectory: %s)",
		objStr(f, "finding_id"), objStr(f, "status"),
		pyStr(objAt(f, "trajectory"))))
	cwe := ""
	if objStr(rc, "cwe") != "" {
		cwe = "CWE " + objStr(rc, "cwe")
	}
	out = append(out, fmt.Sprintf("- bug class: `%s` %s", pyStr(objAt(rc, "class")),
		cwe))
	inv := asObj(objAt(f, "invariant"))
	if objStr(inv, "statement") != "" {
		out = append(out, "- violated invariant: "+objStr(inv, "statement"))
	}
	att := asObj(objAt(f, "attacker"))
	if objStr(att, "profile") != "" {
		capital := ""
		if pyTruthy(objAt(att, "required_capital_usd")) {
			capital = " (capital: $" + pyCommaAuto(objAt(att, "required_capital_usd")) + ")"
		}
		out = append(out, "- attacker: "+objStr(att, "profile")+capital)
	}
	risk := asObj(objAt(f, "risk"))
	v := asObj(objAt(risk, "validated"))
	if len(v.O) > 0 {
		out = append(out, fmt.Sprintf("- validated risk: **%s/10 (%s)**",
			pyStr(objAt(v, "score")), pyStr(objAt(v, "band"))))
	}
	if rv := objStr(risk, "reversibility"); rv != "" {
		out = append(out, "- reversibility: **"+rv+"** (validated_risk component)")
	}
	iv := asObj(objAt(risk, "impact_vector"))
	if len(iv.O) > 0 {
		out = append(out, fmt.Sprintf("- impact vector: %s/%s/%s/%s (score %s)",
			pyStr(objAt(iv, "asset_exposure")),
			pyStr(objAt(iv, "privilege_class")),
			pyStr(objAt(iv, "recoverability")),
			pyStr(objAt(iv, "insolvency_risk")), pyStr(objAt(iv, "score"))))
	}
	if reported := objAt(f, "reported_severity"); pyTruthy(reported) {
		band := "n/a"
		if b := objAt(asObj(objAt(f, "risk")), "validated"); b.Kind == validation.Obj {
			if bv := objAt(b, "band"); bv.Kind != validation.Null {
				band = pyStr(bv)
			}
		}
		out = append(out, fmt.Sprintf("- reported severity: **%s** — computed "+
			"band: **%s**", pyStr(reported), band))
	}
	econ := asObj(objAt(risk, "economic"))
	if decision := findings.UnpriceableDecision(f); decision != nil {
		out = append(out, fmt.Sprintf("- economically extractable: "+
			"UNPRICEABLE (ceiling: %s)", pyStr(objAt(*decision, "ceiling"))))
	} else if ex := objAt(econ, "extractable_usd"); ex.Kind != validation.Null {
		out = append(out, fmt.Sprintf("- economically extractable: $%s",
			pyCommaAuto(ex)))
	}
	if exp := asObj(objAt(f, "exploitability")); len(exp.O) > 0 {
		if paid := objAt(exp, "paid"); paid.Kind == validation.Bool {
			if paid.B {
				out = append(out, fmt.Sprintf(
					"- paid exploitability: **yes** — who pays, and why: "+
						"%s", pyStr(objAt(exp, "argument"))))
			} else {
				line := "- paid exploitability: **no**"
				if a := objStr(exp, "argument"); a != "" {
					line += " — " + a
				}
				out = append(out, line)
			}
		}
	}
	b := asObj(objAt(f, "bounty"))
	if len(b.O) > 0 {
		line := fmt.Sprintf("- bounty gate: eligible=%s, submission_ready=%s",
			pyStr(objAt(b, "eligible")), pyStr(objAt(b, "submission_ready")))
		if blockers := listAt(b, "blocking_reasons"); len(blockers) > 0 {
			line += ", blockers: " + strings.Join(strList(objAt(b,
				"blocking_reasons")), "; ")
		}
		out = append(out, line)
	}
	if ar := asObj(objAt(b, "accepted_risk")); len(ar.O) > 0 {
		kind := objStr(ar, "kind")
		line := fmt.Sprintf("- accepted risk: **%s**", pyStr(objAt(ar,
			"pattern")))
		if kind != "" {
			line += " (" + kind + ")"
		}
		if ref := objStr(ar, "reference"); ref != "" {
			line += " — " + ref
		}
		if note := objStr(ar, "note"); note != "" {
			line += " — " + note
		}
		line += " (documented by the program; not submittable as written)"
		out = append(out, line)
	}
	out = append(out, "")
	out = append(out, "**Claim:** "+getOr(rc, "description", ""))
	if objStr(rc, "mechanism") != "" {
		out = append(out, "")
		out = append(out, "**Mechanism:** "+objStr(rc, "mechanism"))
	}
	seq := listAt(f, "exploit_sequence")
	if len(seq) > 0 {
		out = append(out, "")
		out = append(out, "**Sequence:**")
		sortedSeq := append([]validation.Value{}, seq...)
		sort.SliceStable(sortedSeq, func(i, j int) bool {
			return intAt(sortedSeq[i], "step") < intAt(sortedSeq[j], "step")
		})
		for _, s := range sortedSeq {
			line := fmt.Sprintf("%s. %s", pyStr(objAt(s, "step")),
				pyStr(objAt(s, "action")))
			if objStr(s, "state_effect") != "" {
				line += " → " + objStr(s, "state_effect")
			}
			out = append(out, line)
		}
	}
	ev := listAt(f, "evidence")
	if len(ev) > 0 {
		out = append(out, "")
		out = append(out, "**Evidence (ladder):**")
		// Validate every level up front: a bad level in a single-item
		// evidence array would never trip the sort comparator below.
		for _, e := range ev {
			if evidenceIndex(objStr(e, "level")) < 0 {
				return nil, fmt.Errorf("unknown evidence level")
			}
		}
		sortedEv := append([]validation.Value{}, ev...)
		sort.SliceStable(sortedEv, func(i, j int) bool {
			return evidenceIndex(objStr(sortedEv[i], "level")) <
				evidenceIndex(objStr(sortedEv[j], "level"))
		})
		for _, e := range sortedEv {
			line := fmt.Sprintf("- %s [%s] %s", objStr(e, "level"),
				objStr(e, "type"), pyStr(objAt(e, "description")))
			if objStr(e, "sandbox_profile") != "" {
				line += " (sandbox: " + objStr(e, "sandbox_profile") + ")"
			}
			out = append(out, line)
		}
	}

	if objStr(asObj(objAt(f, "maximization")), "ladder_id") != "" {
		status := objStr(f, "status")
		if status == "CONFIRMED" || status == "CHAIN" {
			rep, err := maximization.LadderReport(campaign, objStr(f, "finding_id"))
			if err != nil {
				return nil, err
			}
			lad := objAt(rep, "ladder")
			if lad.Kind == validation.Obj {
				out = append(out, "")
				disp := asObj(objAt(lad, "disposition"))
				line := fmt.Sprintf("**Variant ladder** `%s` — disposition: "+
					"**%s**", objStr(lad, "ladder_id"), objStr(disp, "state"))
				if objStr(disp, "state") == "waived" && objStr(disp, "reason") != "" {
					r := []rune(objStr(disp, "reason"))
					if len(r) > 120 {
						r = r[:120]
					}
					line += " (waived: " + string(r) + ")"
				}
				out = append(out, line)
				out = append(out, "")
				out = append(out, "| rung | name | axes | capital | extract | "+
					"status | exec |")
				out = append(out, "|---|---|---|---|---|---|---|")
				for _, r := range listAt(rep, "rungs") {
					ratio := "—"
					if v := objAt(r, "extraction_ratio"); v.Kind != validation.Null {
						ratio = pyPercent0(floatVal(v))
					}
					cap := "—"
					if v := objAt(r, "capital_usd"); v.Kind != validation.Null {
						cap = "$" + pyCommaAuto(v)
					}
					axes := strings.Join(strList(objAt(r, "axes")), ", ")
					if axes == "" {
						axes = "—"
					}
					row := fmt.Sprintf("| `%s` | %s ", objStr(r, "rung_id"),
						objStr(r, "name"))
					if objStr(r, "rung_id") == objStr(lad, "maximal_rung_id") {
						row += "**(maximal)** "
					}
					row += fmt.Sprintf("| %s | %s | %s | %s", axes, cap, ratio,
						objStr(r, "status"))
					if objStr(r, "reason") != "" {
						rr := []rune(objStr(r, "reason"))
						if len(rr) > 60 {
							rr = rr[:60]
						}
						row += " (reason: " + string(rr) + ")"
					}
					execID := objStr(r, "exec_id")
					if execID == "" {
						execID = "—"
					}
					row += fmt.Sprintf(" | `%s` |", execID)
					out = append(out, row)
				}
				if unexplored := strList(objAt(rep, "unexplored_axes")); len(unexplored) > 0 {
					out = append(out, "")
					out = append(out, "> unexplored axes: "+
						strings.Join(unexplored, ", ")+" — the search is not "+
						"complete; the maximal rung is provisional")
				}
				rungs := listAt(rep, "rungs")
				if len(rungs) > 0 {
					base := rungs[0]
					mx := asObj(objAt(rep, "maximal"))
					if len(mx.O) > 0 &&
						objStr(mx, "rung_id") != objStr(base, "rung_id") &&
						objAt(mx, "extraction_delta").Kind != validation.Null {
						delta := fmt.Sprintf("> claim delta base→maximal: "+
							"extraction %s → %s", pyPercent0(ratioOf(base)),
							pyPercent0(ratioOf(mx)))
						if objAt(base, "capital_usd").Kind != validation.Null &&
							objAt(mx, "capital_usd").Kind != validation.Null {
							delta += fmt.Sprintf(", capital $%s → $%s",
								pyCommaAuto(objAt(base, "capital_usd")),
								pyCommaAuto(objAt(mx, "capital_usd")))
						}
						out = append(out, "")
						out = append(out, delta)
					}
				}
			}
		}
	}

	status := objStr(f, "status")
	if status == "CONFIRMED" || status == "CHAIN" {
		item, reasonPtr, err := forkpoc.ForkPocEvidence(campaign, f)
		if err != nil {
			return nil, err
		}
		reason := ""
		if reasonPtr != nil {
			reason = *reasonPtr
		}
		out = append(out, "")
		if item.Kind == validation.Obj {
			out = append(out, fmt.Sprintf("- mainnet fork PoC: **proven** — "+
				"%s `%s` from `%s` (fork-runner, exit 0)", objStr(item, "level"),
				objStr(item, "type"), pyStr(objAt(item, "artifact_id"))))
		} else {
			waivers, err := completion.Waivers(campaign, "mainnet-fork-poc")
			if err != nil {
				return nil, err
			}
			waived := false
			for _, w := range waivers {
				subj := objStr(w, "subject")
				if subj == "*" || subj == objStr(f, "finding_id") {
					waived = true
					break
				}
			}
			if waived {
				out = append(out, "- mainnet fork PoC: **WAIVED** (waiver on "+
					"the record)")
			} else {
				out = append(out, "- mainnet fork PoC: **NOT PROVEN** — "+reason)
			}
		}
		immState, immDetail := immunize.ImmunizationDetail(f)
		marks := map[string]string{"immunized": "**IMMUNIZED**",
			"bypass": "**BYPASS FOUND**", "partial": "**PARTIAL**",
			"missing": "**NOT VERIFIED**"}
		mark, immRendered := marks[immState], immDetail
		if immState != "immunized" && immunizationWaived(campaign, f) {
			// B1: an explicit immunization waiver renders as a caveat,
			// matching how the fork-PoC waiver renders above.
			mark, immRendered = "**WAIVED**", "waiver on the record"
		}
		out = append(out, fmt.Sprintf("- patch verification: %s — %s",
			mark, immRendered))
		if immState == "immunized" {
			cls := objStr(rc, "class")
			siblings := []validation.Value{}
			for _, g := range all {
				if objStr(g, "finding_id") == objStr(f, "finding_id") {
					continue
				}
				gs := objStr(g, "status")
				if gs != "CONFIRMED" && gs != "CHAIN" {
					continue
				}
				if objStr(objAt(g, "root_cause"), "class") != cls {
					continue
				}
				if immunize.IsImmunized(g) {
					continue
				}
				siblings = append(siblings, g)
			}
			if len(siblings) > 0 {
				sort.SliceStable(siblings, func(i, j int) bool {
					return objStr(siblings[i], "finding_id") <
						objStr(siblings[j], "finding_id")
				})
				ids := []string{}
				for _, g := range siblings {
					ids = append(ids, "`"+objStr(g, "finding_id")+"`")
				}
				out = append(out, fmt.Sprintf("- immunization credit scope: "+
					"this patch immunizes `%s` ONLY — %d same-class sibling(s) "+
					"are NOT immunized by it (%s); they are separate attack "+
					"surfaces of the same root cause", objStr(f, "finding_id"),
					len(siblings), strings.Join(ids, ", ")))
			}
		}
	}

	ei := asObj(objAt(f, "economic_impact"))
	usdKeys := []string{}
	for _, k := range ei.O {
		if strings.HasSuffix(k.K, "_usd") && k.V.Kind != validation.Null {
			usdKeys = append(usdKeys, k.K)
		}
	}
	if len(usdKeys) > 0 {
		basis := objStr(ei, "price_basis")
		out = append(out, "")
		if basis != "" {
			rowPtr, err := pricing.PriceRow(campaign, basis)
			if err != nil {
				return nil, err
			}
			if rowPtr != nil {
				src := []rune(objStr(*rowPtr, "source"))
				if len(src) > 60 {
					src = src[:60]
				}
				out = append(out, fmt.Sprintf("- price basis: `%s` — %s @ $%s "+
					"(%s, as of %s)", basis, objStr(*rowPtr, "asset"),
					pyCommaAuto(objAt(*rowPtr, "usd")), string(src),
					pyStr(objAt(*rowPtr, "as_of"))))
			} else {
				out = append(out, fmt.Sprintf("- price basis: `%s` — "+
					"**UNRESOLVED** (no row in the price table)", basis))
			}
		} else {
			out = append(out, "- price basis: **NONE** — USD figures "+
				strings.Join(usdKeys, ", ")+" are unattributed")
		}
	}
	out = append(out, "")
	return out, nil
}

func ratioOf(rung validation.Value) float64 {
	return floatVal(objAt(rung, "extraction_ratio"))
}

func floatVal(v validation.Value) float64 {
	switch v.Kind {
	case validation.Int:
		return float64(v.I)
	case validation.Flt:
		return v.F
	}
	return 0
}
