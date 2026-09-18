package cli

// cmd_brief: `webv2 brief <campaign> [--json] [--deep]` — the operator
// cockpit (cli.py cmd_brief verbatim). READ-ONLY: a view, never a mutation.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"websec/internal/briefing"
	"websec/internal/state"
	"websec/internal/validation"
)

const briefUsage = "usage: webv2 brief [-h] [--json] [--deep] campaign\n"

const briefHelp = `usage: webv2 brief [-h] [--json] [--deep] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
  --json
  --deep      fold in the full integrity audit
`

func runBrief(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		cid, asJSON, deep, help, err := parseBriefArgs(args)
		if err != nil {
			return err
		}
		if help {
			fmt.Fprint(r.Out, briefHelp)
			return nil
		}
		c, err := t14Open(root, cid)
		if err != nil {
			return err
		}
		b, err := briefing.BuildBrief(c, deep, nil)
		if err != nil {
			return err
		}
		if asJSON {
			fmt.Fprintln(r.Out, validation.DumpIndentedASCII(b))
			return nil
		}
		return printBrief(c, b, r)
	})
}

func parseBriefArgs(args []string) (string, bool, bool, bool, error) {
	sp := &argSpec{
		prog:  "brief",
		usage: briefUsage,
		flags: []*boolOpt{{name: "--json"}, {name: "--deep"}},
		pos:   []*posOpt{{name: "campaign"}},
	}
	if err := sp.parse(args); err != nil {
		return "", false, false, false, err
	}
	if sp.helpSeen {
		return "", false, false, true, nil
	}
	asJSON, deep := false, false
	for _, f := range sp.flags {
		switch f.name {
		case "--json":
			asJSON = f.set
		case "--deep":
			deep = f.set
		}
	}
	return sp.pos[0].val, asJSON, deep, false, nil
}

func printBrief(c *state.Campaign, b validation.Value, r *Runner) error {
	camp := validation.ObjAt(b, "campaign")
	snapshot := validation.ObjStr(camp, "active_snapshot")
	if snapshot == "" {
		snapshot = "(none)"
	}
	line := fmt.Sprintf("campaign %s (%s) — phase %s, pass %s, stages %s/%s, "+
		"discovery slots left %s, snapshot %s", validation.ObjStr(camp, "campaign_id"),
		validation.ObjStr(camp, "program"), validation.ObjStr(camp, "phase"), pyReprVal(validation.ObjAt(camp, "pass")),
		pyReprVal(validation.ObjAt(camp, "stages_done")), pyReprVal(validation.ObjAt(camp, "stages_total")),
		pyReprVal(validation.ObjAt(camp, "discovery_slots_left")), snapshot)
	if v := validation.ObjAt(camp, "elapsed_hours"); v.Kind != validation.Null {
		line += fmt.Sprintf(", %sh elapsed", pyReprVal(v))
	}
	fmt.Fprintln(r.Out, line)
	if t14Truthy(validation.ObjAt(camp, "closed")) {
		by := validation.ObjStr(camp, "completed_by")
		if by == "" {
			by = "operator"
		}
		reason := validation.ObjStr(camp, "completed_reason")
		if reason == "" {
			reason = "no reason recorded"
		}
		fmt.Fprintf(r.Out, "COMPLETE — closed by %s: %s\n", by, reason)
	}
	fs := validation.ObjAt(b, "findings")
	byStatus := validation.ObjAt(fs, "by_status")
	byStatusTxt := "{ }"
	if t14Truthy(byStatus) {
		byStatusTxt = validation.PyRepr(byStatus)
	}
	fmt.Fprintf(r.Out, "findings: %s  %s\n", pyReprVal(validation.ObjAt(fs, "total")), byStatusTxt)
	if ps := validation.ObjAt(b, "probe_surface"); t14Truthy(ps) {
		pl := fmt.Sprintf("probe surface: %s rows (%s dispositioned, %s open)",
			pyReprVal(validation.ObjAt(ps, "rows")), pyReprVal(validation.ObjAt(ps, "dispositioned")),
			pyReprVal(validation.ObjAt(ps, "open")))
		if t14Truthy(validation.ObjAt(ps, "stale")) {
			pl += " — stale?"
		}
		fmt.Fprintln(r.Out, pl)
	}
	// G9 opaque surfaces (Task 6): presence-gated — a brief whose model
	// carries no components prints no bytes here.
	if ts := validation.ObjAt(b, "tracked_surfaces"); len(ts.A) > 0 {
		fmt.Fprintln(r.Out, "  tracked-but-opaque surfaces (findings only):")
		for _, ln := range t31Strings(ts) {
			fmt.Fprintf(r.Out, "    %s\n", ln)
		}
	}
	// G10 assumption table (Task 4): presence-gated — a brief whose model
	// is chains-only (no declared assumptions, no gaps) prints no bytes.
	if al := validation.ObjAt(b, "chain_assumption_lines"); len(al.A) > 0 {
		fmt.Fprintln(r.Out, "  chain assumptions (declared table + gaps):")
		for _, ln := range t31Strings(al) {
			fmt.Fprintf(r.Out, "    %s\n", ln)
		}
	}
	if dr := validation.ObjAt(b, "disposition_review"); len(dr.A) > 0 {
		fmt.Fprintf(r.Out, "  disposition review: %d flagged high-risk "+
			"dismissal(s) (B4)\n", len(dr.A))
		for _, f := range dr.A {
			phrases := strings.Join(t31Strings(validation.ObjAt(f, "phrases")), ", ")
			fmt.Fprintf(r.Out, "    %s (row %s, tier %s, gap %s): %s [%s]\n",
				validation.ObjStr(f, "priority"), validation.ObjStr(f, "row_id"),
				pyReprVal(validation.ObjAt(f, "tier")), pyReprVal(validation.ObjAt(f, "assertion_gap")),
				scalarStr(validation.ObjAt(f, "reason")), phrases)
		}
	}
	for _, ch := range objListAt(fs, "materializable_chains") {
		fmt.Fprintf(r.Out, "  materializable chain: %s\n",
			strings.Join(t31Strings(validation.ObjAt(ch, "members")), " -> "))
	}
	for _, d := range objListAt(fs, "gate_deficits") {
		fmt.Fprintf(r.Out, "  %s [%s %s]: %s\n", validation.ObjStr(d, "finding_id"),
			validation.ObjStr(d, "status"), validation.ObjStr(d, "level"), validation.ObjStr(d, "deficit"))
	}
	for _, fid := range t31Strings(validation.ObjAt(fs, "memory_recall_pending")) {
		fmt.Fprintf(r.Out, "  %s: memory recall pending — run `webv2 recall %s "+
			"--finding %s`\n", fid, c.CampaignID, fid)
	}
	for _, u := range objListAt(fs, "structurally_unreachable") {
		fmt.Fprintf(r.Out, "  %s stuck at %s (floor %s): %s\n",
			validation.ObjStr(u, "finding_id"), validation.ObjStr(u, "level"), validation.ObjStr(u, "floor"),
			strings.Join(t31Strings(validation.ObjAt(u, "missing")), "; "))
	}
	for _, t := range objListAt(b, "terminals") {
		fmt.Fprintf(r.Out, "  terminal -> %s: %s (capital $%s)\n",
			validation.ObjStr(t, "terminal_capability"),
			strings.Join(t31Strings(validation.ObjAt(t, "path")), " -> "),
			t31Comma0(validation.ObjAt(t, "capital_usd")))
	}
	for _, q := range objListAt(b, "independent_verification_queue") {
		tag := ""
		if t14Truthy(validation.ObjAt(q, "mandatory")) {
			tag = " [MANDATORY]"
		}
		fmt.Fprintf(r.Out, "  E6 queue: %s (at %s)%s\n", validation.ObjStr(q, "finding_id"),
			validation.ObjStr(q, "evidence_level"), tag)
	}
	if t14Truthy(validation.ObjAt(validation.ObjAt(b, "bounty"), "policy")) {
		for _, x := range objListAt(validation.ObjAt(b, "bounty"), "evaluated") {
			var state string
			switch {
			case t14Truthy(validation.ObjAt(x, "submission_ready")):
				state = "submission ready"
			case t14Truthy(validation.ObjAt(x, "eligible")):
				state = "eligible — " + strings.Join(
					t31Strings(validation.ObjAt(x, "blocking_reasons")), "; ")
			default:
				state = "not eligible"
			}
			fmt.Fprintf(r.Out, "  gate: %s: %s\n", validation.ObjStr(x, "finding_id"), state)
		}
	} else {
		fmt.Fprintln(r.Out, "  gate: no policy loaded (run scope with a policy)")
	}
	ch := asObjOrEmpty(validation.ObjAt(b, "critical_hunt"))
	if ps := validation.ObjAt(ch, "prescreen"); t14Truthy(ps) {
		// Python: ', '.join(ps['matched']) or 'none' — an empty match list
		// renders the literal "none", not an empty tail.
		matchedNames := strings.Join(t31Strings(validation.ObjAt(ps, "matched")), ", ")
		if matchedNames == "" {
			matchedNames = "none"
		}
		pl := fmt.Sprintf("  prescreen: matched %s", matchedNames)
		if forced := t31Strings(validation.ObjAt(ps, "forced")); len(forced) > 0 {
			pl += " (forced: " + strings.Join(forced, ", ") + ")"
		}
		fmt.Fprintln(r.Out, pl)
		for _, pair := range validation.ObjAt(ps, "near_matches").O {
			names := t31Strings(pair.V)
			if len(names) > 3 {
				names = names[:3]
			}
			fmt.Fprintf(r.Out, "        near-miss %s: %s\n", pair.K,
				strings.Join(names, ", "))
		}
	}
	if fd := validation.ObjAt(ch, "fork_diff"); t14Truthy(fd) {
		fmt.Fprintf(r.Out, "  fork-diff: %s\n", validation.ObjStr(fd, "summary"))
	}
	for _, rec := range objListAt(ch, "recency_top") {
		d := "never"
		if v := validation.ObjAt(rec, "days_ago"); v.Kind != validation.Null {
			d = pyReprVal(v) + "d ago"
		}
		fmt.Fprintf(r.Out, "  recency: %s %s  %s\n",
			pyFixed2(t31Float(validation.ObjAt(rec, "score"))), pyRight(d, 10),
			validation.ObjStr(rec, "path"))
	}
	amps := asObjOrEmpty(validation.ObjAt(ch, "amplifiers"))
	if detected := validation.ObjAt(amps, "detected"); t14Truthy(detected) {
		parts := []string{}
		keys := make([]string, 0, len(detected.O))
		for _, pair := range detected.O {
			keys = append(keys, pair.K)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s(%s)", k,
				pyReprVal(validation.ObjAt(detected, k))))
		}
		fmt.Fprintln(r.Out, "  amplifiers: "+strings.Join(parts, ", "))
		for _, bc := range objListAt(amps, "boosted_classes") {
			fmt.Fprintf(r.Out, "        boosted %s: %s\n", validation.ObjStr(bc, "bug_class"),
				strings.Join(t31Strings(validation.ObjAt(bc, "amplifiers")), ", "))
		}
	}
	// G1 tool flags: present only when a finding carries detector
	// provenance (briefing.ChToolFlags returns Null otherwise).
	if tf := validation.ObjAt(ch, "tool_flags"); t14Truthy(tf) {
		fmt.Fprintln(r.Out, "TOOL FLAGS (SAST hypotheses)")
		fmt.Fprintf(r.Out, "  flags: %s, corroborated: %d\n",
			pyReprVal(validation.ObjAt(tf, "total")),
			len(t31Strings(validation.ObjAt(tf, "corroborated"))))
		census := []string{}
		for _, pair := range validation.ObjAt(tf, "by_verdict").O {
			census = append(census, pair.K+" "+pyReprVal(pair.V))
		}
		fmt.Fprintf(r.Out, "  by verdict: %s\n", strings.Join(census, ", "))
	}
	iv := asObjOrEmpty(validation.ObjAt(ch, "invariant_verification"))
	if t14Truthy(validation.ObjAt(iv, "total")) {
		unv := strings.Join(t31Strings(validation.ObjAt(iv, "unverified_model")), ", ")
		if unv == "" {
			unv = "none"
		}
		fmt.Fprintf(r.Out, "  invariants: %s total — unverified model-derived: "+
			"%s\n", pyReprVal(validation.ObjAt(iv, "total")), unv)
	}
	for _, s := range objListAt(ch, "stale_artifacts") {
		// r9 (critic): the reason must tell the truth about the geometry.
		// "active pin moved" is only honest when a pin EXISTS to move.
		// r46: "computed before any pin existed" was a story the recorded
		// field cannot support — stale_snapshot == "unpinned" says the
		// artifact was hashed on the UNPINNED tree, which is equally true
		// when a pin exists but the artifact was computed outside it (the
		// critic's repro: `snap --exclude bulk`, then `index`, then
		// `brief` claimed no pin ever existed while one did). Say what the
		// field establishes: the workspace it hashed was not pinned.
		from, active := validation.ObjStr(s, "stale_snapshot"), snapshot
		if active == "(none)" {
			active = ""
		}
		why := "active pin moved"
		switch {
		case from == "" || from == "unpinned":
			why = "computed on the unpinned workspace"
		case active == "":
			why = "the campaign has no active pin anymore"
		}
		if from == "" || from == "unpinned" {
			// One clause, not two: "computed on unpinned, computed
			// before any pin existed" said the same thing twice.
			why = "computed on the unpinned workspace"
			from = ""
		} else {
			why = "computed on " + from + ", " + why
		}
		fmt.Fprintf(r.Out, "  STALE %s (%s) — re-run: %s\n",
			validation.ObjStr(s, "artifact"), why, validation.ObjStr(s, "re_run"))
	}
	for _, m := range objListAt(b, "pending_memory") {
		fmt.Fprintf(r.Out, "  memory decision: %s (%s/%s)\n",
			validation.ObjStr(m, "memory_id"), validation.ObjStr(m, "kind"), validation.ObjStr(m, "status"))
	}
	rv := validation.ObjAt(b, "relations")
	kinds := []string{}
	for _, pair := range validation.ObjAt(rv, "by_kind").O {
		if t14Truthy(pair.V) {
			kinds = append(kinds, pair.K+":"+pyReprVal(pair.V))
		}
	}
	kindTxt := strings.Join(kinds, ", ")
	if kindTxt == "" {
		kindTxt = "none"
	}
	relLine := fmt.Sprintf("  relations: %s edges (%s)", pyReprVal(validation.ObjAt(rv,
		"edge_count")), kindTxt)
	if drift := validation.ObjAt(rv, "drift_problems"); t14Truthy(drift) {
		relLine += " — DRIFT: " + validation.PyRepr(drift)
	}
	fmt.Fprintln(r.Out, relLine)
	if problems := objListAt(b, "problems"); len(problems) > 0 {
		fmt.Fprintln(r.Out, "  problems:")
		for _, p := range problems {
			fmt.Fprintf(r.Out, "    %s\n", scalarStr(p))
		}
	}
	ec := validation.ObjAt(validation.ObjAt(b, "economics"), "totals")
	y := validation.ObjAt(ec, "yield_usd_per_usd")
	budget := validation.ObjAt(validation.ObjAt(b, "economics"), "budget")
	var budgetLine string
	if validation.ObjStr(budget, "status") == "no-limit" {
		budgetLine = "no cost ceiling set (unbounded)"
	} else {
		pos := "within limit"
		if validation.ObjStr(budget, "status") != "within" {
			pos = "EXCEEDED by $" + t31Comma2(validation.ObjAt(budget, "over_by_usd"))
		}
		budgetLine = "$" + t31Comma2(validation.ObjAt(budget, "limit_usd")) + " ceiling — " + pos
	}
	yieldTxt := "n/a (no cost recorded)"
	if y.Kind != validation.Null {
		yieldTxt = pyFixed2(t31Float(y)) + "x"
	}
	fmt.Fprintf(r.Out, "  economics: cost $%s, confirmed %s / $%s, yield %s  "+
		"[%s]\n", t31Comma2(validation.ObjAt(ec, "total_cost_usd")),
		pyReprVal(validation.ObjAt(ec, "confirmed_findings")),
		t31Comma0(validation.ObjAt(ec, "confirmed_value_usd")), yieldTxt, budgetLine)
	integ := validation.ObjAt(b, "integrity")
	if ok := validation.ObjAt(integ, "ok"); ok.Kind != validation.Null {
		problems := validation.ObjAt(integ, "problems")
		n := 0
		if problems.Kind == validation.Obj {
			for _, pair := range problems.O {
				n += len(pair.V.A)
			}
		} else if problems.Kind == validation.Arr {
			n = len(problems.A)
		}
		verdict := "FAIL"
		if t14Truthy(ok) {
			verdict = "PASS"
		}
		fmt.Fprintf(r.Out, "  integrity: %s — %d problem(s) (fast: event-log "+
			"chain; --deep for full re-hashes)\n", verdict, n)
		if shared := validation.ObjAt(integ, "shared_store"); t14Truthy(shared) {
			sv := "FAIL"
			if t14Truthy(validation.ObjAt(shared, "ok")) {
				sv = "PASS"
			}
			fmt.Fprintf(r.Out, "  shared store: %s (%s signatures, %s "+
				"memory rows)\n", sv, pyReprVal(validation.ObjAt(shared, "signature_count")),
				pyReprVal(validation.ObjAt(shared, "memory_count")))
		}
	} else {
		fmt.Fprintln(r.Out, "  integrity: not checked (use --deep)")
	}
	att := asObjOrEmpty(validation.ObjAt(b, "attention"))
	if lines := objListAt(att, "lines"); len(lines) > 0 {
		fmt.Fprintln(r.Out, "  attention:")
		for _, l := range lines {
			fmt.Fprintf(r.Out, "    %s\n", scalarStr(l))
		}
	}
	fmt.Fprintln(r.Out, "next actions:")
	for i, a := range objListAt(b, "next_actions") {
		fmt.Fprintf(r.Out, "  %d. %s\n", i+1, scalarStr(a))
	}
	return nil
}

// t31Strings renders a list value as Go strings (Python's join semantics need
// every element to be a string).
func t31Strings(v validation.Value) []string {
	out := []string{}
	for _, it := range v.A {
		out = append(out, scalarStr(it))
	}
	return out
}

// pyReprVal is Python's str() for a scalar/list/dict in an f-string.
func pyReprVal(v validation.Value) string {
	return validation.PyRepr(v)
}

func asObjOrEmpty(v validation.Value) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VObj()
	}
	return v
}

func t31Float(v validation.Value) float64 {
	switch v.Kind {
	case validation.Int:
		return float64(v.I)
	case validation.Flt:
		return v.F
	}
	return 0
}

// t31Comma0 is Python's f"{v:,.0f}".
func t31Comma0(v validation.Value) string {
	return t31Comma(t31Float(v), 0)
}

// t31Comma2 is Python's f"{v:,.2f}".
func t31Comma2(v validation.Value) string {
	return t31Comma(t31Float(v), 2)
}

func t31Comma(f float64, decimals int) string {
	s := strconv.FormatFloat(f, 'f', decimals, 64)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	intPart, frac := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, frac = s[:i], s[i:]
	}
	var b strings.Builder
	for i, ch := range intPart {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(ch)
	}
	out := b.String() + frac
	if neg {
		return "-" + out
	}
	return out
}

func init() {
	register(command{ord: 21, name: "brief",
		line: "brief <campaign>                     operator cockpit (what matters now)",
		run:  runBrief})
}
