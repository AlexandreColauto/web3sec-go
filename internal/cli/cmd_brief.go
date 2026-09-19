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
	"websec/internal/version"
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
			briefFrameworkBuildWarn(c, r)
			return nil
		}
		if err := printBrief(c, b, r); err != nil {
			return err
		}
		briefFrameworkBuildWarn(c, r)
		return nil
	})
}

// briefFrameworkBuildWarn is the A11 attribution disclosure: when the campaign
// was last recorded under a DIFFERENT framework build than the one answering
// now, say so on stderr — the cockpit's own bytes (stdout, both modes) stay
// untouched, and a campaign with no recorded stamp stays silent.
//
// The stamp lives on the `snapshot.pinned` event's data (state/campaign_
// snapshot.go's emitEvent, DEFECT-2 follow-up) because the state projection's
// snapshots row is an index, not a provenance record. Reading the ledger here
// is the minimal plumbing: no brief value changes shape, no new state key.
// The NEWEST pin is the campaign's latest word (the log is append-only); an
// unreadable ledger, no pin at all, or a pin with no stamp is silence, never
// a guess — the grandfather rule for campaigns pinned before the key existed.
func briefFrameworkBuildWarn(c *state.Campaign, r *Runner) {
	recorded, ok := newestSnapshotFrameworkBuild(c)
	if !ok {
		return
	}
	if running := version.Commit(); recorded != running {
		fmt.Fprintf(r.Err, "framework: campaign last recorded under build %s, "+
			"this binary is %s — behavior above may reflect the newer "+
			"scheduler\n", recorded, running)
	}
}

// newestSnapshotFrameworkBuild returns the framework_build recorded on the
// NEWEST snapshot.pinned event (the log is append-only, so the last pin is
// the newest), and ok=false when the ledger cannot be read, no pin exists,
// or that pin carries no stamp (the grandfather shape). It deliberately does
// NOT walk back to an older pin: "the newest snapshot's stamp" is the claim
// this notice makes, and a missing key is silence, never a guess.
//
// internal/briefing's pinBuild reads the same event data for the ACTIVE
// snapshot (its skew next-action line); this reader answers the different
// question the stderr notice asks — what did the campaign last record,
// whatever is active — and is kept here so the disclosure does not depend on
// the action surface.
func newestSnapshotFrameworkBuild(c *state.Campaign) (string, bool) {
	events, err := c.Events()
	if err != nil {
		return "", false
	}
	found := false
	build := ""
	for _, e := range events {
		if validation.ObjStr(e, "type") != "snapshot.pinned" {
			continue
		}
		found = true
		build = validation.ObjStr(validation.ObjAt(e, "data"), "framework_build")
	}
	if !found || build == "" {
		return "", false
	}
	return build, true
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

// briefPrinter carries the shared printBrief context — the campaign handle,
// the brief value, the writer and the resolved active-snapshot fallback — so
// each section of the cockpit view is its own method with no parameter list
// to grow.
type briefPrinter struct {
	c        *state.Campaign
	b        validation.Value
	r        *Runner
	camp     validation.Value
	snapshot string
}

func printBrief(c *state.Campaign, b validation.Value, r *Runner) error {
	p := &briefPrinter{c: c, b: b, r: r, camp: validation.ObjAt(b, "campaign")}
	p.briefHeader()
	p.briefFindingsSummary()
	p.briefSurfaces()
	p.briefFindingLines()
	p.briefBountyGates()
	p.briefCriticalHunt()
	p.briefHuntSignals()
	p.briefStaleArtifacts()
	p.briefMemoryRelationsProblems()
	p.briefEconomics()
	p.briefIntegrity()
	p.briefAttentionNextActions()
	return nil
}

// briefHeader emits the campaign line and, for a closed campaign, the
// COMPLETE footer. It also resolves the "(none)" snapshot fallback that the
// stale-artifact section reuses.
func (p *briefPrinter) briefHeader() {
	camp := p.camp
	snapshot := validation.ObjStr(camp, "active_snapshot")
	if snapshot == "" {
		snapshot = "(none)"
	}
	p.snapshot = snapshot
	line := fmt.Sprintf("campaign %s (%s) — phase %s, pass %s, stages %s/%s, "+
		"discovery slots left %s, snapshot %s", validation.ObjStr(camp, "campaign_id"),
		validation.ObjStr(camp, "program"), validation.ObjStr(camp, "phase"), pyReprVal(validation.ObjAt(camp, "pass")),
		pyReprVal(validation.ObjAt(camp, "stages_done")), pyReprVal(validation.ObjAt(camp, "stages_total")),
		pyReprVal(validation.ObjAt(camp, "discovery_slots_left")), snapshot)
	if v := validation.ObjAt(camp, "elapsed_hours"); v.Kind != validation.Null {
		line += fmt.Sprintf(", %sh elapsed", pyReprVal(v))
	}
	fmt.Fprintln(p.r.Out, line)
	if t14Truthy(validation.ObjAt(camp, "closed")) {
		by := validation.ObjStr(camp, "completed_by")
		if by == "" {
			by = "operator"
		}
		reason := validation.ObjStr(camp, "completed_reason")
		if reason == "" {
			reason = "no reason recorded"
		}
		fmt.Fprintf(p.r.Out, "COMPLETE — closed by %s: %s\n", by, reason)
	}
}

// briefFindingsSummary emits the findings count line and, when present, the
// probe-surface line.
func (p *briefPrinter) briefFindingsSummary() {
	fs := validation.ObjAt(p.b, "findings")
	byStatus := validation.ObjAt(fs, "by_status")
	byStatusTxt := "{ }"
	if t14Truthy(byStatus) {
		byStatusTxt = validation.PyRepr(byStatus)
	}
	fmt.Fprintf(p.r.Out, "findings: %s  %s\n", pyReprVal(validation.ObjAt(fs, "total")), byStatusTxt)
	if ps := validation.ObjAt(p.b, "probe_surface"); t14Truthy(ps) {
		pl := fmt.Sprintf("probe surface: %s rows (%s dispositioned, %s open)",
			pyReprVal(validation.ObjAt(ps, "rows")), pyReprVal(validation.ObjAt(ps, "dispositioned")),
			pyReprVal(validation.ObjAt(ps, "open")))
		if t14Truthy(validation.ObjAt(ps, "stale")) {
			pl += " — stale?"
		}
		fmt.Fprintln(p.r.Out, pl)
	}
}

// briefSurfaces emits the presence-gated surface sections: the opaque
// tracked surfaces, the chain-assumption table, and the disposition review.
func (p *briefPrinter) briefSurfaces() {
	// G9 opaque surfaces (Task 6): presence-gated — a brief whose model
	// carries no components prints no bytes here.
	if ts := validation.ObjAt(p.b, "tracked_surfaces"); len(ts.A) > 0 {
		fmt.Fprintln(p.r.Out, "  tracked-but-opaque surfaces (findings only):")
		for _, ln := range t31Strings(ts) {
			fmt.Fprintf(p.r.Out, "    %s\n", ln)
		}
	}
	// G10 assumption table (Task 4): presence-gated — a brief whose model
	// is chains-only (no declared assumptions, no gaps) prints no bytes.
	if al := validation.ObjAt(p.b, "chain_assumption_lines"); len(al.A) > 0 {
		fmt.Fprintln(p.r.Out, "  chain assumptions (declared table + gaps):")
		for _, ln := range t31Strings(al) {
			fmt.Fprintf(p.r.Out, "    %s\n", ln)
		}
	}
	if dr := validation.ObjAt(p.b, "disposition_review"); len(dr.A) > 0 {
		fmt.Fprintf(p.r.Out, "  disposition review: %d flagged high-risk "+
			"dismissal(s) (B4)\n", len(dr.A))
		for _, f := range dr.A {
			phrases := strings.Join(t31Strings(validation.ObjAt(f, "phrases")), ", ")
			fmt.Fprintf(p.r.Out, "    %s (row %s, tier %s, gap %s): %s [%s]\n",
				validation.ObjStr(f, "priority"), validation.ObjStr(f, "row_id"),
				pyReprVal(validation.ObjAt(f, "tier")), pyReprVal(validation.ObjAt(f, "assertion_gap")),
				scalarStr(validation.ObjAt(f, "reason")), phrases)
		}
	}
}

// briefFindingLines emits the per-finding detail loops: materializable
// chains, gate deficits, pending memory recalls, unreachable findings,
// terminals and the E6 verification queue.
func (p *briefPrinter) briefFindingLines() {
	fs := validation.ObjAt(p.b, "findings")
	for _, ch := range objListAt(fs, "materializable_chains") {
		fmt.Fprintf(p.r.Out, "  materializable chain: %s\n",
			strings.Join(t31Strings(validation.ObjAt(ch, "members")), " -> "))
	}
	for _, d := range objListAt(fs, "gate_deficits") {
		fmt.Fprintf(p.r.Out, "  %s [%s %s]: %s\n", validation.ObjStr(d, "finding_id"),
			validation.ObjStr(d, "status"), validation.ObjStr(d, "level"), validation.ObjStr(d, "deficit"))
	}
	for _, fid := range t31Strings(validation.ObjAt(fs, "memory_recall_pending")) {
		fmt.Fprintf(p.r.Out, "  %s: memory recall pending — run `webv2 recall %s "+
			"--finding %s`\n", fid, p.c.CampaignID, fid)
	}
	for _, u := range objListAt(fs, "structurally_unreachable") {
		fmt.Fprintf(p.r.Out, "  %s stuck at %s (floor %s): %s\n",
			validation.ObjStr(u, "finding_id"), validation.ObjStr(u, "level"), validation.ObjStr(u, "floor"),
			strings.Join(t31Strings(validation.ObjAt(u, "missing")), "; "))
	}
	for _, t := range objListAt(p.b, "terminals") {
		fmt.Fprintf(p.r.Out, "  terminal -> %s: %s (capital $%s)\n",
			validation.ObjStr(t, "terminal_capability"),
			strings.Join(t31Strings(validation.ObjAt(t, "path")), " -> "),
			t31Comma0(validation.ObjAt(t, "capital_usd")))
	}
	for _, q := range objListAt(p.b, "independent_verification_queue") {
		tag := ""
		if t14Truthy(validation.ObjAt(q, "mandatory")) {
			tag = " [MANDATORY]"
		}
		fmt.Fprintf(p.r.Out, "  E6 queue: %s (at %s)%s\n", validation.ObjStr(q, "finding_id"),
			validation.ObjStr(q, "evidence_level"), tag)
	}
}

// briefBountyGates emits the per-finding bounty gate states, or the
// no-policy line when no policy is loaded.
func (p *briefPrinter) briefBountyGates() {
	if t14Truthy(validation.ObjAt(validation.ObjAt(p.b, "bounty"), "policy")) {
		for _, x := range objListAt(validation.ObjAt(p.b, "bounty"), "evaluated") {
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
			fmt.Fprintf(p.r.Out, "  gate: %s: %s\n", validation.ObjStr(x, "finding_id"), state)
		}
	} else {
		fmt.Fprintln(p.r.Out, "  gate: no policy loaded (run scope with a policy)")
	}
}

// briefCriticalHunt emits the critical-hunt block: prescreen matches, the
// fork-diff summary and the recency top list.
func (p *briefPrinter) briefCriticalHunt() {
	ch := asObjOrEmpty(validation.ObjAt(p.b, "critical_hunt"))
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
		fmt.Fprintln(p.r.Out, pl)
		for _, pair := range validation.ObjAt(ps, "near_matches").O {
			names := t31Strings(pair.V)
			if len(names) > 3 {
				names = names[:3]
			}
			fmt.Fprintf(p.r.Out, "        near-miss %s: %s\n", pair.K,
				strings.Join(names, ", "))
		}
	}
	if fd := validation.ObjAt(ch, "fork_diff"); t14Truthy(fd) {
		fmt.Fprintf(p.r.Out, "  fork-diff: %s\n", validation.ObjStr(fd, "summary"))
	}
	for _, rec := range objListAt(ch, "recency_top") {
		d := "never"
		if v := validation.ObjAt(rec, "days_ago"); v.Kind != validation.Null {
			d = pyReprVal(v) + "d ago"
		}
		fmt.Fprintf(p.r.Out, "  recency: %s %s  %s\n",
			pyFixed2(t31Float(validation.ObjAt(rec, "score"))), pyRight(d, 10),
			validation.ObjStr(rec, "path"))
	}
}

// briefHuntSignals emits the hunt's derived signals: detected amplifiers,
// boosted classes, SAST tool flags and the invariant-verification line.
func (p *briefPrinter) briefHuntSignals() {
	ch := asObjOrEmpty(validation.ObjAt(p.b, "critical_hunt"))
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
		fmt.Fprintln(p.r.Out, "  amplifiers: "+strings.Join(parts, ", "))
		for _, bc := range objListAt(amps, "boosted_classes") {
			fmt.Fprintf(p.r.Out, "        boosted %s: %s\n", validation.ObjStr(bc, "bug_class"),
				strings.Join(t31Strings(validation.ObjAt(bc, "amplifiers")), ", "))
		}
	}
	// G1 tool flags: present only when a finding carries detector
	// provenance (briefing.ChToolFlags returns Null otherwise).
	if tf := validation.ObjAt(ch, "tool_flags"); t14Truthy(tf) {
		fmt.Fprintln(p.r.Out, "TOOL FLAGS (SAST hypotheses)")
		fmt.Fprintf(p.r.Out, "  flags: %s, corroborated: %d\n",
			pyReprVal(validation.ObjAt(tf, "total")),
			len(t31Strings(validation.ObjAt(tf, "corroborated"))))
		census := []string{}
		for _, pair := range validation.ObjAt(tf, "by_verdict").O {
			census = append(census, pair.K+" "+pyReprVal(pair.V))
		}
		fmt.Fprintf(p.r.Out, "  by verdict: %s\n", strings.Join(census, ", "))
	}
	iv := asObjOrEmpty(validation.ObjAt(ch, "invariant_verification"))
	if t14Truthy(validation.ObjAt(iv, "total")) {
		unv := strings.Join(t31Strings(validation.ObjAt(iv, "unverified_model")), ", ")
		if unv == "" {
			unv = "none"
		}
		fmt.Fprintf(p.r.Out, "  invariants: %s total — unverified model-derived: "+
			"%s\n", pyReprVal(validation.ObjAt(iv, "total")), unv)
	}
}

// briefStaleArtifacts emits one line per stale artifact, with the reason
// wording pinned by the r9/r46 review notes.
func (p *briefPrinter) briefStaleArtifacts() {
	for _, s := range objListAt(validation.ObjAt(p.b, "critical_hunt"), "stale_artifacts") {
		// r9 (critic): the reason must tell the truth about the geometry.
		// "active pin moved" is only honest when a pin EXISTS to move.
		// r46: "computed before any pin existed" was a story the recorded
		// field cannot support — stale_snapshot == "unpinned" says the
		// artifact was hashed on the UNPINNED tree, which is equally true
		// when a pin exists but the artifact was computed outside it (the
		// critic's repro: `snap --exclude bulk`, then `index`, then
		// `brief` claimed no pin ever existed while one did). Say what the
		// field establishes: the workspace it hashed was not pinned.
		from, active := validation.ObjStr(s, "stale_snapshot"), p.snapshot
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
		fmt.Fprintf(p.r.Out, "  STALE %s (%s) — re-run: %s\n",
			validation.ObjStr(s, "artifact"), why, validation.ObjStr(s, "re_run"))
	}
}

// briefMemoryRelationsProblems emits pending memory decisions, the relations
// summary line (with drift suffix) and the problems block.
func (p *briefPrinter) briefMemoryRelationsProblems() {
	for _, m := range objListAt(p.b, "pending_memory") {
		fmt.Fprintf(p.r.Out, "  memory decision: %s (%s/%s)\n",
			validation.ObjStr(m, "memory_id"), validation.ObjStr(m, "kind"), validation.ObjStr(m, "status"))
	}
	rv := validation.ObjAt(p.b, "relations")
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
	fmt.Fprintln(p.r.Out, relLine)
	if problems := objListAt(p.b, "problems"); len(problems) > 0 {
		fmt.Fprintln(p.r.Out, "  problems:")
		for _, pr := range problems {
			fmt.Fprintf(p.r.Out, "    %s\n", scalarStr(pr))
		}
	}
}

// briefEconomics emits the cost/budget/yield line.
func (p *briefPrinter) briefEconomics() {
	ec := validation.ObjAt(validation.ObjAt(p.b, "economics"), "totals")
	y := validation.ObjAt(ec, "yield_usd_per_usd")
	budget := validation.ObjAt(validation.ObjAt(p.b, "economics"), "budget")
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
	fmt.Fprintf(p.r.Out, "  economics: cost $%s, confirmed %s / $%s, yield %s  "+
		"[%s]\n", t31Comma2(validation.ObjAt(ec, "total_cost_usd")),
		pyReprVal(validation.ObjAt(ec, "confirmed_findings")),
		t31Comma0(validation.ObjAt(ec, "confirmed_value_usd")), yieldTxt, budgetLine)
}

// briefIntegrity emits the integrity verdict (or the not-checked line) and,
// when present, the shared-store verdict.
func (p *briefPrinter) briefIntegrity() {
	integ := validation.ObjAt(p.b, "integrity")
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
		fmt.Fprintf(p.r.Out, "  integrity: %s — %d problem(s) (fast: event-log "+
			"chain; --deep for full re-hashes)\n", verdict, n)
		if shared := validation.ObjAt(integ, "shared_store"); t14Truthy(shared) {
			sv := "FAIL"
			if t14Truthy(validation.ObjAt(shared, "ok")) {
				sv = "PASS"
			}
			fmt.Fprintf(p.r.Out, "  shared store: %s (%s signatures, %s "+
				"memory rows)\n", sv, pyReprVal(validation.ObjAt(shared, "signature_count")),
				pyReprVal(validation.ObjAt(shared, "memory_count")))
		}
	} else {
		fmt.Fprintln(p.r.Out, "  integrity: not checked (use --deep)")
	}
}

// briefAttentionNextActions emits the attention block and the numbered
// next-actions list that closes the brief.
func (p *briefPrinter) briefAttentionNextActions() {
	att := asObjOrEmpty(validation.ObjAt(p.b, "attention"))
	if lines := objListAt(att, "lines"); len(lines) > 0 {
		fmt.Fprintln(p.r.Out, "  attention:")
		for _, l := range lines {
			fmt.Fprintf(p.r.Out, "    %s\n", scalarStr(l))
		}
	}
	fmt.Fprintln(p.r.Out, "next actions:")
	for i, a := range objListAt(p.b, "next_actions") {
		fmt.Fprintf(p.r.Out, "  %d. %s\n", i+1, scalarStr(a))
	}
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
