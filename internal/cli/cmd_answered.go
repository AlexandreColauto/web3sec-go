package cli

// cmd_answered: `webv2 answered <campaign> <priority> [priority ...] <status>
// [--reason R] [--reason-all R] [--ref R] [--families F] [--symmetry S]
// [--anchor A] [--passes V] [--interim S] [--finding F] [--actor A]` — set
// plan priorities' (Q-*) or one lens entry's
// (L-*) status WITH closure provenance. cli.py cmd_answered verbatim for the
// single-priority shape: closing statuses REQUIRE --reason, L-* ids route to
// planner.mark_lens, and a probe row's disposition must name its anchor. The
// batch shape (several Q-* priorities, one status for all rows) requires
// --reason-all and runs every row's gates before any mutation lands.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

const t14AnsweredUsage = `usage: webv2 answered [-h] [--reason REASON] [--reason-all REASON] [--ref REF]
                      [--families FAMILIES] [--symmetry SYMMETRY]
                      [--reconcile SPEC]
                      [--anchor ANCHOR] [--passes VALUE] [--interim STATEMENT]
                      [--finding FINDING] [--actor ACTOR]
                      [--override-dismissal] [--override-reason OVERRIDE_REASON]
                      campaign priority [priority ...]
                      {open,assigned,answered,not-applicable,deprioritized,blocked}
`

const t14AnsweredHelp = `usage: webv2 answered [-h] [--reason REASON] [--reason-all REASON] [--ref REF]
                      [--families FAMILIES] [--symmetry SYMMETRY]
                      [--reconcile SPEC]
                      [--anchor ANCHOR] [--passes VALUE] [--interim STATEMENT]
                      [--finding FINDING] [--actor ACTOR]
                      [--override-dismissal] [--override-reason OVERRIDE_REASON]
                      campaign priority [priority ...]
                      {open,assigned,answered,not-applicable,deprioritized,blocked}

positional arguments:
  campaign
  priority              one or more plan priorities (Q-*); one status applies
                        to all rows (a mixed-status batch is not supported).
                        A single L-* lens still closes one at a time.
  {open,assigned,answered,not-applicable,deprioritized,blocked}

options:
  -h, --help            show this help message and exit
  --reason REASON       why (required for closing statuses)
  --reason-all REASON   why for every row of a batch close (required to close
                        several priorities at once; --reason names a single
                        closure, --reason-all rides every row)
  --ref REF             evidence ref: finding/exec/artifact id or file#L
                        anchor
  --families FAMILIES   comma-separated lens families attested as checked
                        (required to close an L-* lens)
  --symmetry SYMMETRY   L-04 only: family=primitive[|primitive];... quoting
                        the token-movement primitive per seeded family
  --reconcile SPEC      L-04 only (FIX-6): ROWID=VALUE;... reconciling every
                        funding-mismatch / member-disagreement divergence row
                        this attestation covers. VALUE is a filed finding id
                        (F-<12 hex digits>) or per-member cites
                        primitive:Symbol#L<line>|... (Symbol must appear on
                        the row's own surface entry). Consumed only by an L-04
                        closure — refused on a Q-* priority and on a
                        non-closing lens status
  --anchor ANCHOR       probe rows only: the field this disposition claims is
                        safe — one of the row's probe's own anchor enum
                        (anchors: accumulator, actor, asserter, base,
                        companion, concept, consumer, cursor, custody, guard,
                        invariant, plain, rounded, safety, sentinel, sibling,
                        stranded_entry). Required to disposition a probe row;
                        the value recorded is the row's real anchor. Refused
                        on an L-* lens route (a lens entry is not a probe
                        row)
  --passes VALUE       sentinel-guarded rows only: the value that passes the
                        check (the row's guard is a zero-check that cannot
                        express the truth of the value it guards). Required to
                        close a sentinel-form row without an override; recorded
                        on the priority as its "passes" field. The value is
                        accepted only when it is checkable: it must name a
                        symbol from the row's own surface entry, or be a
                        concrete literal (a decimal integer, a hex number or
                        Ethereum-style address 0x…, bytes32(0x…), a boolean,
                        or a quoted string); prose like "TBD" is refused.
                        Refused on an L-* lens route (a lens entry has no
                        guard)
  --interim STATEMENT  tier-0 rows anchored on asserter only (FIX-5): the
                        deferred-consequence statement pricing the interim
                        window between the row's consumer and the asserter
                        that finally applies the check. Must cite a symbol
                        from the row's own surface entry; recorded on the
                        priority as its "interim" field. Validated on every
                        closure: a statement shorter than 3 non-blank
                        characters is refused (the flag is never inert).
                        Refused on an L-* lens route (a lens entry has no
                        probe row to price)
  --finding FINDING    the other deferred-consequence exit: the id of a filed
                        finding (F-<12 hex digits>) that records the interim
                        window; recorded on the priority as its
                        "interim_finding" field. Validated on every closure:
                        the id must name a filed, LIVE finding (a terminal
                        one — DISPROVED, OUT_OF_SCOPE, INFORMATIONAL,
                        DUPLICATE, SUPERSEDED — is refused), so the flag can
                        never ride a ghost citation. Refused on an L-* lens
                        route (a lens entry has no probe row to price)
  --actor ACTOR         who is closing it (default: cli)
  --override-dismissal
                        B4: override the dismissal gate on a high-risk row
                        (tier 0 / gap >= 3) whose reason uses dismissal
                        vocabulary — requires --override-reason; logged as
                        probe.dismissal_overridden and listed in the report
  --override-reason OVERRIDE_REASON
                        the override justification (required with
                        --override-dismissal)
`

// anchorHelp renders the per-probe anchor contract into the answered help
// text: dispositioning cost one failure per row type because the required
// anchor shapes lived in the registry, not the help (C-12f17fd555 §8c). The
// table is derived from the same registry the gate enforces
// (probes.AnchorAllowed over probes.AnchorEnum), so help and enforcement
// cannot drift; probes and anchors render in sorted order so the block is
// deterministic and pinned by a table test.
func anchorHelp() string {
	enum := probes.AnchorEnum()
	ids := probes.ProbeIDs()
	sort.Strings(ids)
	var b strings.Builder
	b.WriteString("  per-probe anchors (the anchor must be one the probe produced):\n")
	for _, p := range ids {
		names := make([]string, 0, len(enum))
		for _, a := range enum {
			if probes.AnchorAllowed(p, a) {
				names = append(names, a)
			}
		}
		fmt.Fprintf(&b, "    %s: --anchor %s\n", p, strings.Join(names, "|"))
	}
	return b.String()
}

// t14AnsweredRefConventions is the row-type ref contract: the shapes the
// refusal messages imply but the help never named (C-12f17fd555 §8c). The
// row's own surface entry stays the source of truth — `webv2 probes <C> list
// --all` prints it.
const t14AnsweredRefConventions = `  row-type ref conventions (--ref carries the shape the row printed):
    assertion-strength       --ref <consumer contract>#L<line>
    trust-assumption         --ref <actor name>
    custody-primitive        --ref <primitive verb>, or --anchor base with
                             --ref <contract>#L<line>
    short-circuitable-guard  --ref the guard expression as printed on the row
  --passes takes a literal, not prose: an integer, 0x…, an address,
  bytes32(0x…), a bool or a quoted string — or a symbol from the row's own
  surface entry.
`

// answeredArgs is the parsed command line.
type answeredArgs struct {
	campaign          string
	priority          string
	priorities        []string
	status            string
	reason            *string
	reasonAll         *string
	ref               *string
	families          *string
	symmetry          *string
	reconcile         *string
	anchor            *string
	passes            *string
	interim           *string
	finding           *string
	actor             string
	overrideDismissal bool
	overrideReason    *string
}

var answeredStatuses = []string{"open", "assigned", "answered",
	"not-applicable", "deprioritized", "blocked"}

func runAnswered(root string, args []string, r *Runner) error {
	a, err := parseAnswered(args, r)
	if err != nil || a == nil {
		return err
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	if !t14Exists(planPath) {
		return t14ExitErr(2, "no campaign plan loaded (webv2 plan %s)\n", c.CampaignID)
	}
	closing := a.status == "answered" || a.status == "not-applicable" ||
		a.status == "deprioritized" || a.status == "blocked"
	if len(a.priorities) > 1 || a.reasonAll != nil {
		return answeredBatch(c, a, closing, r)
	}
	if closing && (a.reason == nil || strings.TrimSpace(*a.reason) == "") {
		return t14ExitErr(2, "answered: %s requires --reason (why). "+
			"Pass --ref too when the answer rests on evidence "+
			"(finding/exec/artifact/file#L).\n", validation.PyReprStr(a.status))
	}
	if strings.HasPrefix(a.priority, "L-") {
		return answeredLens(c, a, closing, r)
	}
	return answeredPriority(c, a, closing, r)
}

// parseAnswered is the argparse layer. A nil *answeredArgs with a nil error
// means --help was printed.
func parseAnswered(args []string, r *Runner) (*answeredArgs, error) {
	a := &answeredArgs{}
	var pos []string
	for i := 0; i < len(args); i++ {
		consumed, done, handled, err := answeredFlag(args, i, a, r)
		if err != nil {
			return nil, err
		}
		if done {
			return nil, nil
		}
		if handled {
			i += consumed
			continue
		}
		pos = append(pos, args[i])
	}
	return finishAnswered(a, pos)
}

// answeredFlag consumes one option (and its value). done means --help was
// printed; handled=false means the argument is positional. argparse order is
// preserved: the exact-match value flags first, then --actor and the
// --flag=value spellings, then an unrecognized option.
func answeredFlag(args []string, i int, a *answeredArgs,
	r *Runner) (consumed int, done, handled bool, err error) {
	arg := args[i]
	if arg == "-h" || arg == "--help" {
		fmt.Fprint(r.Out, t14AnsweredHelp+anchorHelp()+t14AnsweredRefConventions)
		return 0, true, true, nil
	}
	// FIX-C: an empty or whitespace-only --reconcile value is refused at the
	// parse layer, the way a missing argument is — the same
	// `argument --reconcile: ...` argparse shape --of uses for a missing
	// value. The blank spec parses to zero records, which would pass the
	// coverage half of the FIX-6 gate on the stored reconciliation and then
	// overwrite it with nothing (the data-loss wart this refuses).
	if v, ok := answeredValue(args, i, "--reconcile"); ok &&
		strings.TrimSpace(v) == "" {
		return 0, false, true, t14ArgparseErr(t14AnsweredUsage,
			"answered", "argument --reconcile: an empty SPEC would "+
				"overwrite the stored reconciliation with zero records — "+
				"pass 'ROWID=VALUE;...' or drop --reconcile")
	}
	if arg == "--actor" {
		if i+1 >= len(args) {
			return 0, false, true, t14ArgparseErr(t14AnsweredUsage,
				"answered", "argument --actor: expected one argument")
		}
		a.actor = args[i+1]
		return 1, false, true, nil
	}
	if arg == "--override-dismissal" {
		a.overrideDismissal = true
		return 0, false, true, nil
	}
	// --passes takes a VALUE, so it carries the house looksLikeOption guard
	// inline: `--passes --anchor consumer` is a missing value, never a value
	// named "--anchor". --interim and --finding (FIX-5) take values the same
	// way — a statement and a finding id are never spelled like options.
	if arg == "--passes" && i+1 < len(args) && !looksLikeOption(args[i+1]) {
		v := args[i+1]
		a.passes = &v
		return 1, false, true, nil
	}
	if arg == "--interim" && i+1 < len(args) && !looksLikeOption(args[i+1]) {
		v := args[i+1]
		a.interim = &v
		return 1, false, true, nil
	}
	if arg == "--finding" && i+1 < len(args) && !looksLikeOption(args[i+1]) {
		v := args[i+1]
		a.finding = &v
		return 1, false, true, nil
	}
	if dst, name := answeredDst(a, arg); dst != nil {
		if i+1 >= len(args) {
			return 0, false, true, t14ArgparseErr(t14AnsweredUsage,
				"answered", "argument --%s: expected one argument", name)
		}
		v := args[i+1]
		*dst = &v
		return 1, false, true, nil
	}
	if handled, err := answeredEq(a, arg); handled || err != nil {
		return 0, false, handled, err
	}
	if arg == "--passes" {
		return 0, false, true, t14ArgparseErr(t14AnsweredUsage,
			"answered", "argument --passes: expected one argument")
	}
	if arg == "--interim" {
		return 0, false, true, t14ArgparseErr(t14AnsweredUsage,
			"answered", "argument --interim: expected one argument")
	}
	if arg == "--finding" {
		return 0, false, true, t14ArgparseErr(t14AnsweredUsage,
			"answered", "argument --finding: expected one argument")
	}
	if strings.HasPrefix(arg, "-") {
		return 0, false, true, t14Unrecognized(arg)
	}
	return 0, false, false, nil
}

// answeredValue reports the value a value-taking flag would consume at
// position i: the next token for the space-separated form, the text after
// '=' for the --flag= form. ok is false when the argument is not that flag
// in either spelling, or when the space-separated form carries no value at
// all (the missing-argument error answers that shape, not this one).
func answeredValue(args []string, i int, name string) (string, bool) {
	arg := args[i]
	if arg == name {
		if i+1 < len(args) {
			return args[i+1], true
		}
		return "", false
	}
	if strings.HasPrefix(arg, name+"=") {
		return strings.TrimPrefix(arg, name+"="), true
	}
	return "", false
}

// answeredDst maps a value-taking flag (space-separated form) to its field.
func answeredDst(a *answeredArgs, arg string) (**string, string) {
	switch arg {
	case "--reason":
		return &a.reason, "reason"
	case "--reason-all":
		return &a.reasonAll, "reason-all"
	case "--ref":
		return &a.ref, "ref"
	case "--families":
		return &a.families, "families"
	case "--symmetry":
		return &a.symmetry, "symmetry"
	case "--reconcile":
		return &a.reconcile, "reconcile"
	case "--anchor":
		return &a.anchor, "anchor"
	case "--override-reason":
		return &a.overrideReason, "override-reason"
	}
	return nil, ""
}

// answeredEq handles the --flag=value spellings (--actor= included).
func answeredEq(a *answeredArgs, arg string) (bool, error) {
	for _, f := range []struct {
		name string
		dst  **string
	}{
		{"--reason", &a.reason}, {"--reason-all", &a.reasonAll},
		{"--ref", &a.ref},
		{"--families", &a.families}, {"--symmetry", &a.symmetry},
		{"--reconcile", &a.reconcile},
		{"--anchor", &a.anchor}, {"--passes", &a.passes},
		{"--interim", &a.interim}, {"--finding", &a.finding},
		{"--override-reason", &a.overrideReason},
	} {
		if strings.HasPrefix(arg, f.name+"=") {
			v := strings.TrimPrefix(arg, f.name+"=")
			*f.dst = &v
			return true, nil
		}
	}
	if strings.HasPrefix(arg, "--actor=") {
		a.actor = strings.TrimPrefix(arg, "--actor=")
		return true, nil
	}
	return false, nil
}

// finishAnswered enforces the required positionals and the status enum.
// The status is the LAST positional; everything between the campaign and
// the status is a priority, so `answered C Q-001 answered` keeps its old
// shape while `answered C P1 P2 P3 status` closes a batch.
func finishAnswered(a *answeredArgs, pos []string) (*answeredArgs, error) {
	if len(pos) == 0 {
		return nil, t14ArgparseErr(t14AnsweredUsage, "answered",
			"the following arguments are required: %s",
			"campaign, priority, status")
	}
	if len(pos) == 1 {
		return nil, t14ArgparseErr(t14AnsweredUsage, "answered",
			"the following arguments are required: %s", "priority, status")
	}
	if len(pos) == 2 {
		// `answered C Q-001` names a priority but no status;
		// `answered C answered` names a status but no row.
		if t14InList(pos[1], answeredStatuses) {
			return nil, t14ExitErr(2, "answered: at least one "+
				"priority is required (got campaign %s and status "+
				"%s, no row)\n", validation.PyReprStr(pos[0]),
				validation.PyReprStr(pos[1]))
		}
		return nil, t14ArgparseErr(t14AnsweredUsage, "answered",
			"the following arguments are required: %s", "status")
	}
	a.campaign = pos[0]
	a.status = pos[len(pos)-1]
	a.priorities = append([]string(nil), pos[1:len(pos)-1]...)
	a.priority = a.priorities[0]
	if !t14InList(a.status, answeredStatuses) {
		return nil, t14ArgparseErr(t14AnsweredUsage, "answered",
			"argument status: invalid choice: %s (choose from %s)",
			validation.PyReprStr(a.status),
			"'"+strings.Join(answeredStatuses, "', '")+"'")
	}
	return a, nil
}

// answeredLens is the L-* route: the plan's lens entries, same verb, same
// reason enforcement, plus the family/symmetry attestations.
func answeredLens(c *state.Campaign, a *answeredArgs, closing bool,
	r *Runner) error {
	// Round-3 chief item 1: the probe-row flags are inert on a lens route —
	// a lens entry has no probe row to disposition, no guard to satisfy and
	// no interim window to price, so any of them here would be silently
	// dropped while the help text claims validation on every closure.
	// Refused before the recon gate, the way the reconcile shape refusals
	// are.
	for _, f := range []struct {
		flag, what, why string
		val             *string
	}{
		{"--finding", "records the interim window of a Q-* probe row on " +
			"a filed finding", "there is no probe row to price", a.finding},
		{"--interim", "prices a Q-* probe row's interim window with a " +
			"statement", "there is no probe row to price", a.interim},
		{"--passes", "records the passing value of a sentinel-guarded " +
			"Q-* probe row", "there is no guard to satisfy", a.passes},
		{"--anchor", "dispositions a Q-* probe row by naming the field " +
			"it claims is safe", "there is no probe row to disposition",
			a.anchor},
	} {
		if f.val != nil {
			return t14ExitErr(2, "answered: %s %s — %s is an L-* lens "+
				"route, so %s: drop %s\n", f.flag, f.what,
				validation.PyReprStr(a.priority), f.why, f.flag)
		}
	}
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	target, ok := t14FindByID(t14List(plan, "lenses"), a.priority)
	if !ok {
		return t14ExitErr(2, "answered: unknown lens %s\n", a.priority)
	}
	fams := splitFamilies(a.families)
	seeded := t14Strings(t14List(target, "families"))
	if closing {
		if err := checkLensFamilies(a, fams, seeded); err != nil {
			return err
		}
	}
	sym, err := lensSymmetry(a, target, seeded, closing)
	if err != nil {
		return err
	}
	// FIX-6: the divergence reconciliation rides the attestation. A malformed
	// spec is refused here — the gate inside mark_lens would otherwise
	// diagnose it per-row, and the shape error is the one the operator can
	// fix without reading the surface. The flag only means something to the
	// lens that owns the divergence rows: anything else is refused, not
	// silently recorded on an entry that reconciles nothing.
	var recs *[]validation.Value
	if a.reconcile != nil {
		if validation.ObjStr(target, "lens") != "primitive-symmetry" {
			return t14ExitErr(2, "answered: --reconcile reconciles the "+
				"divergence rows of a primitive-symmetry lens — %s is not "+
				"one, so there is nothing to reconcile: drop --reconcile\n",
				validation.PyReprStr(a.priority))
		}
		// Round-3 chief item 2: the reconciliation is part of the closing
		// attestation — markLensEntry consumes the spec only on a closing
		// status, so a non-closing one would ignore it (and drop the stored
		// reconciliation outright). Refused, naming the L-04 closing route.
		if !closing {
			return t14ExitErr(2, "answered: --reconcile is consumed only "+
				"by an L-04 primitive-symmetry lens closure — %s with "+
				"status %s is not a closure, so there is nothing to "+
				"reconcile: drop --reconcile\n",
				validation.PyReprStr(a.priority),
				validation.PyReprStr(a.status))
		}
		parsed, err := planner.ParseReconcile(a.reconcile)
		if err != nil {
			return t14ExitErr(2, "answered: %s\n", err)
		}
		recs = &parsed
	}
	actor := a.actor
	if actor == "" {
		actor = "cli"
	}
	updated, err := planner.MarkLens(c, plan, a.priority, a.status,
		planner.LensOpts{Reason: a.reason, Ref: a.ref, Actor: actor,
			FamiliesChecked: famPtr(fams, a.families), Symmetry: sym,
			Reconcile: recs})
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	printAnsweredLens(c, a, updated, closing, r)
	return nil
}

// splitFamilies is the Python list comprehension over --families.
func splitFamilies(families *string) []string {
	if families == nil {
		return nil
	}
	var out []string
	for _, f := range strings.Split(*families, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// checkLensFamilies enforces the attestation: every seeded family must be
// named, unless the lens is degenerate and the operator attests none apply.
func checkLensFamilies(a *answeredArgs, fams, seeded []string) error {
	checked := map[string]struct{}{}
	for _, f := range fams {
		checked[f] = struct{}{}
	}
	var missing []string
	for _, f := range seeded {
		if _, ok := checked[f]; !ok {
			missing = append(missing, f)
		}
	}
	degenerate := len(seeded) == 0 || (len(seeded) == 1 && seeded[0] == "protocol")
	_, noneApplicable := checked["none-applicable"]
	if len(missing) > 0 && !(degenerate && noneApplicable) {
		return t14ExitErr(2, "answered: %s has unattested families "+
			"(missing: %s). Pass --families %s (or attest none apply) "+
			"with --reason (why).\n", a.priority,
			strings.Join(missing, ", "), strings.Join(missing, ","))
	}
	return nil
}

// lensSymmetry parses and validates --symmetry for a primitive-symmetry lens.
func lensSymmetry(a *answeredArgs, target validation.Value, seeded []string,
	closing bool) (*[]validation.Value, error) {
	if validation.ObjStr(target, "lens") != "primitive-symmetry" || !closing ||
		len(seeded) == 0 || (len(seeded) == 1 && seeded[0] == "protocol") {
		return nil, nil
	}
	parsed := parseSymmetry(a.symmetry)
	have := map[string]int{}
	for _, s := range parsed {
		n := 0
		for _, p := range t14List(s, "primitives").A {
			if strings.TrimSpace(scalarStr(p)) != "" {
				n++
			}
		}
		have[validation.ObjStr(s, "family")] = n
	}
	var missing []string
	for _, f := range seeded {
		if have[f] == 0 {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		parts := make([]string, 0, len(missing))
		for _, f := range missing {
			parts = append(parts, f+"=burn")
		}
		return nil, t14ExitErr(2, "answered: %s has unattested symmetry "+
			"primitives (missing: %s). Pass --symmetry '%s' "+
			"(family=primitive[|primitive];...) with --reason (why).\n",
			a.priority, strings.Join(missing, ", "), strings.Join(parts, ";"))
	}
	return &parsed, nil
}

// printAnsweredLens reports the closure and, for a closing lens, the probe
// surface rows it dispositioned.
func printAnsweredLens(c *state.Campaign, a *answeredArgs,
	updated validation.Value, closing bool, r *Runner) {
	lens, _ := t14FindByID(t14List(updated, "lenses"), a.priority)
	ref := ""
	if cr := validation.ObjAt(lens, "closed_ref"); t14Truthy(cr) {
		ref = " (ref: " + scalarStr(cr) + ")"
	}
	fmt.Fprintf(r.Out, "%s: status -> %s%s\n", a.priority, a.status, ref)
	if closing {
		printProbeClosure(c, updated, map[string]struct{}{
			validation.ObjStr(lens, "lens"): {}}, r.Out)
	}
}

// answeredPriority is the Q-* route.
func answeredPriority(c *state.Campaign, a *answeredArgs, closing bool,
	r *Runner) error {
	// Round-3 chief item 2: --reconcile is consumed only by the L-04
	// primitive-symmetry lens closure — on a Q-* priority it would exit 0
	// silently ignoring the spec. Refused, naming the route that does
	// consume it.
	if a.reconcile != nil {
		return t14ExitErr(2, "answered: --reconcile reconciles the "+
			"divergence rows of an L-04 primitive-symmetry lens closure — "+
			"%s is a Q-* priority, so there is nothing to reconcile: drop "+
			"--reconcile\n", validation.PyReprStr(a.priority))
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	plan, err := validation.ReadJson(planPath)
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	target, ok := t14FindByID(t14List(plan, "priorities"), a.priority)
	if !ok {
		return t14ExitErr(2, "answered failed: no priority %s in the "+
			"campaign plan\n", validation.PyReprStr(a.priority))
	}
	probe := validation.ObjAt(target, "probe")
	if probe.Kind == validation.Obj &&
		t14InList(a.status, planner.ProbeRowDispositioned) {
		if err := checkProbeAnchor(c, a, target, probe); err != nil {
			return err
		}
	}
	actor := a.actor
	if actor == "" {
		actor = "cli"
	}
	overrideLogged := false
	skipNotice := ""
	updated, err := planner.MarkAnswered(c, plan, a.priority, a.status,
		planner.AnsweredOpts{Reason: a.reason, Ref: a.ref, Actor: actor,
			Anchor: a.anchor, PassesValue: a.passes, Interim: a.interim,
			Finding:           a.finding,
			OverrideDismissal: a.overrideDismissal,
			OverrideReason:    a.overrideReason, OverrideLogged: &overrideLogged,
			SkipNotice: &skipNotice})
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	if skipNotice != "" {
		// FIX-3: a gate that stood down says so — on stderr, so the
		// closure's success line never quietly absorbs it.
		fmt.Fprintln(r.Err, skipNotice)
	}
	if overrideLogged {
		// The override is a decision, not a formality: say so where the
		// operator can see it, and name the record it left behind.
		fmt.Fprintf(r.Out, "  dismissal overridden: %s logged as "+
			"probe.dismissal_overridden (actor %s)\n", a.priority, actor)
	}
	p, _ := t14FindByID(t14List(updated, "priorities"), a.priority)
	ref := ""
	if cr := validation.ObjAt(p, "closed_ref"); t14Truthy(cr) {
		ref = " (ref: " + scalarStr(cr) + ")"
	}
	if anchor := validation.ObjAt(validation.ObjAt(p, "probe"), "anchor"); t14Truthy(anchor) {
		ref += " [anchor " + validation.ObjStr(anchor, "field") + "]"
	}
	fmt.Fprintf(r.Out, "%s: status -> %s%s\n", a.priority, a.status, ref)
	if closing && validation.ObjAt(p, "probe").Kind == validation.Obj {
		lensName := ""
		if spec, ok := planner.PB().Probes[validation.ObjStr(probe, "probe_id")]; ok {
			lensName = spec.Lens
		}
		var lensSet map[string]struct{}
		if lensName != "" {
			lensSet = map[string]struct{}{lensName: {}}
		}
		printProbeClosure(c, updated, lensSet, r.Out)
	}
	return nil
}

// answeredBatch is the Q-* batch route: one status applies to every row (a
// mixed-status batch is not supported), --reason-all rides every row, and
// every row's gates run before any mutation lands — the first failure names
// its row and nothing is written. Lenses close one at a time, never here.
func answeredBatch(c *state.Campaign, a *answeredArgs, closing bool,
	r *Runner) error {
	// Round-3 chief item 2: the batch is a Q-* route — --reconcile has no
	// row to reconcile here and would be silently ignored.
	if a.reconcile != nil {
		return t14ExitErr(2, "answered: --reconcile reconciles the "+
			"divergence rows of an L-04 primitive-symmetry lens closure — "+
			"%s is a Q-* priority, so there is nothing to reconcile: drop "+
			"--reconcile\n", validation.PyReprStr(a.priorities[0]))
	}
	for _, pid := range a.priorities {
		if strings.HasPrefix(pid, "L-") {
			return t14ExitErr(2, "answered: batch close supports Q-* "+
				"priorities only — close lenses one at a time (got %s)\n",
				pid)
		}
	}
	var reason *string
	switch {
	case a.reasonAll != nil:
		reason = a.reasonAll
	case a.reason != nil:
		if len(a.priorities) > 1 {
			return t14ExitErr(2, "answered: closing %d priorities "+
				"needs --reason-all (why) — --reason names a single "+
				"closure, --reason-all rides every row.\n",
				len(a.priorities))
		}
		reason = a.reason
	}
	if closing && (reason == nil || strings.TrimSpace(*reason) == "") {
		return t14ExitErr(2, "answered: %s requires --reason-all (why). "+
			"Pass --ref too when the answer rests on evidence "+
			"(finding/exec/artifact/file#L).\n", validation.PyReprStr(a.status))
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	plan, err := validation.ReadJson(planPath)
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	actor := a.actor
	if actor == "" {
		actor = "cli"
	}
	reasonStr := ""
	if reason != nil {
		reasonStr = *reason
	}
	rows := make([]planner.AnsweredRow, len(a.priorities))
	logged := make([]bool, len(a.priorities))
	notices := make([]string, len(a.priorities))
	for i, pid := range a.priorities {
		rows[i] = planner.AnsweredRow{PriorityID: pid, Outcome: a.status,
			Opts: planner.AnsweredOpts{Ref: a.ref, Actor: actor,
				Anchor: a.anchor, PassesValue: a.passes, Interim: a.interim,
				Finding:           a.finding,
				OverrideDismissal: a.overrideDismissal,
				OverrideReason:    a.overrideReason,
				OverrideLogged:    &logged[i], SkipNotice: &notices[i]}}
	}
	updated, err := planner.MarkAnsweredBatch(c, plan, rows, reasonStr)
	if err != nil {
		// The batch error already names the row
		// ("answered: row 2 (Q-005): ..."), so it prints as-is.
		return t14ExitErr(2, "%s\n", err)
	}
	for i, pid := range a.priorities {
		if notices[i] != "" {
			// FIX-3: a gate that stood down says so — on stderr, so the
			// closure's success line never quietly absorbs it.
			fmt.Fprintln(r.Err, notices[i])
		}
		if logged[i] {
			fmt.Fprintf(r.Out, "  dismissal overridden: %s logged as "+
				"probe.dismissal_overridden (actor %s)\n", pid, actor)
		}
		p, _ := t14FindByID(t14List(updated, "priorities"), pid)
		ref := ""
		if cr := validation.ObjAt(p, "closed_ref"); t14Truthy(cr) {
			ref = " (ref: " + scalarStr(cr) + ")"
		}
		if anchor := validation.ObjAt(validation.ObjAt(p, "probe"), "anchor"); t14Truthy(anchor) {
			ref += " [anchor " + validation.ObjStr(anchor, "field") + "]"
		}
		fmt.Fprintf(r.Out, "%s: status -> %s%s\n", pid, a.status, ref)
	}
	return nil
}

// checkProbeAnchor is the A4 operator-facing requirement: a probe closure
// without an anchor is not a disposition, it is a shrug.
func checkProbeAnchor(c *state.Campaign, a *answeredArgs, target,
	probe validation.Value) error {
	row, err := probeSurfaceRow(c, target)
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	if row == nil {
		return t14ExitErr(2, "answered: probe row %s is not in the current "+
			"surface — re-run `webv2 probes %s run --emit`\n",
			validation.PyReprStr(validation.ObjStr(probe, "row_id")), c.CampaignID)
	}
	var allowed []string
	if spec, ok := planner.PB().Probes[validation.ObjStr(*row, "probe")]; ok &&
		spec.Anchors != nil {
		allowed = *spec.Anchors
	}
	if a.anchor == nil || *a.anchor == "" {
		return t14ExitErr(2, "answered: %s is probe row %s — a probe "+
			"disposition must name the field it claims is safe: "+
			"--anchor <field> (one of %s)\n", a.priority,
			validation.ObjStr(probe, "row_id"), strings.Join(allowed, ", "))
	}
	if !t14InList(*a.anchor, allowed) {
		return t14ExitErr(2, "answered: --anchor %s is not produced by "+
			"probe %s; allowed: %s\n", validation.PyReprStr(*a.anchor),
			validation.PyReprStr(validation.ObjStr(*row, "probe")),
			strings.Join(allowed, ", "))
	}
	return nil
}

// probeSurfaceRow is cli.py's _probe_surface_row: the surface row a probe
// priority points at, or nil when the campaign has no surface / the row is
// absent. The probes module is unported (P3), so CampaignSurface is the
// "feature absent" reader and this is nil in practice.
func probeSurfaceRow(c *state.Campaign,
	target validation.Value) (*validation.Value, error) {
	surface, err := planner.PB().CampaignSurface(c)
	if err != nil || surface == nil {
		return nil, err
	}
	rid := validation.ObjStr(validation.ObjAt(target, "probe"), "row_id")
	for _, row := range t14List(*surface, "rows").A {
		if validation.ObjStr(row, "row_id") == rid {
			row := row
			return &row, nil
		}
	}
	return nil, nil
}

// printProbeClosure is cli.py's _print_probe_closure: the probe clause of a
// lens as a sentence with counts (only_closed=True). With the probes module
// unported there is no surface, so divergence_status emits no probe entry and
// this prints nothing — exactly what Python prints for a campaign with no
// probe artifact.
func printProbeClosure(c *state.Campaign, plan validation.Value,
	lensNames map[string]struct{}, stdout interface{ Write([]byte) (int, error) }) {
	div, err := planner.DivergenceStatusFor(c, plan, nil)
	if err != nil {
		return
	}
	for _, entry := range t14List(div, "lenses").A {
		probe := validation.ObjAt(entry, "probe")
		if probe.Kind != validation.Obj || !t14Truthy(validation.ObjAt(probe, "message")) {
			continue
		}
		if lensNames != nil {
			_, a := lensNames[validation.ObjStr(entry, "lens")]
			_, b := lensNames[validation.ObjStr(entry, "id")]
			if !a && !b {
				continue
			}
		}
		if !t14Truthy(validation.ObjAt(probe, "closed")) {
			continue
		}
		fmt.Fprintf(stdout, "%s\n", validation.ObjStr(probe, "message"))
	}
}

// parseSymmetry is _parse_symmetry: "family=primitive[|primitive];...".
func parseSymmetry(spec *string) []validation.Value {
	out := []validation.Value{}
	if spec == nil || *spec == "" {
		return out
	}
	for _, part := range strings.Split(*spec, ";") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		fam, prims, _ := strings.Cut(part, "=")
		var list []validation.Value
		for _, p := range strings.Split(prims, "|") {
			if p = strings.TrimSpace(p); p != "" {
				list = append(list, validation.VStr(p))
			}
		}
		out = append(out, validation.VObj(
			validation.KV{K: "family", V: validation.VStr(strings.TrimSpace(fam))},
			validation.KV{K: "primitives", V: validation.VArr(list...)},
		))
	}
	return out
}

// famPtr renders cli.py's `families_checked=fams`: None when --families was
// absent, the (possibly empty) list otherwise.
func famPtr(fams []string, given *string) *[]string {
	if given == nil {
		return nil
	}
	return &fams
}

// t14FindByID is next((x for x in items if x["id"] == id), None).
func t14FindByID(items validation.Value, id string) (validation.Value, bool) {
	for _, it := range items.A {
		if validation.ObjStr(it, "id") == id {
			return it, true
		}
	}
	return validation.VNull(), false
}

// t14Strings renders a list value as Go strings.
func t14Strings(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, it := range v.A {
		out = append(out, scalarStr(it))
	}
	return out
}

// t14InList is `x in items`.
func t14InList(x string, items []string) bool {
	for _, it := range items {
		if it == x {
			return true
		}
	}
	return false
}

func init() {
	register(command{ord: 35, name: "answered",
		line: `answered <campaign> <priority> [priority ...] <status> [--reason R]
                        [--reason-all R] [--ref R]
                        close/open plan priorities or a lens with provenance`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runAnswered(root, args, r)
			})
		}})
}
