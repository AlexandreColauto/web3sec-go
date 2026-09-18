package cli

// cmd_answered_args: answered's argparse layer — usage/help text, the
// anchor/ref-convention help blocks, the parsed args struct and the
// token loop (moved verbatim from cmd_answered.go, which keeps the
// concern's documentation, the entry point and the registration).
import (
	"fmt"
	"sort"
	"strings"
	"websec/internal/probes"
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
