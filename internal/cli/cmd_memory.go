package cli

// cmd_memory: `webv2 memory <campaign> [--approve MEM] [--by NAME]` — list
// the campaign's learning memory, or record a human approval (cli.py
// cmd_memory verbatim).
//
// D5 (2026-09-10) adds the two flags that close the learning stage's reachable
// surface, on THIS verb rather than as new top-level verbs: `--reflect TEXT`
// (the only writer of learnings.jsonl — learning.ReflectionEntry had no caller
// outside its own test, so the completion proof's "no reflection entry" item
// could never be cleared by any command) and `--reject MEM --reason TEXT`
// (the inbox could only approve; a wrong candidate stayed pending forever).
//
// B5b/D6: neither path may end in silence — an empty store says so and names
// the command that queues a row, and an `--approve` that changes nothing says
// what was already true instead of claiming an approval. The
// leakage-partition guard runs BEFORE the no-op short-circuit, so a row
// forced to human-approved by a hand edit is still refused.
//
// D4 (2026-09-10) adds `--queue-finding FINDING` (with `--kind` and
// `--pattern`): a terminal finding that never went through a ladder rung had
// no way to gain the memory row the learning completion proof demands, since
// the ladder-disprove wire was learning.QueueMemory's only production caller.
// The row is queued, never approved — the human approval step is untouched.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

const memoryUsage = "usage: webv2 memory [-h] [--approve APPROVE] [--by BY] " +
	"[--reflect TEXT] [--round ROUND] [--reject REJECT] [--reason REASON] " +
	"[--rejection-class CLASS] [--queue-finding FINDING] [--kind KIND] " +
	"[--pattern TEXT] [--list] [--live-only] campaign\n"

// memoryHelp is argparse's `webv2 memory --help` output plus the D5 and D4
// flags, and §7.5's listing view flags.
const memoryHelp = `usage: webv2 memory [-h] [--approve APPROVE] [--by BY] [--reflect TEXT] [--round ROUND] [--reject REJECT] [--reason REASON] [--rejection-class CLASS] [--queue-finding FINDING] [--kind KIND] [--pattern TEXT] [--list] [--live-only] campaign

positional arguments:
  campaign

options:
  -h, --help         show this help message and exit
  --approve APPROVE  record a human approval (prints the promotion commands)
  --by BY            the approving identity
  --reflect TEXT     append one reflection entry to learnings.jsonl
  --round ROUND      the round the reflection belongs to (default 1)
  --reject REJECT    reject a pending memory candidate
  --reason REASON    why it was rejected (required with --reject; logged)
  --rejection-class CLASS
                     invalid-hypothesis | not-exploitable | below-threshold
  --queue-finding FINDING
                     queue the memory row a terminal finding needs
  --kind KIND        the memory kind (default: confirmed for CONFIRMED,
                     disproved for DISPROVED)
  --pattern TEXT     the pattern the row records (default: finding title)
  --list             list the campaign's memory rows (the default view)
  --live-only        hide DUPLICATE/SUPERSEDED/INFORMATIONAL rows
`

// memoryBuildSpec builds the argparse spec of `memory`.
func memoryBuildSpec() *argSpec {
	return &argSpec{
		prog:  "memory",
		usage: memoryUsage,
		vals: []*valOpt{{name: "--approve"}, {name: "--by"},
			{name: "--reflect"}, {name: "--round"}, {name: "--reject"},
			{name: "--reason"}, {name: "--rejection-class"},
			{name: "--queue-finding"}, {name: "--kind"}, {name: "--pattern"}},
		flags: []*boolOpt{{name: "--list"}, {name: "--live-only"}},
		pos:   []*posOpt{{name: "campaign"}},
	}
}

// memoryCheckFlags rejects the flag combinations argparse-style mutual
// exclusivity forbids: the four actions are mutually exclusive and several
// flags only make sense with the action that consumes them.
func memoryCheckFlags(sp *argSpec) error {
	reflect, round, reject := sp.vals[2].val, sp.vals[3].val, sp.vals[4].val
	reason, rejectClass := sp.vals[5].val, sp.vals[6].val
	approve := sp.vals[0].val
	queueFinding, kind, pattern := sp.vals[7].val, sp.vals[8].val, sp.vals[9].val
	// The first three actions are mutually exclusive; each carries flags
	// that only make sense with it. `--queue-finding` (D4) is the fourth
	// action, excluded from --approve/--reflect/--reject just below.
	actions := 0
	for _, set := range []bool{approve != "", reflect != "", reject != ""} {
		if set {
			actions++
		}
	}
	if actions > 1 {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --approve: not allowed with --reflect or --reject")
	}
	if reason != "" && reject == "" {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --reason: only meaningful with --reject")
	}
	if rejectClass != "" && reject == "" {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --rejection-class: only meaningful with --reject")
	}
	if round != "" && reflect == "" {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --round: only meaningful with --reflect")
	}
	if queueFinding != "" &&
		(approve != "" || reflect != "" || reject != "") {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --queue-finding: not allowed with --approve, "+
				"--reflect or --reject")
	}
	if kind != "" && queueFinding == "" {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --kind: only meaningful with --queue-finding")
	}
	if pattern != "" && queueFinding == "" {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --pattern: only meaningful with --queue-finding")
	}
	// §7.5: --list names the listing view explicitly, so it cannot ride along
	// with an action; --live-only is a property of that view.
	action := approve != "" || reflect != "" || reject != "" ||
		queueFinding != ""
	if sp.flags[0].set && action {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --list: not allowed with --approve, --reflect, "+
				"--reject or --queue-finding")
	}
	if sp.flags[1].set && action {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --live-only: only meaningful with the listing view")
	}
	return nil
}

// memoryRunAction dispatches the explicit action flags; it reports whether
// one of them fired (the fall-through is the listing view).
func memoryRunAction(c *state.Campaign, sp *argSpec, by string, r *Runner) (bool, error) {
	if approve := sp.vals[0].val; approve != "" {
		return true, memoryApprove(c, approve, by, r)
	}
	if reflect := sp.vals[2].val; reflect != "" {
		return true, memoryReflect(c, reflect, sp.vals[3].val, r)
	}
	if reject := sp.vals[4].val; reject != "" {
		return true, memoryReject(c, reject, sp.vals[5].val, sp.vals[6].val, r)
	}
	if queueFinding := sp.vals[7].val; queueFinding != "" {
		return true, memoryQueueFinding(c, queueFinding, sp.vals[8].val, sp.vals[9].val, r)
	}
	return false, nil
}

// memoryList prints the campaign's memory rows (or the empty-store notice).
// liveOnly is §7.5's view filter: the ingest-clutter statuses are hidden and
// tallied in a footer, so an inbox that looks quiet cannot be mistaken for an
// inbox that is empty.
func memoryList(c *state.Campaign, r *Runner, liveOnly bool) error {
	rows, err := learning.AllMemory(c)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprint(r.Out, "memory: no rows yet — nothing to show\n")
		fmt.Fprintf(r.Out, "next: a disproved ladder rung queues a "+
			"negative memory row — webv2 ladder %s disprove <F-...> "+
			"<RUNG> --reason '...'\n", c.CampaignID)
		return nil
	}
	hidden := 0
	for _, m := range rows {
		if liveOnly && junkStatuses[validation.ObjStr(m, "status")] {
			hidden++
			continue
		}
		fmt.Fprintf(r.Out, "%s [%s/%s] promotion=%s  %s\n",
			validation.ObjStr(m, "memory_id"), validation.ObjStr(m, "kind"),
			validation.ObjStr(m, "status"), validation.ObjStr(m, "promotion_status"),
			pyHead(validation.ObjStr(m, "pattern"), 80))
	}
	if hidden > 0 {
		if _, err := fmt.Fprintf(r.Out, "live-only: %d rows hidden\n", hidden); err != nil {
			return err
		}
	}
	return nil
}

func runMemory(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := memoryBuildSpec()
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, memoryHelp)
			return nil
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		by := sp.vals[1].val
		if by == "" {
			by = "unknown"
		}
		if err := memoryCheckFlags(sp); err != nil {
			return err
		}
		handled, err := memoryRunAction(c, sp, by, r)
		if handled || err != nil {
			return err
		}
		return memoryList(c, r, sp.flags[1].set)
	})
}

// memoryQueueFinding is the `--queue-finding` half (D4): one memory row for a
// terminal finding that has no ladder rung to derive one from. The finding's
// status must be in learning.MEMORY_STATUSES; the kind is --kind when given,
// else the status's default. The row is queued — promotion_status stays
// pending — and only an explicit human --approve moves it.
func memoryQueueFinding(c *state.Campaign, findingID, kind, pattern string,
	r *Runner) error {
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return err
	}
	status := validation.ObjStr(f, "status")
	if !slices.Contains(learning.MEMORY_STATUSES, status) {
		return fmt.Errorf("finding %s has status %s; a memory row accepts "+
			"one of %s", validation.PyReprStr(findingID),
			validation.PyReprStr(status), sftChoiceList(learning.MEMORY_STATUSES))
	}
	if kind == "" {
		switch status {
		case "CONFIRMED":
			kind = "confirmed"
		case "DISPROVED":
			kind = "disproved"
		default:
			return fmt.Errorf("no default memory kind for status %s; pass "+
				"--kind with one of %s", validation.PyReprStr(status),
				sftChoiceList(learning.MemoryKinds))
		}
	}
	if pattern == "" {
		pattern = validation.ObjStr(f, "title")
	}
	fid := validation.ObjStr(f, "finding_id")
	var fidPtr, bugClassPtr *string
	if fid != "" {
		fidPtr = &fid
	}
	if class := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class"); class != "" {
		bugClassPtr = &class
	}
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind:      kind,
		Status:    status,
		Pattern:   pattern,
		FindingID: fidPtr,
		BugClass:  bugClassPtr,
	})
	if err != nil {
		return err
	}
	memID := validation.ObjStr(mem, "memory_id")
	fmt.Fprintf(r.Out, "%s queued for %s (%s) — approve with: webv2 memory "+
		"%s --approve %s --by NAME\n", memID, fid, status, c.CampaignID, memID)
	return nil
}

// memoryReflect is the `--reflect` half: one ReflectionOpts entry appended to
// learnings.jsonl. The sentence lands in process_improvements — the field of a
// reflection entry that a one-line observation belongs in (the other four are
// per-round diagnostic lists a model fills).
func memoryReflect(c *state.Campaign, text, round string, r *Runner) error {
	n := int64(1)
	if round != "" {
		parsed, err := strconv.ParseInt(round, 10, 64)
		if err != nil {
			return t14ArgparseErr(memoryUsage, "memory",
				"argument --round: invalid int value: %s", validation.PyReprStr(round))
		}
		n = parsed
	}
	if _, err := learning.ReflectionEntry(c, learning.ReflectionOpts{
		Round:               n,
		ProcessImprovements: []string{text},
	}); err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "reflection recorded (round %d): %s\n", n, pyHead(text, 80))
	fmt.Fprintf(r.Out, "  learnings.jsonl now holds %d entr(ies)\n",
		countLearnings(c))
	return nil
}

// memoryReject is the `--reject` half of cmd_memory.
func memoryReject(c *state.Campaign, reject, reason, class string, r *Runner) error {
	if reason == "" {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --reason: required with --reject")
	}
	mem, err := learning.RejectMemory(c, reject, reason, class)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "rejected %s (%s) promotion=%s\n",
		validation.ObjStr(mem, "memory_id"), orUnknown(validation.ObjStr(mem, "rejection_class")),
		validation.ObjStr(mem, "promotion_status"))
	fmt.Fprintf(r.Out, "  reason logged: %s\n", pyHead(reason, 80))
	return nil
}

// countLearnings is the number of lines in learnings.jsonl (0 when absent).
// r39b: the ONE framing predicate — state.BlankLine, like every other JSONL
// reader in the tree. A strings.TrimSpace copy answered "blank" to a line of
// Unicode whitespace (U+00A0 alone) that the log/ledger readers count as a
// RECORD this decoder cannot parse; two predicates answering differently to
// the same byte is the exact r38 shape.
func countLearnings(c *state.Campaign) int {
	raw, err := os.ReadFile(filepath.Join(c.Dir, "learnings.jsonl"))
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if !state.BlankLine(line) {
			n++
		}
	}
	return n
}

// memoryApprove is the `--approve` half of cmd_memory.
func memoryApprove(c *state.Campaign, approve, by string,
	r *Runner) error {
	rowPath := filepath.Join(c.MemoryDir, approve+".json")
	var prior validation.Value = validation.VNull()
	if _, err := os.Stat(rowPath); err == nil {
		prior, err = validation.ReadJson(rowPath)
		if err != nil {
			return err
		}
	}
	if prior.Kind == validation.Obj {
		// The leakage-partition guard runs BEFORE the no-op short-circuit
		// (fix round 1 / MINOR 1): a row forced to human-approved or
		// promoted by a hand edit or legacy write is still refused, never
		// reported as "nothing changed" with a `publish` that would raise.
		if err := learning.AssertApprovable(approve, prior); err != nil {
			return err
		}
	}
	if prior.Kind == validation.Obj {
		status := validation.ObjStr(prior, "promotion_status")
		if status == "human-approved" || status == "promoted" {
			// Already at (or past) the approval this command records: write
			// nothing and log nothing, and say why plus the next step.
			fmt.Fprintf(r.Out, "%s: already %s by %s at %s — nothing changed\n",
				approve, status, orUnknown(validation.ObjStr(prior, "approved_by")),
				orUnknown(validation.ObjStr(prior, "approved_at")))
			if status == "human-approved" {
				commands, err := learning.PromotionCommands(c, approve, by)
				if err != nil {
					return err
				}
				fmt.Fprintf(r.Out, "next: %s\n", validation.ObjStr(commands[0], "command"))
			} else {
				fmt.Fprint(r.Out, "next: nothing to do — the row is already "+
					"promoted\n")
			}
			return nil
		}
	}
	mem, err := learning.ApproveMemory(c, approve, by)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "approved %s by %s\n", validation.ObjStr(mem, "memory_id"),
		validation.ObjStr(mem, "approved_by"))
	if rowCls, fndCls, stale := learning.StaleBugClass(c, mem); stale {
		// r7 (critic): queue-time taxonomy stamped into the row can go
		// stale under an amend --class. The approval stands (the human
		// judged the PATTERN); the label drift is named before promotion,
		// never carried silently.
		fmt.Fprintf(r.Err, "warn: this row carries bug_class %s but its "+
			"source finding is now classified %q — review the label before "+
			"promoting\n", rowCls, fndCls)
	}
	fmt.Fprint(r.Out, "promote with (in priority order):\n")
	commands, err := learning.PromotionCommands(c, validation.ObjStr(mem, "memory_id"), by)
	if err != nil {
		return err
	}
	for _, pc := range commands {
		fmt.Fprintf(r.Out, "  [%s] %s\n", validation.ObjStr(pc, "substrate"),
			validation.ObjStr(pc, "command"))
		fmt.Fprintf(r.Out, "      %s\n", validation.ObjStr(pc, "note"))
	}
	return nil
}

// orUnknown is Python's `x or 'unknown'`.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func init() {
	register(command{ord: 31, name: "memory",
		line: "memory <campaign> [--approve M] [--reflect T] [--reject M]   " +
			"list learning memory / approve / reflect / reject",
		run: runMemory})
}
