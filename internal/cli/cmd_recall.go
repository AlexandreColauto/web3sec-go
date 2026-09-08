package cli

// cmd_recall: `webv2 recall <campaign> --finding F [--mode M] [--note N]` —
// consult the graph memory for a finding and record the check (cli.py
// cmd_recall verbatim). The derived query is advisory; the recording is the
// operator's explicit act, and the act reports its own relevance verdict
// (B3/D2): a cite that overlaps nothing says so out loud.

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

var recallModes = []string{"negative", "comparative"}

func runRecall(root string, args []string, r *Runner) int {
	ensureSeams()
	findingID, mode, note := "", "negative", ""
	haveFinding, haveNote := false, false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--finding" && i+1 < len(args):
			findingID, haveFinding = args[i+1], true
			i++
		case strings.HasPrefix(a, "--finding="):
			findingID, haveFinding = strings.TrimPrefix(a, "--finding="), true
		case a == "--mode" && i+1 < len(args):
			mode = args[i+1]
			i++
		case strings.HasPrefix(a, "--mode="):
			mode = strings.TrimPrefix(a, "--mode=")
		case a == "--note" && i+1 < len(args):
			note, haveNote = args[i+1], true
			i++
		case strings.HasPrefix(a, "--note="):
			note, haveNote = strings.TrimPrefix(a, "--note="), true
		case a == "--finding":
			return r.fail(root, argErrf("recall",
				"argument --finding: expected one argument"))
		case a == "--mode":
			return r.fail(root, argErrf("recall",
				"argument --mode: expected one argument"))
		case a == "--note":
			return r.fail(root, argErrf("recall",
				"argument --note: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) > 1 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", pos[1]))
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if !haveFinding {
		missing = append(missing, "--finding")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("recall", missing...))
	}
	if !containsStrCLI(recallModes, mode) {
		return r.fail(root, argErrf("recall",
			"argument --mode: invalid choice: %s (choose from %s)",
			validation.PyReprStr(mode), quotedList(recallModes)))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	if mode == "comparative" && strings.TrimSpace(note) == "" {
		fmt.Fprintln(r.Err, "recall: --mode comparative requires --note "+
			"(what did you compare?)")
		return 2
	}
	if err := recallBody(c, findingID, mode, note, haveNote, r.Out); err != nil {
		return r.withErr(root, func() error { return err })
	}
	return 0
}

// recallBody is the query + recording + relevance report.
func recallBody(c *state.Campaign, findingID, mode, note string, haveNote bool,
	stdout io.Writer) error {
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return err
	}
	classV := objAt(objAt(f, "root_cause"), "class")
	classText := "-"
	if pyTruthyCLI(classV) {
		classText = scalarStr(classV)
	}
	rowsByID, err := findings.VisibleMemoryRows(c)
	if err != nil {
		return err
	}
	shown := rankMemoryRows(rowsByID, classV)
	fmt.Fprintf(stdout, "graph memory consultation for %s (class=%s; %d "+
		"visible rows, showing %d):\n", findingID, classText, len(rowsByID),
		len(shown))
	ids := make([]string, 0, len(shown))
	for _, row := range shown {
		summary := ""
		if s := objAt(row, "evidence_summary"); s.Kind == validation.Str {
			summary = pyHead(s.S, 120)
		}
		pattern := "-"
		if p := objAt(row, "pattern"); pyTruthyCLI(p) {
			pattern = scalarStr(p)
		}
		mid := objStr(row, "memory_id")
		ids = append(ids, mid)
		fmt.Fprintf(stdout, "  %s [%s] %s — %s\n", mid,
			scalarStr(objAt(row, "bug_class")), pattern, summary)
	}
	sort.Strings(ids)
	check := validation.VObj(
		validation.KV{K: "memory_ids", V: strArrCLI(ids)},
		validation.KV{K: "mode", V: validation.VStr(mode)},
	)
	if haveNote {
		check.O = append(check.O, validation.KV{K: "note",
			V: validation.VStr(note)})
	}
	out, err := findings.RecordMemoryCheck(c, findingID,
		[]validation.Value{check})
	if err != nil {
		return err
	}
	checks := objAt(objAt(out, "provenance"), "memory_checks")
	fmt.Fprintf(stdout, "recorded: mode=%s on %s (%d total memory check(s))\n",
		mode, findingID, len(checks.A))
	entry, found := lastMemoryCheck(checks, ids, mode)
	if !found {
		return nil
	}
	if rel := objAt(entry, "recalled_irrelevant"); pyTruthyCLI(rel) {
		_, reason := findings.IrrelevantReason(objAt(entry, "relevance"), ids)
		fmt.Fprintf(stdout, "  relevance: no overlapping row — corpus.gap "+
			"logged (%s)\n", reason)
		return nil
	}
	relevance, ok := fieldAtCLI(entry, "relevance")
	if !ok {
		fmt.Fprintln(stdout, "  relevance: not recorded — this identical "+
			"check predates the relevance test and is left as it is")
		return nil
	}
	discount := ""
	if d := objAt(relevance, "discounted"); len(d.A) > 0 {
		discount = "; discounted " + joinCommaCLI(strListCLI(d)) +
			" (non-discriminative class needs a second basis)"
	}
	basis := joinCommaCLI(strListCLI(objAt(relevance, "basis")))
	if basis == "" {
		basis = "-"
	}
	fmt.Fprintf(stdout, "  relevance: %d overlapping row(s) via %s%s\n",
		len(objAt(relevance, "overlapping").A), basis, discount)
	return nil
}

// rankMemoryRows is Python's class-first ranking: rows whose bug_class
// equals the finding's root-cause class first, then by memory_id.
func rankMemoryRows(rowsByID map[string]validation.Value,
	classV validation.Value) []validation.Value {
	rows := make([]validation.Value, 0, len(rowsByID))
	for _, row := range rowsByID {
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ci := 1
		if valueEqCLI(objAt(rows[i], "bug_class"), classV) {
			ci = 0
		}
		cj := 1
		if valueEqCLI(objAt(rows[j], "bug_class"), classV) {
			cj = 0
		}
		if ci != cj {
			return ci < cj
		}
		return objStr(rows[i], "memory_id") < objStr(rows[j], "memory_id")
	})
	if len(rows) > 20 {
		rows = rows[:20]
	}
	return rows
}

// lastMemoryCheck is Python's reversed() search for the entry this act
// stamped (matching ids AND mode); a pre-B3 duplicate has neither.
func lastMemoryCheck(checks validation.Value, ids []string,
	mode string) (validation.Value, bool) {
	for i := len(checks.A) - 1; i >= 0; i-- {
		chk := checks.A[i]
		if chk.Kind != validation.Obj {
			continue
		}
		if !equalStrListCLI(valueStringsCLI(objAt(chk, "memory_ids")), ids) {
			continue
		}
		if objStr(chk, "mode") == mode {
			return chk, true
		}
	}
	return validation.VNull(), false
}

func fieldAtCLI(v validation.Value, key string) (validation.Value, bool) {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// valueEqCLI is Python == for the JSON scalars the ranking compares.
func valueEqCLI(a, b validation.Value) bool {
	if a.Kind == b.Kind {
		switch a.Kind {
		case validation.Str:
			return a.S == b.S
		case validation.Null:
			return true
		case validation.Int:
			return validation.IntText(a) == validation.IntText(b)
		case validation.Bool:
			return a.B == b.B
		}
	}
	return validation.CanonCompact(a) == validation.CanonCompact(b)
}

func strArrCLI(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, it := range items {
		out = append(out, validation.VStr(it))
	}
	return validation.VArr(out...)
}

func valueStringsCLI(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		out = append(out, scalarStr(e))
	}
	return out
}

func equalStrListCLI(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// joinCommaCLI is ", ".join(items).
func joinCommaCLI(items []string) string { return strings.Join(items, ", ") }

func init() {
	register(command{ord: 46, name: "recall",
		line: "recall <campaign> --finding F      consult graph memory + record",
		run:  runRecall})
}
