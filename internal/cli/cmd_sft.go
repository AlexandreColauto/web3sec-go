package cli

// cmd_sft: `webv2 sft {lint,add,list,split,report,backfill,export} ...` — the
// SFT critical-bug reasoning dataset verb (cli.py cmd_sft_* verbatim, including
// the exit-code contract: 0 pass, 1 lint failure, 2 usage/error).

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"websec/internal/sft"
	"websec/internal/validation"
)

const (
	sftUsage = "usage: webv2 sft [-h] {lint,add,list,split,report,backfill," +
		"export} ...\n"

	sftLintUsage = "usage: webv2 sft lint [-h] file\n"
	sftAddUsage  = "usage: webv2 sft add [-h] [--status {draft,curated}] file\n"
	sftListUsage = "usage: webv2 sft list [-h] [--status STATUS] " +
		"[--partition PARTITION] [--taxonomy TAXONOMY]\n"
	sftSplitUsage    = "usage: webv2 sft split [-h] [--seed SEED]\n"
	sftReportUsage   = "usage: webv2 sft report [-h]\n"
	sftBackfillUsage = "usage: webv2 sft backfill [-h] [-o OUT] campaign finding\n"
	sftExportUsage   = "usage: webv2 sft export [-h] " +
		"[--partition {training,held-out}]\n"
)

var sftChoices = []string{"lint", "add", "list", "split", "report", "backfill",
	"export"}

func runSft(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error { return sftDispatch(root, args, r) })
}

// sftDispatch splits the parent parser (subcommand choice + -h) from the
// chosen subparser.
func sftDispatch(root string, args []string, r *Runner) error {
	sub, rest := "", []string(nil)
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			sub, rest = a, args[i+1:]
			break
		}
		if a == "-h" || a == "--help" {
			fmt.Fprint(r.Out, sftHelp)
			return nil
		}
		return t14ArgparseErr(sftUsage, "sft",
			"unrecognized arguments: %s", a)
	}
	if sub == "" {
		return t14ArgparseErr(sftUsage, "sft",
			"the following arguments are required: sft_cmd")
	}
	if !containsStr(sftChoices, sub) {
		return t14ArgparseErr(sftUsage, "sft",
			"argument sft_cmd: invalid choice: %s (choose from 'lint', "+
				"'add', 'list', 'split', 'report', 'backfill', 'export')",
			quoteSingle(sub))
	}
	if hasHelp(rest) {
		fmt.Fprint(r.Out, sftSubHelp(sub))
		return nil
	}
	switch sub {
	case "lint":
		return sftLintCmd(rest, r)
	case "add":
		return sftAddCmd(rest, r)
	case "list":
		return sftListCmd(rest, r)
	case "split":
		return sftSplitCmd(rest, r)
	case "report":
		return sftReportCmd(rest, r)
	case "backfill":
		return sftBackfillCmd(root, rest, r)
	case "export":
		return sftExportCmd(rest, r)
	}
	return nil
}

const sftHelp = sftUsage + `
positional arguments:
  {lint,add,list,split,report,backfill,export}
    lint                lint one example file (exit 0/1/2)
    add                 add an example to the store
    list                list stored examples
    split               re-run the deterministic cluster split
    report              taxonomy/pivot/source mix vs targets
    backfill            draft an example from a campaign trajectory (Task D)
    export              chat-format JSONL for training pipelines

options:
  -h, --help            show this help message and exit
`

// sftSubHelp is the subparser help text (argparse's `webv2 sft <sub> -h`).
func sftSubHelp(sub string) string {
	return map[string]string{
		"lint":     sftLintUsage + "\npositional arguments:\n  file\n",
		"add":      sftAddUsage + "\npositional arguments:\n  file\n",
		"list":     sftListUsage,
		"split":    sftSplitUsage,
		"report":   sftReportUsage,
		"backfill": sftBackfillUsage,
		"export":   sftExportUsage,
	}[sub]
}

// sftSpec is one subparser's argument surface: valued options (with
// aliases), required positionals, choices and int-typed options.
type sftSpec struct {
	usage, prog string
	valued      map[string]string // flag (incl. aliases) -> value key
	required    []string          // required positionals, in order
	choices     map[string][]string
	ints        map[string]bool
}

// sftParsed is one subparser's parse result.
type sftParsed struct {
	pos  []string
	vals map[string]string
}

func (p *sftParsed) get(key, def string) string {
	if v, ok := p.vals[key]; ok {
		return v
	}
	return def
}

func (p *sftParsed) opt(key string) *string {
	if v, ok := p.vals[key]; ok {
		return &v
	}
	return nil
}

// sftParse is argparse's parse_args for one sft subparser. A missing option
// value, an invalid choice and a missing required positional are reported by
// the SUBparser; unknown flags and extra positionals are reported by the ROOT
// parser (Python's `unrecognized arguments`, top-level usage) — which is why
// the required-positional check runs first.
func sftParse(args []string, spec sftSpec) (*sftParsed, error) {
	p := &sftParsed{vals: map[string]string{}}
	type extra struct {
		idx  int
		text string
	}
	extras := []extra{}
	add := func(i int, text string) { extras = append(extras, extra{i, text}) }
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			for j := i + 1; j < len(args); j++ {
				add(j, args[j])
			}
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			p.pos = append(p.pos, a)
			continue
		}
		name, inline, hasInline := sftSplitFlag(a)
		key, known := spec.valued[name]
		if !known {
			add(i, a)
			continue
		}
		val := inline
		if !hasInline {
			if i+1 >= len(args) {
				return nil, t14ArgparseErr(spec.usage, spec.prog,
					"argument %s: expected one argument", name)
			}
			val = args[i+1]
			i++
		}
		if allowed, ok := spec.choices[key]; ok &&
			!containsStr(allowed, val) {
			return nil, t14ArgparseErr(spec.usage, spec.prog,
				"argument %s: invalid choice: %s (choose from %s)", name,
				quoteSingle(val), sftChoiceList(allowed))
		}
		if spec.ints[key] {
			if _, err := strconv.Atoi(val); err != nil {
				return nil, t14ArgparseErr(spec.usage, spec.prog,
					"argument %s: invalid int value: %s", name,
					quoteSingle(val))
			}
		}
		p.vals[key] = val
	}
	if len(p.pos) < len(spec.required) {
		return nil, t14ArgparseErr(spec.usage, spec.prog,
			"the following arguments are required: %s",
			strings.Join(spec.required[len(p.pos):], ", "))
	}
	for j, a := range p.pos[len(spec.required):] {
		add(len(args)+j, a)
	}
	if len(extras) > 0 {
		sort.SliceStable(extras, func(i, j int) bool {
			return extras[i].idx < extras[j].idx
		})
		toks := make([]string, 0, len(extras))
		for _, e := range extras {
			toks = append(toks, e.text)
		}
		return nil, t14Unrecognized(strings.Join(toks, " "))
	}
	return p, nil
}

// sftSplitFlag splits `--name=value` into (name, value, true).
func sftSplitFlag(a string) (string, string, bool) {
	if i := strings.Index(a, "="); i >= 0 {
		return a[:i], a[i+1:], true
	}
	return a, "", false
}

// sftChoiceList is argparse's `'a', 'b'` choice rendering.
func sftChoiceList(allowed []string) string {
	q := make([]string, 0, len(allowed))
	for _, a := range allowed {
		q = append(q, quoteSingle(a))
	}
	return strings.Join(q, ", ")
}

// sftLintCmd is cmd_sft_lint: exit 0 = pass, 1 = lint failed, 2 = error.
func sftLintCmd(args []string, r *Runner) error {
	p, err := sftParse(args, sftSpec{usage: sftLintUsage, prog: "sft lint",
		required: []string{"file"}})
	if err != nil {
		return err
	}
	ex, err := sftLoadFile(p.pos[0])
	if err != nil {
		return t14ExitErr(2, "sft: cannot read %s: %s\n", p.pos[0], err)
	}
	existing, err := sftCurated()
	if err != nil {
		return err
	}
	reasons := sft.LintExample(ex, existing, sftDefaultStatus(ex))
	for _, reason := range reasons {
		fmt.Fprintln(r.Out, reason)
	}
	if len(sftHard(reasons)) > 0 {
		return &t14Exit{code: 1}
	}
	if len(reasons) == 0 {
		fmt.Fprintln(r.Out, "lint: PASS")
	} else {
		fmt.Fprintln(r.Out, "lint: PASS (warnings only)")
	}
	return nil
}

// sftAddCmd is cmd_sft_add.
func sftAddCmd(args []string, r *Runner) error {
	p, err := sftParse(args, sftSpec{usage: sftAddUsage, prog: "sft add",
		valued:   map[string]string{"--status": "status"},
		required: []string{"file"},
		choices:  map[string][]string{"status": {"draft", "curated"}}})
	if err != nil {
		return err
	}
	ex, err := sftLoadFile(p.pos[0])
	if err != nil {
		return t14ExitErr(2, "sft: cannot read %s: %s\n", p.pos[0], err)
	}
	added, err := sft.AddExample(ex, p.get("status", "draft"))
	if err != nil {
		return t14ExitErr(2, "sft add failed: %s\n", err)
	}
	fmt.Fprintf(r.Out, "added %s (status=%s)\n", validation.ObjStr(added, "id"),
		validation.ObjStr(added, "status"))
	return nil
}

// sftListCmd is cmd_sft_list.
func sftListCmd(args []string, r *Runner) error {
	p, err := sftParse(args, sftSpec{usage: sftListUsage, prog: "sft list",
		valued: map[string]string{"--status": "status",
			"--partition": "partition", "--taxonomy": "taxonomy"}})
	if err != nil {
		return err
	}
	rows, err := sft.ListExamples(p.opt("status"), p.opt("partition"),
		p.opt("taxonomy"))
	if err != nil {
		return err
	}
	for _, e := range rows {
		fmt.Fprintf(r.Out, "%s  %s  %s  %s  %s\n", validation.ObjStr(e, "id"),
			pyPad(validation.ObjStr(e, "status"), 8),
			pyPad(pyOr(validation.ObjStr(e, "taxonomy"), "-"), 32),
			pyPad(pyOr(validation.ObjStr(e, "partition"), "-"), 9),
			validation.ObjStr(validation.ObjAt(e, "source"), "ref"))
	}
	return nil
}

// sftSplitCmd is cmd_sft_split.
func sftSplitCmd(args []string, r *Runner) error {
	p, err := sftParse(args, sftSpec{usage: sftSplitUsage, prog: "sft split",
		valued: map[string]string{"--seed": "seed"},
		ints:   map[string]bool{"seed": true}})
	if err != nil {
		return err
	}
	seed := 42
	if v := p.opt("seed"); v != nil {
		seed, _ = strconv.Atoi(*v)
	}
	stats, err := sft.SplitExamples(seed)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "split: training=%d held-out=%d (%s%%) "+
		"unsplit_drafts=%d clusters=%d/%d\n", validation.ObjAt(stats, "training").I,
		validation.ObjAt(stats, "held-out").I, sftNumText(validation.ObjAt(stats, "held_out_pct")),
		validation.ObjAt(stats, "unsplit_drafts").I,
		validation.ObjAt(validation.ObjAt(stats, "clusters"), "training").I,
		validation.ObjAt(validation.ObjAt(stats, "clusters"), "held-out").I)
	return nil
}

// sftReportCmd is cmd_sft_report.
func sftReportCmd(args []string, r *Runner) error {
	if _, err := sftParse(args, sftSpec{usage: sftReportUsage,
		prog: "sft report"}); err != nil {
		return err
	}
	rep, err := sft.MixReport()
	if err != nil {
		return err
	}
	fmt.Fprintln(r.Out, "taxonomy mix (target in parens):")
	for _, kv := range validation.ObjAt(rep, "taxonomy_mix").O {
		row := kv.V
		fmt.Fprintf(r.Out, "  %s %s  %s%%  (target %s%%, gap %s)\n",
			pyPad(kv.K, 34), pyPadLeft(validation.ObjAt(row, "count"), 4),
			pyPadLeft(validation.ObjAt(row, "pct"), 5),
			fmtFloat(validation.ObjAt(row, "target_pct"), 0), fmtSigned(validation.ObjAt(row, "gap")))
	}
	fmt.Fprintf(r.Out, "pivot share: %s%% (target ~%s%%)\n",
		sftNumText(validation.ObjAt(rep, "pivot_share_pct")),
		fmtFloat(validation.ObjAt(rep, "pivot_target_pct"), 0))
	fmt.Fprintf(r.Out, "source mix: %s\n", pyDictRepr(validation.ObjAt(rep, "source_mix")))
	fmt.Fprintf(r.Out, "partitions: %s\n",
		pyDictRepr(validation.ObjAt(rep, "partition_counts")))
	fmt.Fprintf(r.Out, "dedup collisions (curated): %d\n",
		validation.ObjAt(rep, "dedup_collisions").I)
	for _, w := range validation.ObjAt(rep, "warnings").A {
		fmt.Fprintf(r.Out, "warn: %s\n", w.S)
	}
	return nil
}

// sftBackfillCmd is cmd_sft_backfill.
func sftBackfillCmd(root string, args []string, r *Runner) error {
	p, err := sftParse(args, sftSpec{usage: sftBackfillUsage,
		prog:     "sft backfill",
		valued:   map[string]string{"-o": "out", "--out": "out"},
		required: []string{"campaign", "finding"}})
	if err != nil {
		return err
	}
	c, err := t14Open(root, p.pos[0])
	if err != nil {
		return err
	}
	draft, err := sft.BackfillFinding(c, p.pos[1])
	if err != nil {
		return t14ExitErr(2, "sft backfill failed: %s\n", err)
	}
	text := validation.DumpIndented(draft) + "\n"
	out := p.get("out", "")
	if out != "" {
		if err := os.WriteFile(out, []byte(text), 0o644); err != nil {
			return t14ExitErr(2, "sft backfill failed: %s\n", err)
		}
		fmt.Fprintf(r.Out, "wrote draft to %s \u2014 edit the TODOs, then "+
			"`webv2 sft add %s`\n", out, out)
		return nil
	}
	fmt.Fprint(r.Out, text)
	return nil
}

// sftExportCmd is cmd_sft_export.
func sftExportCmd(args []string, r *Runner) error {
	p, err := sftParse(args, sftSpec{usage: sftExportUsage,
		prog:   "sft export",
		valued: map[string]string{"--partition": "partition"},
		choices: map[string][]string{"partition": {"training",
			"held-out"}}})
	if err != nil {
		return err
	}
	text, err := sft.ExportJSONL(p.opt("partition"))
	if err != nil {
		return err
	}
	fmt.Fprint(r.Out, text)
	return nil
}

// ---- helpers -------------------------------------------------------------

func sftLoadFile(path string) (validation.Value, error) {
	text, err := t14ReadText(path)
	if err != nil {
		return validation.VNull(), err
	}
	return t14ParseJSON(text)
}

func sftCurated() ([]validation.Value, error) {
	store, err := sft.LoadStore()
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, e := range validation.ObjAt(store, "examples").A {
		if validation.ObjStr(e, "status") == "curated" {
			out = append(out, e)
		}
	}
	return out, nil
}

func sftDefaultStatus(ex validation.Value) string {
	if s := validation.ObjStr(ex, "status"); s != "" {
		return s
	}
	return "draft"
}

func sftHard(reasons []string) []string {
	out := []string{}
	for _, r := range reasons {
		if !strings.HasPrefix(r, "warn:") {
			out = append(out, r)
		}
	}
	return out
}

func hasHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

// sftNumText is Python's str() for an int/float JSON value.
func sftNumText(v validation.Value) string {
	switch v.Kind {
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	}
	return ""
}

// pyPad / pyPadLeft are Python's `{s:<n}` / `{s:>n}` (no truncation).
func pyPad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func pyPadLeft(v validation.Value, n int) string {
	s := sftNumText(v)
	if len(s) >= n {
		return s
	}
	return strings.Repeat(" ", n-len(s)) + s
}

// fmtFloat is `{v:.0f}`.
func fmtFloat(v validation.Value, places int) string {
	if v.Kind != validation.Flt {
		return sftNumText(v)
	}
	return strconv.FormatFloat(v.F, 'f', places, 64)
}

// fmtSigned is `{v:+.1f}`.
func fmtSigned(v validation.Value) string {
	if v.Kind != validation.Flt {
		return sftNumText(v)
	}
	s := strconv.FormatFloat(v.F, 'f', 1, 64)
	if !strings.HasPrefix(s, "-") {
		s = "+" + s
	}
	return s
}

// pyDictRepr is Python's repr of a str->int dict in insertion order.
func pyDictRepr(v validation.Value) string {
	if v.Kind != validation.Obj {
		return "{}"
	}
	parts := make([]string, 0, len(v.O))
	for _, kv := range v.O {
		parts = append(parts, validation.PyReprStr(kv.K)+": "+sftNumText(kv.V))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func pyOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func init() {
	register(command{ord: 66, name: "sft",
		line: "SFT critical-bug reasoning dataset: lint / add / list / " +
			"split / report / backfill / export",
		run: runSft})
}
