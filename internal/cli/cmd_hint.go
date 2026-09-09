package cli

// cmd_hint: `webv2 hint <campaign> --kind K --content C [--source-ref R]
// [--actor A]` — a reflection-derived instruction for the planner. kind
// 'priority' enters the next work queue; the others are surfaced in the
// briefing. cli.py cmd_hint + learning.planner_hint verbatim (learning is
// unported, so the two functions it needs live here and the planner's
// load_planner_hints seam is wired to the local twin).

import (
	"fmt"
	"os"
	"strings"
	"time"

	"websec/internal/learning"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

const t14HintUsage = `usage: webv2 hint [-h] --kind {priority,exclusion,detector,note}
                  --content CONTENT [--source-ref SOURCE_REF] [--actor ACTOR]
                  campaign
`

const t14HintHelp = `usage: webv2 hint [-h] --kind {priority,exclusion,detector,note}
                  --content CONTENT [--source-ref SOURCE_REF] [--actor ACTOR]
                  campaign

positional arguments:
  campaign

options:
  -h, --help            show this help message and exit
  --kind {priority,exclusion,detector,note}
  --content CONTENT
  --source-ref SOURCE_REF
                        finding/memory id this came from
  --actor ACTOR
`

// HINT_KINDS is learning.HINT_KINDS.
var t14HintKinds = []string{"priority", "exclusion", "detector", "note"}

// hintArgs is the parsed command line.
type hintArgs struct {
	campaign  string
	kind      string
	content   string
	sourceRef string
	actor     string
}

func runHint(root string, args []string, r *Runner) error {
	a, err := parseHint(args, r)
	if err != nil || a == nil {
		return err
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	row, err := learning.PlannerHint(c, learning.HintOpts{Kind: a.kind,
		Content: a.content, SourceRef: a.sourceRef, Actor: a.actor})
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "%s: kind=%s — %s\n", objStr(row, "hint_id"),
		objStr(row, "kind"), t14Truncate(objStr(row, "content"), 70))
	return nil
}

// parseHint is the argparse layer (required: campaign, --kind, --content).
func parseHint(args []string, r *Runner) (*hintArgs, error) {
	a := &hintArgs{}
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t14HintHelp)
			return nil, nil
		}
		name, val, hasVal := splitFlag(arg)
		switch name {
		case "--kind", "--content", "--source-ref", "--actor":
			if !hasVal {
				if i+1 >= len(args) {
					return nil, t14ArgparseErr(t14HintUsage, "hint",
						"argument %s: expected one argument", name)
				}
				val = args[i+1]
				i++
			}
		}
		switch name {
		case "--kind":
			a.kind = val
		case "--content":
			a.content = val
		case "--source-ref":
			a.sourceRef = val
		case "--actor":
			a.actor = val
		default:
			if strings.HasPrefix(arg, "-") {
				return nil, t14Unrecognized(arg)
			}
			pos = append(pos, arg)
		}
	}
	var missing []string
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if a.kind == "" {
		missing = append(missing, "--kind")
	}
	if !t14FlagGiven(args, "--content") {
		missing = append(missing, "--content")
	}
	if len(missing) > 0 {
		return nil, t14ArgparseErr(t14HintUsage, "hint",
			"the following arguments are required: %s",
			strings.Join(missing, ", "))
	}
	if len(pos) > 1 {
		return nil, t14Unrecognized(strings.Join(pos[1:], " "))
	}
	a.campaign = pos[0]
	if !t14InList(a.kind, t14HintKinds) {
		return nil, t14ArgparseErr(t14HintUsage, "hint",
			"argument --kind: invalid choice: %s (choose from %s)",
			validation.PyReprStr(a.kind), "'priority', 'exclusion', "+
				"'detector', 'note'")
	}
	return a, nil
}

// t14FlagGiven reports whether an option (in either --x V or --x=V form)
// appeared at all: --content "" is still a supplied argument.
func t14FlagGiven(args []string, name string) bool {
	for _, arg := range args {
		if arg == name || strings.HasPrefix(arg, name+"=") {
			return true
		}
	}
	return false
}

// t14LoadPlannerHints is learning.load_planner_hints(campaign,
// kind="priority"): the rows the work queue consumes, in file order.
func t14LoadPlannerHints(c *state.Campaign) ([]planner.PlannerHint, error) {
	kind := "priority"
	rows, err := learning.LoadPlannerHints(c, &kind)
	if err != nil {
		return nil, err
	}
	var out []planner.PlannerHint
	for _, row := range rows {
		out = append(out, planner.PlannerHint{
			HintID:  objStr(row, "hint_id"),
			Content: objStr(row, "content"),
		})
	}
	return out, nil
}

// t14PyJSONLine is json.dumps(row, ensure_ascii=False): insertion order,
// Python's default ", "/": " separators, raw UTF-8 for non-ASCII.
func t14PyJSONLine(v validation.Value) string {
	var b strings.Builder
	switch v.Kind {
	case validation.Str:
		t14WritePyString(&b, v.S)
	case validation.Null:
		b.WriteString("null")
	case validation.Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case validation.Int:
		b.WriteString(validation.IntText(v))
	case validation.Flt:
		b.WriteString(validation.PythonFloat(v.F))
	case validation.Arr:
		b.WriteByte('[')
		for i, e := range v.A {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(t14PyJSONLine(e))
		}
		b.WriteByte(']')
	case validation.Obj:
		b.WriteByte('{')
		for i, kv := range v.O {
			if i > 0 {
				b.WriteString(", ")
			}
			t14WritePyString(&b, kv.K)
			b.WriteString(": ")
			b.WriteString(t14PyJSONLine(kv.V))
		}
		b.WriteByte('}')
	}
	return b.String()
}

// t14WritePyString is json.dumps(str, ensure_ascii=False) quoting.
func t14WritePyString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		default:
			if r < 0x20 {
				fmt.Fprintf(b, "\\u%04x", r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// t14PyTuple renders a Python tuple literal: ('a', 'b').
func t14PyTuple(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, validation.PyReprStr(it))
	}
	if len(parts) == 1 {
		return "(" + parts[0] + ",)"
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// t14NowIso is state.now_iso (unexported there): WEBV2_NOW verbatim, else the
// real clock at microsecond precision with a +00:00 offset.
func t14NowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}

func init() {
	planner.SetLoadPlannerHints(t14LoadPlannerHints)
	register(command{ord: 65, name: "hint",
		line: `hint <campaign> --kind K --content C  record a planner hint`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runHint(root, args, r)
			})
		}})
}
