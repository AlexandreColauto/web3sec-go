package cli

// cmd_ingest: `webv2 ingest [campaign] --json-file F [--example] [--trajectory T]
// [--stage S] [--answers-priority Q] [--priority-outcome O] [--json]` — ingest a
// model-produced hypothesis payload: schema-validated, dedup-fingerprinted,
// intake-checked, with the taxonomy advisory and intake warnings logged WITH
// the finding. cli.py cmd_ingest verbatim.
//
// `--from slither|aderyn --json-file out.json` (G1/I2a) is the SAST lane: the
// tool's JSON output is adapted to hypothesis payloads
// (internal/datasets/slither, internal/datasets/aderyn) and fed through the
// SAME orchestrator ingest path, one finding per admitted check/issue.
//
// The `--example` payload is the shipped examples/hypothesis.example.json
// (byte-identical to internal/taxonomy/testdata/seed/hypothesis.example.json)
// embedded verbatim; the closed-enum legend is WALKED from the embedded
// schema/finding.schema.json at call time, so it can never drift from what
// validation accepts.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"websec/internal/datasets/aderyn"
	"websec/internal/datasets/slither"
	"websec/internal/findings"
	"websec/internal/orchestrator"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

const t14IngestUsage = `usage: webv2 ingest [-h] [--json-file JSON_FILE] [--example]
                    [--trajectory TRAJECTORY] [--stage STAGE]
                    [--answers-priority ANSWERS_PRIORITY]
                    [--priority-outcome {answered,not-applicable,deprioritized}]
                    [--json]
                    [--from {slither,aderyn}]
                    [campaign]
`

const t14IngestHelp = `usage: webv2 ingest [-h] [--json-file JSON_FILE] [--example]
                    [--trajectory TRAJECTORY] [--stage STAGE]
                    [--answers-priority ANSWERS_PRIORITY]
                    [--priority-outcome {answered,not-applicable,deprioritized}]
                    [--json]
                    [--from {slither,aderyn}]
                    [campaign]

positional arguments:
  campaign

options:
  -h, --help            show this help message and exit
  --json-file JSON_FILE
                        payload JSON file (omit with --example)
  --example             print a valid example payload to stdout and exit
  --trajectory TRAJECTORY
                         full trajectory name or dispatch letter (A=code
                         B=economic C=state-machine D=attacker E=historical
                         F=integration G=drift H=lifecycle)
  --stage STAGE         discovery stage that produced this
  --answers-priority ANSWERS_PRIORITY
                        close a plan priority (Q-*) with this finding as the
                        answer — the plan loop Orchestrator.ingest closes
                        (unknown ids are reported, a missing plan logs
                        plan.answer_orphaned)
  --priority-outcome {answered,not-applicable,deprioritized}
                        how --answers-priority closes the priority (default:
                        answered)
  --json
  --from {slither,aderyn}
                        tool-output ingest (G1/I2a); requires
                        --json-file
`

// trajectoryLetterAliases is the M4 map: the runbook and prompt 39
// (trajectory dispatch) teach trajectories as A–H letters, while the
// schema enum wants full names. Single letters normalize here, at parse
// time; anything else passes through to schema validation unchanged
// (chain|model have no letters; junk still fails loudly there).
var trajectoryLetterAliases = map[string]string{
	"a": "code",
	"b": "economic",
	"c": "state-machine",
	"d": "attacker",
	"e": "historical",
	"f": "integration",
	"g": "drift",
	"h": "lifecycle",
}

// normalizeTrajectory maps a dispatch letter to its trajectory name.
func normalizeTrajectory(val string) string {
	if len(val) == 1 {
		if full, ok := trajectoryLetterAliases[strings.ToLower(val)]; ok {
			return full
		}
	}
	return val
}

// t14ExamplePayload is examples/hypothesis.example.json verbatim.
const t14ExamplePayload = `{
  "title": "ShareVault deposit inflates the share price for later depositors",
  "root_cause": {
    "class": "share-price-inflation",
    "description": "The first depositor sets the share price with a single wei, so all later depositors buy shares at a price the attacker chose, diluting their position.",
    "mechanism": "deposit() mints shares at total_assets/total_shares before any real assets are in the vault"
  },
  "affected": [
    {"path": "src/ShareVault.sol", "contract": "ShareVault",
     "function": "deposit", "lines": [42, 60], "entry_point": true}
  ],
  "attacker": {"profile": "arbitrary EOA", "capabilities": ["deposit"]},
  "evidence": [],
  "invariant": {
    "id": "INV-1",
    "statement": "a depositor's share of total assets may not decrease as a result of their own deposit"
  },
  "assumptions": [
    {
      "id": "A1",
      "type": "state",
      "claim": "the vault can be empty when the first deposit arrives",
      "status": "UNKNOWN",
      "model_belief": 0.9,
      "blocking": true
    }
  ],
  "preconditions": [
    {
      "kind": "state",
      "description": "vault is empty (total_shares == 0)",
      "satisfied_by": "be the first depositor"
    }
  ],
  "exploit_sequence": [
    {"step": 1, "actor": "attacker", "action": "deposit(1 wei) to set the share price"},
    {"step": 2, "actor": "victim", "action": "deposit(1 ETH) at the attacker-set price"}
  ]
}
`

// t14IngestOutcomes is the --priority-outcome choice list.
var t14IngestOutcomes = []string{"answered", "not-applicable", "deprioritized"}

// ingestArgs is the parsed command line.
type ingestArgs struct {
	campaign        string
	jsonFile        string
	example         bool
	from            string
	trajectory      string
	stage           string
	answersPriority string
	priorityOutcome string
	asJSON          bool
}

func runIngest(root string, args []string, r *Runner) error {
	a, err := parseIngest(args, r)
	if err != nil || a == nil {
		return err
	}
	// The consistency check comes BEFORE the --example branch: the example
	// prints a payload and returns, so a rejected flag combination used to be
	// accepted and silently ignored there.
	if a.priorityOutcome != "" && a.answersPriority == "" {
		return t14ExitErr(2, "--priority-outcome requires "+
			"--answers-priority (there is no plan priority to close "+
			"without it)\n")
	}
	if a.example {
		return printIngestExample(r)
	}
	if a.campaign == "" || a.jsonFile == "" {
		return t14ExitErr(2, "usage: webv2 ingest <campaign> --json-file "+
			"FILE (or -)   (or: webv2 ingest --example)\n")
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	if a.from != "" {
		return runIngestSast(root, c, a, r)
	}
	payload, err := t14ReadPayload(a.jsonFile)
	if err != nil {
		return err
	}
	if a.answersPriority != "" {
		if err := t14PrecheckAnswersPriority(c, a); err != nil {
			return err
		}
	}
	outcome := a.priorityOutcome
	if outcome == "" {
		outcome = "answered"
	}
	f, err := orchestrator.New(c).Ingest(payload, orchestrator.IngestOpts{
		Trajectory: a.trajectory, Stage: a.stage,
		AnswersPriority: a.answersPriority, PriorityOutcome: outcome})
	if err != nil {
		printIngestFailure(r, err)
		return t14ExitErr(2, "")
	}
	printIngestResult(r, f, a.asJSON)
	return nil
}

// sastLane is one tool-output adapter: the JSON->payloads reader plus the
// discovery stage its hypotheses are attributed to. The table is the ONLY
// place a SAST tool is declared — parseIngest's allowlist and the dispatch
// below both read it, so a new tool is one entry, not three edits.
type sastLane struct {
	toPayloads func(validation.Value) ([]validation.Value, error)
	stage      string
}

// sastLanes is the two-entry tool table (slither G1, aderyn I2a).
var sastLanes = map[string]sastLane{
	"slither": {toPayloads: slither.ToPayloads, stage: "sast-slither"},
	"aderyn":  {toPayloads: aderyn.ToPayloads, stage: "sast-aderyn"},
}

// sastTools is the allowlist in argparse declaration order (the `choose from`
// list order is the flag's declaration order, not map order).
var sastTools = []string{"slither", "aderyn"}

// runIngestSast is the SAST lane: tool JSON -> hypothesis payloads -> the
// SAME orchestrator ingest as a model payload. A rejected payload exits 2
// after reporting which check died — detector output is input, not verdict.
// parseIngest has already enforced the --from/--json-file dependency and the
// tool allowlist, so `a.from` always names a sastLanes entry here.
func runIngestSast(root string, c *state.Campaign, a *ingestArgs, r *Runner) error {
	lane := sastLanes[a.from]
	doc, err := t14ReadPayload(a.jsonFile) // existing ordered-JSON reader
	if err != nil {
		return t14ExitErr(2, "%s JSON unparsable: %s\n", a.from, err)
	}
	payloads, err := lane.toPayloads(doc)
	if err != nil {
		return t14ExitErr(2, "%s\n", err)
	}
	orch := orchestrator.New(c)
	stage := a.stage
	if stage == "" {
		stage = lane.stage
	}
	var created []string
	for _, p := range payloads {
		f, err := orch.Ingest(p, orchestrator.IngestOpts{
			Trajectory: a.trajectory, Stage: stage})
		if err != nil {
			printIngestFailure(r, err)
			return t14ExitErr(2, "")
		}
		created = append(created, objStr(f, "finding_id"))
	}
	fmt.Fprintf(r.Out, "%s ingest: %d hypotheses created\n", a.from, len(created))
	for _, id := range created {
		fmt.Fprintf(r.Out, "  %s\n", id)
	}
	return nil
}

// printIngestFailure is the stderr half of a rejected payload: the validation
// message plus the shape-contract hint (the shape-swap hint when the error
// names a known confusion).
func printIngestFailure(r *Runner, err error) {
	fmt.Fprintf(r.Err, "ingest failed: %s\n", err)
	if hint := t14IngestShapeHint(err.Error()); hint != "" {
		fmt.Fprintf(r.Err, "hint: %s\n", hint)
		return
	}
	fmt.Fprint(r.Err, "hint: the `webv2 ingest --example` payload is the "+
		"shape contract — diff yours against it (fields, nesting, value "+
		"types); the message above names the offending path\n")
}

// printIngestResult is the accepted-payload output: the taxonomy advisory and
// intake warnings are part of the record, so they are printed with the id.
func printIngestResult(r *Runner, f validation.Value, asJSON bool) {
	cls := objStr(objAt(f, "root_cause"), "class")
	advisory := taxonomy.ClassAdvisory(&cls)
	warnings := findings.IntakeCheckpoint(f,
		objStrDefault(f, "trajectory", "code"), objStr(f, "campaign_id"))
	if asJSON {
		t14PrintJSON(r.Out, validation.VObj(
			validation.KV{K: "finding", V: f},
			validation.KV{K: "class_advisory", V: t14OrNull(advisory)},
			validation.KV{K: "intake_warnings", V: t14StrArr(warnings)},
		))
		return
	}
	shown := cls
	if shown == "" {
		shown = "?"
	}
	fmt.Fprintf(r.Out, "ingested %s [%s] (class %s)\n",
		objStr(f, "finding_id"), objStr(f, "status"), shown)
	if advisory != "" {
		fmt.Fprintf(r.Out, "  ADVISORY: %s\n", advisory)
	}
	for _, w := range warnings {
		fmt.Fprintf(r.Out, "  warning: %s\n", w)
	}
}

// parseIngest is the argparse layer. ingest has no required argument, so a
// surplus/unrecognized argument is the only parse failure that can follow a
// successful scan.
func parseIngest(args []string, r *Runner) (*ingestArgs, error) {
	a := &ingestArgs{}
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t14IngestHelp)
			return nil, nil
		}
		if arg == "--example" {
			a.example = true
			continue
		}
		if arg == "--json" {
			a.asJSON = true
			continue
		}
		name, val, hasVal := splitFlag(arg)
		switch name {
		case "--json-file", "--trajectory", "--stage", "--answers-priority",
			"--priority-outcome":
			if !hasVal {
				if i+1 >= len(args) {
					return nil, t14ArgparseErr(t14IngestUsage, "ingest",
						"argument %s: expected one argument", name)
				}
				val = args[i+1]
				i++
			}
		case "--from":
			// argparse refuses to consume a token that looks like another
			// option, so `--from --json-file x` is "expected one argument".
			if !hasVal {
				if i+1 >= len(args) || looksLikeOption(args[i+1]) {
					return nil, t14ArgparseErr(t14IngestUsage, "ingest",
						"argument --from: expected one argument")
				}
				val = args[i+1]
				i++
			}
		}
		switch name {
		case "--json-file":
			a.jsonFile = val
		case "--from":
			a.from = val
		case "--trajectory":
			a.trajectory = normalizeTrajectory(val)
		case "--stage":
			a.stage = val
		case "--answers-priority":
			a.answersPriority = val
		case "--priority-outcome":
			if !t14InList(val, t14IngestOutcomes) {
				return nil, t14ArgparseErr(t14IngestUsage, "ingest",
					"argument --priority-outcome: invalid choice: %s "+
						"(choose from %s)", validation.PyReprStr(val),
					"'answered', 'not-applicable', 'deprioritized'")
			}
			a.priorityOutcome = val
		default:
			if strings.HasPrefix(arg, "-") {
				return nil, t14Unrecognized(arg)
			}
			pos = append(pos, arg)
		}
	}
	if a.from != "" {
		if _, ok := sastLanes[a.from]; !ok {
			return nil, t14ArgparseErr(t14IngestUsage, "ingest",
				"argument --from: invalid choice: %s (choose from %s)",
				validation.PyReprStr(a.from), quotedList(sastTools))
		}
	}
	// The SAST lane's dependency is a parse-time argparse failure: it must
	// fire before any command body, so a campaign that cannot be opened never
	// shadows the missing flag.
	if a.from != "" && a.jsonFile == "" {
		return nil, t14ExitErr(2,
			"argument --from: --json-file is required with --from\n")
	}
	if len(pos) > 1 {
		return nil, t14Unrecognized(strings.Join(pos[1:], " "))
	}
	if len(pos) == 1 {
		a.campaign = pos[0]
	}
	return a, nil
}

// t14ReadPayload is json.loads(sys.stdin.read()) for "-", else
// json.loads(Path(f).read_text()).
func t14ReadPayload(path string) (validation.Value, error) {
	if path == "-" {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return validation.VNull(), err
		}
		return t14ParseJSON(string(raw))
	}
	text, err := t14ReadText(path)
	if err != nil {
		return validation.VNull(), err
	}
	return t14ParseJSON(text)
}

// t14PrecheckAnswersPriority is the pre-ingest plan check: an unknown
// priority would otherwise leave the finding ingested with the question still
// open and the failure arriving as a traceback.
func t14PrecheckAnswersPriority(c *state.Campaign, a *ingestArgs) error {
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	if !t14Exists(planPath) {
		return nil // the API's plan.answer_orphaned log is a real state
	}
	raw, err := os.ReadFile(planPath)
	if err != nil {
		return t14ExitErr(2, "ingest failed: cannot read the campaign plan "+
			"(%s)\n", err)
	}
	plan, err := t14ParseJSON(string(raw))
	if err != nil {
		// cli.py surfaces json.JSONDecodeError's own text here, so the
		// CPython-parity scanner supplies the message.
		return t14ExitErr(2, "ingest failed: cannot read the campaign plan "+
			"(%s)\n", err)
	}
	priorities := t14List(plan, "priorities")
	if _, ok := t14FindByID(priorities, a.answersPriority); !ok {
		return t14ExitErr(2, "ingest failed: no priority %s in the campaign "+
			"plan — the question would stay open (`webv2 plan` lists the "+
			"ids)\n", validation.PyReprStr(a.answersPriority))
	}
	target, _ := t14FindByID(priorities, a.answersPriority)
	outcome := a.priorityOutcome
	if outcome == "" {
		outcome = "answered"
	}
	if objAt(target, "probe").Kind == validation.Obj &&
		t14InList(outcome, planner.ProbeRowDispositioned) {
		rowID := objStr(objAt(target, "probe"), "row_id")
		return t14ExitErr(2, "ingest failed: priority %s is probe row %s — "+
			"a probe disposition must name the field it claims is safe "+
			"(--anchor), which `ingest` cannot supply: ingest the finding "+
			"WITHOUT --answers-priority, then close the row with "+
			"`webv2 answered %s %s %s --reason <why> --actor <you> "+
			"--anchor <field>`\n",
			a.answersPriority, validation.PyReprStr(rowID), c.CampaignID,
			a.answersPriority, outcome)
	}
	return nil
}

// printIngestExample is the --example branch: the payload on stdout (pipeable),
// the contract statement and the schema-walked enum legend on stderr.
func printIngestExample(r *Runner) error {
	text := t14ExamplePayload
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	fmt.Fprint(r.Out, text)
	fmt.Fprint(r.Err, "This payload IS the ingest schema contract: the "+
		"fields, nesting and value types shown are exactly what "+
		"`webv2 ingest <campaign> --json-file` validates against — a "+
		"payload that differs in shape fails validation, and the error names "+
		"the offending field.\n")
	fmt.Fprint(r.Err, "save as payload.json, then: webv2 ingest <campaign> "+
		"--json-file payload.json\n(or pipe: webv2 ingest --example | "+
		"webv2 ingest <campaign> --json-file -)\n")
	// The fields alone do not tell a first pass what the closed enums may
	// say; the legend is WALKED from the schema at call time.
	legend, err := validation.SchemaEnumLegend("finding")
	if err != nil {
		return err
	}
	fmt.Fprint(r.Err, "closed-enum fields (auto-generated from "+
		"schema/finding.schema.json — every allowed value):\n")
	for _, line := range legend {
		fmt.Fprintf(r.Err, "  %s\n", line)
	}
	return nil
}

// t14IngestShapeHint is _ingest_shape_hint: the assumptions/preconditions
// shape swap every round-2 operator actually hit.
func t14IngestShapeHint(msg string) string {
	precond := []string{"'kind'", "'satisfied_by'", "'enforced_by_poc'"}
	assumption := []string{"'id'", "'claim'", "'model_belief'"}
	if strings.Contains(msg, "assumptions/") && t14AnyIn(msg, precond) {
		return "did you use the preconditions shape for an assumption? " +
			"assumptions need {id, type, claim, status, model_belief, " +
			"blocking}; preconditions need {kind, description, satisfied_by, " +
			"enforced_by_poc} — see `webv2 ingest --example`"
	}
	if strings.Contains(msg, "preconditions/") && t14AnyIn(msg, assumption) {
		return "did you use the assumptions shape for a precondition? " +
			"preconditions need {kind, description, satisfied_by, " +
			"enforced_by_poc}; assumptions need {id, type, claim, status, " +
			"model_belief, blocking} — see `webv2 ingest --example`"
	}
	return ""
}

// t14AnyIn is `any(k in msg for k in keys)`.
func t14AnyIn(msg string, keys []string) bool {
	for _, k := range keys {
		if strings.Contains(msg, k) {
			return true
		}
	}
	return false
}

// t14OrNull is Python's None for the JSON dump when there is nothing to say.
func t14OrNull(s string) validation.Value {
	if s == "" {
		return validation.VNull()
	}
	return validation.VStr(s)
}

// t14StrArr renders Go strings as a JSON array value.
func t14StrArr(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, it := range items {
		out = append(out, validation.VStr(it))
	}
	return validation.VArr(out...)
}

// objStrDefault is `v.get(key, default)` for string fields.
func objStrDefault(v validation.Value, key, def string) string {
	got := objAt(v, key)
	if got.Kind == validation.Str {
		return got.S
	}
	return def
}

// ---- schema-walked enum legend (validation.schema_enum_legend) ------------

// ---- CPython-compatible JSON error text -----------------------------------

// t14PyJSONError reproduces CPython's json.JSONDecodeError text for doc, or
// "" when doc decodes. Go's encoding/json reports a different shape ("invalid
// character 'b' looking for beginning of object key string"); the CLI's
// error lines are Python's, so the scanner below is a faithful port of
// json/decoder.py + json/scanner.py (positions are code points).
func t14PyJSONError(doc string) string {
	runes := []rune(doc)
	pos, msg := t14PyJSONDecode(runes)
	if msg == "" {
		return ""
	}
	if pos > len(runes) {
		pos = len(runes)
	}
	head := string(runes[:pos])
	line := 1 + strings.Count(head, "\n")
	col := pos - strings.LastIndex(head, "\n")
	return fmt.Sprintf("%s: line %d column %d (char %d)", msg, line, col, pos)
}

// t14PyJErr is CPython's JSONDecodeError payload (message + position).
type t14PyJErr struct {
	msg string
	pos int
}

// t14PyJSONDecode is JSONDecoder.decode: leading whitespace, one value, then
// trailing whitespace only.
func t14PyJSONDecode(s []rune) (int, string) {
	end, jerr := t14PyScanOnce(s, t14SkipWS(s, 0))
	if jerr != nil {
		return jerr.pos, jerr.msg
	}
	end = t14SkipWS(s, end)
	if end != len(s) {
		return end, "Extra data"
	}
	return 0, ""
}

// t14PyScanOnce is scanner._scan_once: the value at idx, or StopIteration(idx)
// as "Expecting value".
func t14PyScanOnce(s []rune, idx int) (int, *t14PyJErr) {
	if idx >= len(s) {
		return 0, &t14PyJErr{msg: "Expecting value", pos: idx}
	}
	switch {
	case s[idx] == '"':
		return t14PyScanString(s, idx+1)
	case s[idx] == '{':
		return t14PyObject(s, idx+1)
	case s[idx] == '[':
		return t14PyArray(s, idx+1)
	case s[idx] == 'n' && t14Runes(s, idx, idx+4) == "null":
		return idx + 4, nil
	case s[idx] == 't' && t14Runes(s, idx, idx+4) == "true":
		return idx + 4, nil
	case s[idx] == 'f' && t14Runes(s, idx, idx+5) == "false":
		return idx + 5, nil
	case s[idx] == 'N' && t14Runes(s, idx, idx+3) == "NaN":
		return idx + 3, nil
	case s[idx] == 'I' && t14Runes(s, idx, idx+8) == "Infinity":
		return idx + 8, nil
	case s[idx] == '-' && t14Runes(s, idx, idx+9) == "-Infinity":
		return idx + 9, nil
	}
	if loc := t14NumberRe.FindStringIndex(string(s[idx:])); loc != nil {
		return idx + len([]rune(string(s[idx:])[:loc[1]])), nil
	}
	return 0, &t14PyJErr{msg: "Expecting value", pos: idx}
}

// t14NumberRe is json.scanner.NUMBER_RE (anchored at the scan position).
var t14NumberRe = regexp.MustCompile(
	`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?`)

// t14PyObject is decoder.JSONObject.
func t14PyObject(s []rune, end int) (int, *t14PyJErr) {
	nextchar := t14At(s, end)
	if nextchar != '"' {
		if t14IsWS(nextchar) {
			end = t14SkipWS(s, end)
			nextchar = t14At(s, end)
		}
		if nextchar == '}' {
			return end + 1, nil
		}
		if nextchar != '"' {
			return 0, &t14PyJErr{msg: "Expecting property name enclosed in " +
				"double quotes", pos: end}
		}
	}
	end++
	for {
		var jerr *t14PyJErr
		if end, jerr = t14PyScanString(s, end); jerr != nil {
			return 0, jerr
		}
		if t14At(s, end) != ':' {
			end = t14SkipWS(s, end)
			if t14At(s, end) != ':' {
				return 0, &t14PyJErr{msg: "Expecting ':' delimiter", pos: end}
			}
		}
		end++
		if end < len(s) && t14IsWS(s[end]) {
			end++
			if end < len(s) && t14IsWS(s[end]) {
				end = t14SkipWS(s, end+1)
			}
		}
		if end, jerr = t14PyScanOnce(s, end); jerr != nil {
			return 0, jerr
		}
		nextchar = t14At(s, end)
		if t14IsWS(nextchar) {
			end = t14SkipWS(s, end)
			nextchar = t14At(s, end)
		}
		end++
		if nextchar == '}' {
			return end, nil
		}
		if nextchar != ',' {
			return 0, &t14PyJErr{msg: "Expecting ',' delimiter", pos: end - 1}
		}
		commaIdx := end - 1
		end = t14SkipWS(s, end)
		nextchar = t14At(s, end)
		end++
		if nextchar != '"' {
			if nextchar == '}' {
				return 0, &t14PyJErr{msg: "Illegal trailing comma before " +
					"end of object", pos: commaIdx}
			}
			return 0, &t14PyJErr{msg: "Expecting property name enclosed in " +
				"double quotes", pos: end - 1}
		}
	}
}

// t14PyArray is decoder.JSONArray.
func t14PyArray(s []rune, end int) (int, *t14PyJErr) {
	nextchar := t14At(s, end)
	if t14IsWS(nextchar) {
		end = t14SkipWS(s, end)
		nextchar = t14At(s, end)
	}
	if nextchar == ']' {
		return end + 1, nil
	}
	for {
		var jerr *t14PyJErr
		if end, jerr = t14PyScanOnce(s, end); jerr != nil {
			return 0, jerr
		}
		nextchar = t14At(s, end)
		if t14IsWS(nextchar) {
			end = t14SkipWS(s, end)
			nextchar = t14At(s, end)
		}
		end++
		if nextchar == ']' {
			return end, nil
		}
		if nextchar != ',' {
			return 0, &t14PyJErr{msg: "Expecting ',' delimiter", pos: end - 1}
		}
		commaIdx := end - 1
		if end < len(s) && t14IsWS(s[end]) {
			end++
			if end < len(s) && t14IsWS(s[end]) {
				end = t14SkipWS(s, end+1)
			}
		}
		nextchar = t14At(s, end)
		if nextchar == ']' {
			return 0, &t14PyJErr{msg: "Illegal trailing comma before end " +
				"of array", pos: commaIdx}
		}
	}
}

// t14PyScanString is decoder.py_scanstring (end is the index after the
// opening quote).
func t14PyScanString(s []rune, end int) (int, *t14PyJErr) {
	begin := end - 1
	for {
		i := end
		for i < len(s) && s[i] != '"' && s[i] != '\\' && s[i] >= 0x20 {
			i++
		}
		if i >= len(s) {
			return 0, &t14PyJErr{msg: "Unterminated string starting at",
				pos: begin}
		}
		terminator := s[i]
		end = i + 1
		if terminator == '"' {
			return end, nil
		}
		if terminator != '\\' {
			// the C scanner (what json.loads uses) omits py_scanstring's
			// {!r} of the offending character
			return 0, &t14PyJErr{msg: "Invalid control character at",
				pos: end - 1}
		}
		if end >= len(s) {
			return 0, &t14PyJErr{msg: "Unterminated string starting at",
				pos: begin}
		}
		esc := s[end]
		if esc != 'u' {
			if !strings.ContainsRune("\"\\/bfnrt", esc) {
				// the C scanner points at the backslash, not the escape
				return 0, &t14PyJErr{msg: "Invalid \\escape", pos: end - 1}
			}
			end++
			continue
		}
		uni, jerr := t14DecodeUXXXX(s, end)
		if jerr != nil {
			return 0, jerr
		}
		end += 5
		if uni >= 0xd800 && uni <= 0xdbff && t14Runes(s, end, end+2) == "\\u" {
			uni2, jerr2 := t14DecodeUXXXX(s, end+1)
			if jerr2 != nil {
				return 0, jerr2
			}
			if uni2 >= 0xdc00 && uni2 <= 0xdfff {
				end += 6
			}
		}
	}
}

// t14DecodeUXXXX is decoder._decode_uXXXX (pos is the index of the "u").
func t14DecodeUXXXX(s []rune, pos int) (int, *t14PyJErr) {
	if pos+5 <= len(s) {
		v := 0
		ok := true
		for _, r := range s[pos+1 : pos+5] {
			d, good := t14HexVal(r)
			if !good {
				ok = false
				break
			}
			v = v*16 + d
		}
		if ok {
			return v, nil
		}
	}
	return 0, &t14PyJErr{msg: "Invalid \\uXXXX escape", pos: pos}
}

// t14HexVal is one hex digit.
func t14HexVal(r rune) (int, bool) {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0'), true
	case r >= 'a' && r <= 'f':
		return int(r-'a') + 10, true
	case r >= 'A' && r <= 'F':
		return int(r-'A') + 10, true
	}
	return 0, false
}

// t14At is s[i:i+1] ("" out of range).
func t14At(s []rune, i int) rune {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

// t14Runes is s[a:b] as a string (clamped).
func t14Runes(s []rune, a, b int) string {
	if a < 0 {
		a = 0
	}
	if b > len(s) {
		b = len(s)
	}
	if a >= b {
		return ""
	}
	return string(s[a:b])
}

// t14IsWS is `c in " \t\n\r"`.
func t14IsWS(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// t14SkipWS is WHITESPACE.match(s, i).end().
func t14SkipWS(s []rune, i int) int {
	for i < len(s) && t14IsWS(s[i]) {
		i++
	}
	return i
}

func init() {
	register(command{ord: 32, name: "ingest",
		line: `ingest <campaign> --json-file F    ingest a hypothesis payload`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runIngest(root, args, r)
			})
		}})
}
