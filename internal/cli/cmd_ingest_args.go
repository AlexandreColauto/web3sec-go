package cli

// cmd_ingest_args: ingest's argparse layer — usage/help text, the
// parsed args struct and the token scan / cross-flag validation (moved
// verbatim from cmd_ingest.go, which keeps the concern's documentation,
// the entry point and the registration).
import (
	"fmt"
	"strings"
	"websec/internal/validation"
)

const t14IngestUsage = `usage: webv2 ingest [-h] [--json-file JSON_FILE] [--example]
                    [--trajectory TRAJECTORY] [--stage STAGE]
                    [--answers-priority ANSWERS_PRIORITY]
                    [--priority-outcome {answered,not-applicable,deprioritized}]
                    [--json]
                    [--from {slither,aderyn}]
                    [--lint]
                    [campaign]
`

const t14IngestHelp = `usage: webv2 ingest [-h] [--json-file JSON_FILE] [--example]
                    [--trajectory TRAJECTORY] [--stage STAGE]
                    [--answers-priority ANSWERS_PRIORITY]
                    [--priority-outcome {answered,not-applicable,deprioritized}]
                    [--json]
                    [--from {slither,aderyn}]
                    [--lint]
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
  --lint                validate the payload through the whole ingest
                        pipeline (schema, ledger, gate math) and print what
                        a real ingest would print — accept or refuse — but
                        write nothing: no state change, no events, no
                        finding files (exit 0 accepted / 2 refused)
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
	lint            bool
}

// parseIngest is the argparse layer. ingest has no required argument, so a
// surplus/unrecognized argument is the only parse failure that can follow a
// successful scan.
func parseIngest(args []string, r *Runner) (*ingestArgs, error) {
	a := &ingestArgs{}
	pos, help, err := parseIngestScan(args, a, r)
	if err != nil {
		return nil, err
	}
	if help {
		return nil, nil
	}
	if err := parseIngestValidate(a, pos); err != nil {
		return nil, err
	}
	if len(pos) == 1 {
		a.campaign = pos[0]
	}
	return a, nil
}

// parseIngestScan is the argparse token loop; a consumed -h/--help prints
// the help block and reports help=true.
func parseIngestScan(args []string, a *ingestArgs, r *Runner) (pos []string, help bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t14IngestHelp)
			return nil, true, nil
		}
		if arg == "--example" {
			a.example = true
			continue
		}
		if arg == "--json" {
			a.asJSON = true
			continue
		}
		if arg == "--lint" {
			a.lint = true
			continue
		}
		name, val, hasVal := splitFlag(arg)
		val, n, err := parseIngestValue(args, i, name, val, hasVal)
		if err != nil {
			return nil, false, err
		}
		i += n
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
				return nil, false, t14ArgparseErr(t14IngestUsage, "ingest",
					"argument --priority-outcome: invalid choice: %s "+
						"(choose from %s)", validation.PyReprStr(val),
					"'answered', 'not-applicable', 'deprioritized'")
			}
			a.priorityOutcome = val
		default:
			if strings.HasPrefix(arg, "-") {
				return nil, false, t14Unrecognized(arg)
			}
			pos = append(pos, arg)
		}
	}
	return pos, false, nil
}

// parseIngestValue consumes the separate-argument form of an option value at
// args[i]; it returns the value and how many extra argv tokens were consumed.
func parseIngestValue(args []string, i int, name, val string, hasVal bool) (string, int, error) {
	switch name {
	case "--json-file", "--trajectory", "--stage", "--answers-priority",
		"--priority-outcome":
		if !hasVal {
			if i+1 >= len(args) {
				return "", 0, t14ArgparseErr(t14IngestUsage, "ingest",
					"argument %s: expected one argument", name)
			}
			return args[i+1], 1, nil
		}
	case "--from":
		// argparse refuses to consume a token that looks like another
		// option, so `--from --json-file x` is "expected one argument".
		if !hasVal {
			if i+1 >= len(args) || looksLikeOption(args[i+1]) {
				return "", 0, t14ArgparseErr(t14IngestUsage, "ingest",
					"argument --from: expected one argument")
			}
			return args[i+1], 1, nil
		}
	}
	return val, 0, nil
}

// parseIngestValidate runs the cross-flag checks that follow the token scan:
// the --from lane choice, its parse-time --json-file dependency and the
// surplus-positional rejection.
func parseIngestValidate(a *ingestArgs, pos []string) error {
	if a.from != "" {
		if _, ok := sastLanes[a.from]; !ok {
			return t14ArgparseErr(t14IngestUsage, "ingest",
				"argument --from: invalid choice: %s (choose from %s)",
				validation.PyReprStr(a.from), quotedList(sastTools))
		}
	}
	// The SAST lane's dependency is a parse-time argparse failure: it must
	// fire before any command body, so a campaign that cannot be opened never
	// shadows the missing flag.
	if a.from != "" && a.jsonFile == "" {
		return t14ExitErr(2,
			"argument --from: --json-file is required with --from\n")
	}
	if len(pos) > 1 {
		return t14Unrecognized(strings.Join(pos[1:], " "))
	}
	return nil
}
