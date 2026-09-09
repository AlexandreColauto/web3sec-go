package cli

// cmd_t23_shared: the shared surface of the T23 verbs (chains, terminals,
// privileged, impact, ladder) — argparse-exact usage/help blocks captured
// from the Python reference, the Python float formatters they need, and the
// seam wiring Python performs at import time (chain_engine, maximization,
// learning.queue_memory).

import (
	"strconv"
	"strings"

	"websec/internal/bounty"
	"websec/internal/chainengine"
	"websec/internal/completion"
	"websec/internal/maximization"
	"websec/internal/orchestrator"
	"websec/internal/pipeline"
	"websec/internal/state"
	"websec/internal/validation"
)

// --- usage blocks (captured from the live Python CLI at COLUMNS=80) --------

const t23ChainsUsage = "usage: webv2 chains [-h] campaign\n"
const t23TerminalsUsage = "usage: webv2 terminals [-h] campaign\n"
const t23PrivilegedUsage = "usage: webv2 privileged [-h] campaign\n"

const t23ImpactUsage = `usage: webv2 impact [-h] [--extractable EXTRACTABLE] [--max-loss MAX_LOSS]
                    [--required-capital REQUIRED_CAPITAL]
                    [--artifact ARTIFACT] [--description DESCRIPTION]
                    [--unpriceable] [--ceiling CEILING] [--reason REASON]
                    [--actor ACTOR]
                    campaign finding
`

const t23LadderUsage = `usage: webv2 ladder [-h] [--name NAME] [--description DESCRIPTION]
                    [--axes AXES] [--capital CAPITAL] [--ratio RATIO]
                    [--removes REMOVES] [--note NOTE] [--reason REASON]
                    [--exec EXEC_ID] [--actor ACTOR]
                    campaign
                    {start,show,explore,add,repro,disprove,set-maximal,complete,waive,report}
                    [finding] [rung] [axis]
`

// t23LadderActions is the action choice list, in cli.py order.
var t23LadderActions = []string{"start", "show", "explore", "add", "repro",
	"disprove", "set-maximal", "complete", "waive", "report"}

// --- argparse help (stdout, exit 0) ----------------------------------------

const t23ChainsHelp = `usage: webv2 chains [-h] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
`

const t23TerminalsHelp = `usage: webv2 terminals [-h] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
`

const t23PrivilegedHelp = `usage: webv2 privileged [-h] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
`

const t23ImpactHelp = `usage: webv2 impact [-h] [--extractable EXTRACTABLE] [--max-loss MAX_LOSS]
                    [--required-capital REQUIRED_CAPITAL]
                    [--artifact ARTIFACT] [--description DESCRIPTION]
                    [--unpriceable] [--ceiling CEILING] [--reason REASON]
                    [--actor ACTOR]
                    campaign finding

positional arguments:
  campaign
  finding

options:
  -h, --help            show this help message and exit
  --extractable EXTRACTABLE
                        extractable_usd
  --max-loss MAX_LOSS   max_loss_usd
  --required-capital REQUIRED_CAPITAL
                        attacker required capital
  --artifact ARTIFACT   path to the impact evidence artifact (fork dump / TVL
                        snapshot); registers it and mints E7
  --description DESCRIPTION
                        E7 evidence description
  --unpriceable         record the NAMED DECISION that no USD figure is
                        defensible; requires --ceiling, --reason and --actor,
                        and satisfies the economic-class E7 clause
  --ceiling CEILING     capacity basis for --unpriceable (why no figure is
                        defensible)
  --reason REASON       written reason for --unpriceable
  --actor ACTOR         who decided (required with --unpriceable)
`

const t23LadderHelp = `usage: webv2 ladder [-h] [--name NAME] [--description DESCRIPTION]
                    [--axes AXES] [--capital CAPITAL] [--ratio RATIO]
                    [--removes REMOVES] [--note NOTE] [--reason REASON]
                    [--exec EXEC_ID] [--actor ACTOR]
                    campaign
                    {start,show,explore,add,repro,disprove,set-maximal,complete,waive,report}
                    [finding] [rung] [axis]

positional arguments:
  campaign
  {start,show,explore,add,repro,disprove,set-maximal,complete,waive,report}
  finding               the finding (report: optional)
  rung                  rung id (repro/disprove/set-maximal)
  axis                  axis (explore)

options:
  -h, --help            show this help message and exit
  --name NAME           rung name (add)
  --description DESCRIPTION
                        what the rung changes (add)
  --axes AXES           comma-separated axes (add)
  --capital CAPITAL     attacker capital USD (add)
  --ratio RATIO         extraction ratio 0..1 (add)
  --removes REMOVES     semicolon-separated removed preconditions (add)
  --note NOTE           written reason (explore: why the axis is not
                        applicable)
  --reason REASON       written reason (disprove/waive)
  --exec EXEC_ID        EXEC id (repro)
  --actor ACTOR         who acts (complete/waive)
`

// --- python float formatting ----------------------------------------------

// t23Money0 is Python's f"{x:,.0f}".
func t23Money0(f float64) string {
	s := strconv.FormatFloat(f, 'f', 0, 64)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// t23PyG is Python's f"{x:g}" (6 significant digits, trailing zeros dropped).
func t23PyG(f float64) string {
	return strconv.FormatFloat(f, 'g', 6, 64)
}

// t23FloatArg parses an argparse `type=float` value. The error text is
// argparse's: `argument --flag: invalid float value: 'abc'`.
func t23FloatArg(cmd, flag, raw string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0, t14ArgparseErr(t23UsageFor(cmd), cmd,
			"argument %s: invalid float value: %s", flag,
			validation.PyReprStr(raw))
	}
	return f, nil
}

// t23UsageFor maps a verb to its argparse usage block.
func t23UsageFor(cmd string) string {
	switch cmd {
	case "chains":
		return t23ChainsUsage
	case "terminals":
		return t23TerminalsUsage
	case "privileged":
		return t23PrivilegedUsage
	case "impact":
		return t23ImpactUsage
	case "ladder":
		return t23LadderUsage
	}
	return t23ChainsUsage
}

// t23HelpFor maps a verb to its help block.
func t23HelpFor(cmd string) string {
	switch cmd {
	case "chains":
		return t23ChainsHelp
	case "terminals":
		return t23TerminalsHelp
	case "privileged":
		return t23PrivilegedHelp
	case "impact":
		return t23ImpactHelp
	case "ladder":
		return t23LadderHelp
	}
	return t23ChainsHelp
}

// t23ValueArg consumes an option's value, mirroring argparse: a token that
// looks like an option (a "-" prefix that is not a negative number) is never
// taken as a value, so `--reason -foo` fails exactly as Python does.
func t23ValueArg(args []string, i int, usage, prog, name string) (string, error) {
	if i+1 >= len(args) ||
		(t23IsOption(args[i+1]) && !t23NegativeNumber(args[i+1])) {
		return "", t14ArgparseErr(usage, prog,
			"argument %s: expected one argument", name)
	}
	return args[i+1], nil
}

// t23NegativeNumber is argparse's negative-number test for value slots: a
// digit or "." directly after the dash (so -5, -.5 and -1e3 are values).
func t23NegativeNumber(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	return (s[1] >= '0' && s[1] <= '9') || s[1] == '.'
}

// t23IsOption is argparse's option test: anything starting with "-" except a
// lone "-" (which argparse keeps as a positional).
func t23IsOption(arg string) bool {
	return len(arg) > 1 && strings.HasPrefix(arg, "-")
}

// t23None is Python's repr(None) as these verbs render it: an absent optional
// positional. Finding ids, rung ids and axes are never empty in the data
// model, so "" faithfully stands in for None.
const t23None = "None"

// t23PyNone is `x if x is not None else "None"`.
func t23PyNone(s string) string {
	if s == "" {
		return t23None
	}
	return s
}

// --- seam wiring -----------------------------------------------------------

// init wires the T23 ports into the seams Python connects at import time.
// The CLI is driven directly by tests, so the connections must not wait for
// cmd/webv2/main.go.
func init() { t23WireSeams() }

// t23WireSeams connects every seam Python's imports connect. Idempotent:
// every setter just replaces the target.
func t23WireSeams() {
	orchestrator.SetChainEngine(orchestrator.ChainEngineAPI{
		ChainReport: chainengine.ChainReport})
	completion.SetMaximization(t23Maximization{})
	pipeline.SetMaximization(t23Maximization{})
	bounty.SetLoadLadder(t23LoadLadder)
}

// t23Maximization adapts maximization.LoadLadder (a *Value, Python's None)
// onto the seams' (Value, Null-when-absent) shape.
type t23Maximization struct{}

func (t23Maximization) LoadLadder(c *state.Campaign,
	findingID string) (validation.Value, error) {
	return t23LoadLadder(c, findingID)
}

// t23LoadLadder is maximization.load_ladder with None mapped to Null.
func t23LoadLadder(c *state.Campaign, findingID string) (validation.Value, error) {
	lad, err := maximization.LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if lad == nil {
		return validation.VNull(), nil
	}
	return *lad, nil
}
