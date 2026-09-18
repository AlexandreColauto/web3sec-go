package cli

// cmd_ingest_helpers: ingest's input helpers — the trajectory
// dispatch-letter alias map, the payload reader, the answers-priority
// precheck and the small validation-value helpers (moved verbatim from
// cmd_ingest.go).
import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

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
	if validation.ObjAt(target, "probe").Kind == validation.Obj &&
		t14InList(outcome, planner.ProbeRowDispositioned) {
		rowID := validation.ObjStr(validation.ObjAt(target, "probe"), "row_id")
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
	got := validation.ObjAt(v, key)
	if got.Kind == validation.Str {
		return got.S
	}
	return def
}
