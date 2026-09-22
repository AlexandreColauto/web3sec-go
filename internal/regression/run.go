package regression

import (
	"fmt"
	"os"

	"websec/internal/state"
	"websec/internal/validation"
)

// Scorers is the closed vocabulary of coarse scorers this suite ingests.
// §3a: "Use ScaBench's own scorer for coarse tracking only" — and the
// framework's own offline gold scorer is the second, deterministic half.
var Scorers = []string{"eval-gold", "scabench-judge"}

// measurementRediscovery is §3a's D8 label, written on every run path and
// pinned as a schema const: a run record that does not say `rediscovery`
// cannot be written at all.
const measurementRediscovery = "rediscovery"

// evalGoldKeys is the exact stdout key set of scripts/eval-gold.py, pinned
// from that script's own docstring contract. TestEvalGoldKeysMatchTheRealScorer
// runs the real script (when python3 is on PATH) and compares, so this list
// cannot drift away from the scorer it claims to read.
var evalGoldKeys = []string{
	"found", "missed", "false_positives", "pass", "bonus", "verdict",
	"verdict_note", "operator_confirmed",
}

// RunSpec is one run to record. eval-gold reads ScoreFile; scabench-judge
// takes the operator's transcription of the judge's report plus the report's
// own URL — the suite never parses the judge, it records what the operator
// read and where they read it.
type RunSpec struct {
	TargetID       string
	Scorer         string
	ScoreFile      string
	Found          int64
	Missed         int64
	FalsePositives int64
	Verdict        string
	VerdictNote    string
	ReportURL      string
	ArtifactID     string
	Notes          string
}

// NormalizeScore translates one scorer's own vocabulary into the suite's
// coarse score. It refuses an unknown scorer, a missing key, and an unknown
// key: a scorer whose output grew a field must be re-read by a human, never
// half-ingested.
func NormalizeScore(scorer string, raw validation.Value) (validation.Value, error) {
	switch scorer {
	case "eval-gold":
		return normalizeEvalGold(raw)
	case "scabench-judge":
		return normalizeJudge(raw)
	}
	return validation.VNull(), fmt.Errorf("unknown scorer %q (known: %v)", scorer, Scorers)
}

// kindName renders a Value's kind as the Python type name the rest of the
// CLI uses: a refusal that says "list" instead of "115" helps nobody (the
// ordered-JSON Kind is a rune with no String() method).
//
// It is byte-for-byte internal/pipeline/status.go's kindName, and it is a
// copy rather than a call for a hard reason: that helper is UNEXPORTED, so no
// package outside internal/pipeline can reach it, and exporting it would put
// a new public name on a Python-semantics port for one caller. The house rule
// covers the rest — small helpers are duplicated, not exported. This copy is
// the only one of the three that records the decision: internal/pipeline's
// carries no comment at all, and internal/completion/support.go:110's
// describes the Python type name, not the duplication. The D8 note in Task 1's
// report claimed no such helper existed; that claim was wrong, and this
// comment is the correction.
func kindName(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "NoneType"
	case validation.Bool:
		return "bool"
	case validation.Int:
		return "int"
	case validation.Flt:
		return "float"
	case validation.Str:
		return "str"
	case validation.Arr:
		return "list"
	case validation.Obj:
		return "dict"
	}
	return "NoneType"
}

// checkEvalGoldKeys refuses a key this adapter does not know: a scorer whose
// output grew a field must be re-read by a human, never half-ingested.
func checkEvalGoldKeys(raw validation.Value) error {
	for _, kvp := range raw.O {
		if !contains(evalGoldKeys, kvp.K) {
			return fmt.Errorf("eval-gold output carries key %q, which this adapter does not know — re-read scripts/eval-gold.py's contract and extend evalGoldKeys deliberately", kvp.K)
		}
	}
	return nil
}

// evalGoldCounts normalizes the scorer's three count keys. In the scorer's
// REAL output `found` and `missed` are arrays of gold ids (eval-gold.py:
// `"missed": [g for g in ids if g not in found]`), so the count is the array's
// length; `false_positives` is already an integer. The ids themselves stay in
// the score file, whose sha256 every run records.
func evalGoldCounts(raw validation.Value) ([]validation.KV, error) {
	out := make([]validation.KV, 0, 3)
	for _, k := range []string{"found", "missed"} {
		v := validation.ObjAt(raw, k)
		if v.Kind != validation.Arr {
			return nil, fmt.Errorf("eval-gold output key %q is %s, want the scorer's array of gold ids", k, kindName(v))
		}
		out = append(out, kv(k, validation.VInt(int64(len(v.A)))))
	}
	fp := validation.ObjAt(raw, "false_positives")
	if fp.Kind != validation.Int {
		return nil, fmt.Errorf("eval-gold output key %q is %s, want an integer", "false_positives", kindName(fp))
	}
	return append(out, kv("false_positives", fp)), nil
}

// normalizeEvalGold is the eval-gold adapter: the scorer's eight keys in, the
// suite's four counts and one verdict out.
func normalizeEvalGold(raw validation.Value) (validation.Value, error) {
	if raw.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf("eval-gold output must be one JSON object, got %s", kindName(raw))
	}
	if err := checkEvalGoldKeys(raw); err != nil {
		return validation.VNull(), err
	}
	counts, err := evalGoldCounts(raw)
	if err != nil {
		return validation.VNull(), err
	}
	verdict := validation.ObjStr(raw, "verdict")
	if verdict == "" {
		return validation.VNull(), fmt.Errorf("eval-gold output carries no verdict string")
	}
	out := validation.VObj(counts...)
	out.O = validation.SetOrAppend(out.O, "verdict", validation.VStr(verdict))
	if note := validation.ObjStr(raw, "verdict_note"); note != "" {
		out.O = validation.SetOrAppend(out.O, "verdict_note", validation.VStr(note))
	}
	return out, nil
}

// normalizeJudge is the transcribed-score adapter: the operator's counts,
// already in the suite's vocabulary.
func normalizeJudge(raw validation.Value) (validation.Value, error) {
	if raw.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf("a transcribed judge score must be an object")
	}
	return raw, nil
}

// readEvalGoldFile reads the scorer's saved stdout and digests it.
func readEvalGoldFile(spec RunSpec) (validation.Value, string, error) {
	if spec.ScoreFile == "" {
		return validation.VNull(), "", fmt.Errorf("eval-gold needs --score-file (the scorer's stdout, saved)")
	}
	data, err := os.ReadFile(spec.ScoreFile)
	if err != nil {
		return validation.VNull(), "", err
	}
	raw, err := validation.ParseOrdered(data)
	if err != nil {
		return validation.VNull(), "", err
	}
	sha, err := validation.Sha256File(spec.ScoreFile)
	if err != nil {
		return validation.VNull(), "", err
	}
	return raw, sha, nil
}

// judgeInput turns the operator's transcription into a raw score object. A
// transcribed score that does not cite its report is refused — an uncited
// number is exactly the kind of fact this suite exists to refuse.
func judgeInput(spec RunSpec) (validation.Value, string, error) {
	if spec.ReportURL == "" {
		return validation.VNull(), "", fmt.Errorf("a transcribed judge score must cite --report-url — an uncited number is not a measurement")
	}
	if spec.Found < 0 || spec.Missed < 0 || spec.FalsePositives < 0 {
		return validation.VNull(), "", fmt.Errorf("score counts cannot be negative")
	}
	if spec.Verdict == "" {
		return validation.VNull(), "", fmt.Errorf("a transcribed score needs --verdict")
	}
	raw := validation.VObj(
		kv("found", validation.VInt(spec.Found)),
		kv("missed", validation.VInt(spec.Missed)),
		kv("false_positives", validation.VInt(spec.FalsePositives)),
		kv("verdict", validation.VStr(spec.Verdict)),
	)
	if spec.VerdictNote != "" {
		raw.O = validation.SetOrAppend(raw.O, "verdict_note", validation.VStr(spec.VerdictNote))
	}
	return raw, "", nil
}

// scorerInput is the raw score and its file digest for one run.
func scorerInput(spec RunSpec) (validation.Value, string, error) {
	switch spec.Scorer {
	case "eval-gold":
		return readEvalGoldFile(spec)
	case "scabench-judge":
		return judgeInput(spec)
	}
	return validation.VNull(), "", fmt.Errorf("unknown scorer %q (known: %v)", spec.Scorer, Scorers)
}

// runDoc builds one run record document.
func runDoc(c *state.Campaign, spec RunSpec, rid string, score validation.Value,
	sha string) validation.Value {
	doc := validation.VObj(
		kv("run_id", validation.VStr(rid)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("scorer", validation.VStr(spec.Scorer)),
		kv("score", score),
		// §3a D8, structural: the label is not a comment, it is a required
		// const in the schema and it is written on every path.
		kv("measurement", validation.VStr(measurementRediscovery)),
		kv("is_detection_rate", validation.VBool(false)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("schema_version", validation.VInt(1)),
	)
	doc.O = withOptional(doc.O,
		optionalStr{"score_file_sha256", sha},
		optionalStr{"report_url", spec.ReportURL},
		optionalStr{"artifact_id", spec.ArtifactID},
		optionalStr{"notes", spec.Notes},
	)
	return doc
}

// runEventData is the one ledger event that goes with one run record.
func runEventData(rid, targetID, scorer string, score validation.Value) validation.Value {
	return validation.VObj(
		kv("run_id", validation.VStr(rid)),
		kv("target_id", validation.VStr(targetID)),
		kv("scorer", validation.VStr(scorer)),
		kv("score", score),
		kv("measurement", validation.VStr(measurementRediscovery)),
	)
}

// RecordRun writes one run record. Two refusals beyond NormalizeScore's: the
// target must exist in this campaign, and a transcribed (judge) score must
// cite the report it was transcribed from.
func RecordRun(c *state.Campaign, spec RunSpec) (validation.Value, error) {
	if !contains(Scorers, spec.Scorer) {
		return validation.VNull(), fmt.Errorf("unknown scorer %q (known: %v)", spec.Scorer, Scorers)
	}
	if err := requireTarget(c, spec.TargetID); err != nil {
		return validation.VNull(), err
	}
	raw, sha, err := scorerInput(spec)
	if err != nil {
		return validation.VNull(), err
	}
	score, err := NormalizeScore(spec.Scorer, raw)
	if err != nil {
		return validation.VNull(), err
	}
	rid := state.NewID("RUN", 12)
	doc := runDoc(c, spec, rid, score, sha)
	data := runEventData(rid, spec.TargetID, spec.Scorer, score)
	return writeThenLog(c, runPath(c, rid), doc, "regression_run",
		"regression.run.recorded", &rid, data)
}

// LoadRuns is every run record in the campaign, in file order.
func LoadRuns(c *state.Campaign) ([]validation.Value, error) {
	return loadRecords(RunsDir(c), "RUN-")
}
