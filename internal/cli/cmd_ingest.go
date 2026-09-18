package cli

// cmd_ingest: `webv2 ingest [campaign] --json-file F [--example] [--trajectory T]
// [--stage S] [--answers-priority Q] [--priority-outcome O] [--json] [--lint]
// [--no-hints]` — ingest a model-produced hypothesis payload: schema-validated,
// dedup-fingerprinted, intake-checked, with the taxonomy advisory and intake
// warnings logged WITH the finding. cli.py cmd_ingest verbatim.
//
// `--no-hints` (B9) suppresses the write-time hygiene note; it is documented
// in the verb's help and implemented in hints.go.
//
// `--lint` (wave N, T4) threads a lint flag into the SAME run function and the
// same orchestrator call: the payload travels the exact real pipeline (schema
// -> exec_ref ledger checks -> gate math) and the command prints exactly what a
// real ingest prints — the acceptance line or the refusal, same streams, exit 0
// / 2 — while the single write guard in findings.ingestHypothesis (plus the
// orchestrator's stage/plan closure guard) keeps the campaign untouched. There
// is no second validator: `--lint` cannot drift from `ingest`.
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
	"websec/internal/orchestrator"
	"websec/internal/validation"
)

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
		AnswersPriority: a.answersPriority, PriorityOutcome: outcome,
		Lint: a.lint})
	if err != nil {
		printIngestFailure(r, err)
		return t14ExitErr(2, "")
	}
	printIngestResult(r, c, f, a.asJSON)
	// B9: the capped, suppressible write-time hygiene note. It rides stderr,
	// AFTER the success bytes above (stdout is untouched), and it can never
	// fail this run — emitWriteHints is void and swallows every read error.
	emitWriteHints(c, []validation.Value{f}, a.noHints, r.Err)
	return nil
}

func init() {
	register(command{ord: 32, name: "ingest",
		line: `ingest <campaign> --json-file F [--lint]    ingest a hypothesis payload`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runIngest(root, args, r)
			})
		}})
}
