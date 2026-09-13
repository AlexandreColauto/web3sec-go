package findings_test

// gate_remediation_guard_test.go: the wave-N T1 pin-vs-reality guard. A
// remediation hint is operator-facing copy of a command, and copy drifts from
// the parser silently — the `critic-verdict` entry told operators to run
// `webv2 verdict <fid> confirmed '<reasoning>' --actor <you>` for months
// while cmd_verdict.go accepted neither that positional shape nor --actor.
//
// The guard reads the CLI dispatch registry (cli.CommandNames) instead of
// grepping the command sources: a hint that opens `webv2 <verb>` may only
// name a verb the dispatcher really has, and the verdict hint must carry the
// flags cmd_verdict.go requires.

import (
	"strings"
	"testing"

	"websec/internal/cli"
	"websec/internal/findings"
)

func TestGateRemediationVerbsAreDispatched(t *testing.T) {
	verbs := map[string]bool{}
	for _, name := range cli.CommandNames() {
		verbs[name] = true
	}
	if len(verbs) == 0 {
		t.Fatal("CLI dispatch registry is empty — this guard would pass vacuously")
	}

	named := 0
	for check, entry := range findings.GATE_REMEDIATION {
		fields := strings.Fields(entry)
		if len(fields) < 2 || fields[0] != "webv2" {
			continue // prose entry, or one that names no command first
		}
		verb := fields[1]
		if strings.HasPrefix(verb, "-") || strings.HasPrefix(verb, "<") {
			continue // a flag or a metavariable, not a verb
		}
		named++
		if !verbs[verb] {
			t.Errorf("GATE_REMEDIATION[%q] tells the operator to run %q, which "+
				"the CLI does not dispatch: %q", check, verb, entry)
		}
	}
	if named == 0 {
		t.Fatal("no GATE_REMEDIATION entry names a `webv2 <verb>` command — " +
			"this guard has gone blind to the catalog")
	}

	// cmd_verdict.go: `webv2 verdict <campaign> <finding> --verdict V
	// --reason R` — two POSITIONALS (the campaign is not optional), both
	// flags required, and `--actor` is not a recognized argument (it fails
	// as "unrecognized arguments: --actor").
	hint := findings.GATE_REMEDIATION["critic-verdict"]
	fields := strings.Fields(hint)
	if len(fields) < 4 || strings.HasPrefix(fields[2], "-") ||
		strings.HasPrefix(fields[3], "-") {
		t.Errorf("critic-verdict remediation %q must name the campaign and "+
			"the finding positionally (`webv2 verdict <campaign> <finding> "+
			"...`)", hint)
	}
	for _, want := range []string{"--verdict", "--reason"} {
		if !strings.Contains(hint, want) {
			t.Errorf("critic-verdict remediation %q misses required flag %s",
				hint, want)
		}
	}
	if strings.Contains(hint, "--actor") {
		t.Errorf("critic-verdict remediation %q names --actor, which "+
			"cmd_verdict.go rejects", hint)
	}
}
