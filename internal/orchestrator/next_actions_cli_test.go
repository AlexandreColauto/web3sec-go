package orchestrator_test

// next_actions_cli_test.go: Task 7 — every next-action line is a COPYABLE
// command.
//
// The guidance catalog used to speak the Python API's language
// (`orchestrator.scope(policy_path=...)`, `orchestrator.triage_all()`,
// "run the maximal-exploitation prompt via adapter.build_context"). An
// operator reading `webv2 brief` could not paste a single one of those lines
// into a shell: the verb was a method name, the arguments were keyword
// arguments. The law is now: every line the work-queue assembly MINTS is a
// runnable `webv2 …` command, and no line may carry a parenthesised
// pseudo-call.
//
// Three independent checks, because a regex alone would pass vacuously:
//
//  1. shape — every emitted line opens `webv2 ` and contains no parenthesis;
//  2. dispatch — the verb each line names is in the CLI registry
//     (cli.CommandNames), so a typo cannot ship as guidance;
//  3. parse — the line, with its metavariables substituted, is fed to the
//     real dispatcher and may not come back as a usage error (exit 2).
//
// Plus concrete expected command lists for four known fixture campaigns: a
// regex that accepted `webv2 nonsense` would be worthless, so the catalog is
// pinned verbatim for the phases a fresh campaign walks.

import (
	"fmt"
	"strings"
	"testing"

	"websec/internal/cli"
	"websec/internal/orchestrator"
	"websec/internal/state"
)

const t7CampaignID = "C-0000000000"

// t7Metavars is the substitution table for the metavariables the catalog is
// allowed to print. A `<...>` token that is NOT here is a failure, not a
// skip: an uncovered metavariable would make check 3 blind for that line.
var t7Metavars = map[string]string{
	"<policy.json>":   "policy.json",
	"<target>":        ".",
	"<src>":           ".",
	"<plan.json>":     "plan.json",
	"<model.json>":    "model.json",
	"<payload.json>":  "payload.json",
	"<finding>":       "F-1",
	"<other>":         "F-2",
	"<EXEC-id>":       "EXEC-1",
	"<description>":   "desc",
	"<reason>":        "why",
	"<actor>":         "me",
	"<verdict>":       "confirmed",
	"<same|distinct>": "same",
	"<note>":          "note",
	"<command>":       "ls",
	"<profile>":       "p",
	"<check>":         "evidence-floor",
	"<stage>":         "discovery",
	"<memory-id>":     "M-1",
	"<text>":          "note",
}

// t7Reporter is the failure sink: *testing.T in the real tests, a recorder in
// the mutation check.
type t7Reporter interface {
	Errorf(format string, args ...any)
}

// t7Fixture pins a fresh campaign to one phase and returns the emitted
// next-action lines.
func t7Fixture(t *testing.T, phase string) (*state.Campaign, []string) {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{
		CampaignID: t7CampaignID})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	if err := c.SetPhase(phase, "task 7 fixture"); err != nil {
		t.Fatalf("set phase %s: %v", phase, err)
	}
	v, err := orchestrator.NextActions(c)
	if err != nil {
		t.Fatalf("next actions for phase %s: %v", phase, err)
	}
	out := make([]string, 0, len(v.A))
	for _, a := range v.A {
		out = append(out, a.S)
	}
	return c, out
}

// t7Command is one emitted line split into the tokens the shell would see:
// the `webv2` head, the verb, and everything after it (a trailing `# reason`
// comment is dropped, exactly as a shell would).
func t7Command(line string) (verb string, tokens []string) {
	code := line
	if i := strings.Index(code, "  # "); i >= 0 {
		code = code[:i]
	}
	fields := strings.Fields(code)
	if len(fields) == 0 || fields[0] != "webv2" {
		return "", fields
	}
	if len(fields) < 2 {
		return "", fields[1:]
	}
	return fields[1], fields[1:]
}

// t7CheckLine is the per-line guard: shape, dispatch and metavariable
// coverage. It returns how many assertions it made, so a caller can refuse to
// pass vacuously.
func t7CheckLine(rep t7Reporter, verbs map[string]bool, phase, line string) int {
	checks := 0
	checks++
	if !strings.HasPrefix(line, "webv2 ") {
		rep.Errorf("phase %s: next action %q is not a runnable `webv2 …` "+
			"command", phase, line)
	}
	checks++
	if strings.ContainsAny(line, "()") {
		rep.Errorf("phase %s: next action %q carries a parenthesis — that is "+
			"a Python-API pseudo-call, not a command an operator can paste",
			phase, line)
	}
	verb, tokens := t7Command(line)
	if verb != "" {
		checks++
		if !verbs[verb] {
			rep.Errorf("phase %s: next action %q names %q, which the CLI "+
				"does not dispatch", phase, line, verb)
		}
	}
	for _, tok := range tokens {
		if !strings.HasPrefix(tok, "<") {
			continue
		}
		checks++
		if _, ok := t7Metavars[tok]; !ok {
			rep.Errorf("phase %s: next action %q prints the metavariable %q, "+
				"which t7Metavars does not cover — seed the table so the line "+
				"is still parse-checked", phase, line, tok)
		}
	}
	return checks
}

// t7Verbs is the CLI dispatch registry as a set.
func t7Verbs(t *testing.T) map[string]bool {
	t.Helper()
	verbs := map[string]bool{}
	for _, name := range cli.CommandNames() {
		verbs[name] = true
	}
	if len(verbs) == 0 {
		t.Fatal("CLI dispatch registry is empty — this guard would pass " +
			"vacuously")
	}
	return verbs
}

// TestNextActionsAreCopyableCommands is the law itself, over every phase the
// campaign can be in.
func TestNextActionsAreCopyableCommands(t *testing.T) {
	verbs := t7Verbs(t)
	checked := 0
	for _, phase := range state.Phases {
		_, lines := t7Fixture(t, phase)
		if len(lines) == 0 {
			t.Errorf("phase %s: no next actions at all — the guidance went "+
				"silent", phase)
			continue
		}
		for _, line := range lines {
			checked += t7CheckLine(t, verbs, phase, line)
		}
	}
	if checked == 0 {
		t.Fatal("no next-action line was checked — the catalog is empty")
	}
}

// TestNextActionsGuardCatchesMutations proves each half of the guard can
// fail: a pseudo-API line, a prose line, an unseeded metavariable and an
// undispatched verb must all be reported by the line guard, and a misspelled
// FLAG (real verb, wrong shape) must come back from the dispatcher as a usage
// error — otherwise TestNextActionsCommandsParse proves nothing.
func TestNextActionsGuardCatchesMutations(t *testing.T) {
	verbs := t7Verbs(t)
	for _, tc := range []struct {
		name    string
		line    string
		wantMin int
	}{
		{"python-API pseudo-call",
			"orchestrator.scope(policy_path=...)", 2},
		{"prose line", "campaign complete or halted", 1},
		{"undispatched verb", "webv2 plans " + t7CampaignID, 1},
		{"unseeded metavariable",
			"webv2 plan " + t7CampaignID + " <unseeded-metavar>", 1},
	} {
		rec := &t7Recorder{}
		t7CheckLine(rec, verbs, "MUTATION", tc.line)
		if len(rec.msgs) < tc.wantMin {
			t.Errorf("%s: guard reported %d problem(s), want at least %d: %v",
				tc.name, len(rec.msgs), tc.wantMin, rec.msgs)
		}
	}
	var out, errOut strings.Builder
	if exit := cli.Run([]string{"--root", t.TempDir(), "scope", t7CampaignID,
		"--polcy", "policy.json"}, &out, &errOut); exit != 2 {
		t.Fatalf("dispatcher accepted a misspelled flag (exit %d) — the "+
			"parse check would be blind: %s", exit, errOut.String())
	}
}

type t7Recorder struct{ msgs []string }

func (r *t7Recorder) Errorf(format string, args ...any) {
	r.msgs = append(r.msgs, strings.TrimSpace(fmt.Sprintf(format, args...)))
}

// TestNextActionsConcreteFixtures pins the exact commands for four known
// fixture campaigns — the phases a fresh campaign walks before any finding
// exists. A regex that accepted `webv2 nonsense` would pass the law above, so
// the catalog is asserted verbatim here.
func TestNextActionsConcreteFixtures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		phase string
		want  []string
	}{
		{
			name:  "fresh campaign at SCOPE",
			phase: "SCOPE",
			want: []string{
				"webv2 scope " + t7CampaignID + " --policy <policy.json>",
				"webv2 snap " + t7CampaignID + " <target>",
			},
		},
		{
			name:  "snapshot pinned",
			phase: "SNAPSHOT",
			want: []string{
				"webv2 snap " + t7CampaignID + " <target>",
			},
		},
		{
			name:  "plan not yet written",
			phase: "CAMPAIGN_PLANNING",
			want: []string{
				"webv2 plan " + t7CampaignID + " <plan.json>",
				"webv2 prove " + t7CampaignID +
					" --stage campaign-planning  # 1 missing",
			},
		},
		{
			name:  "reproduction, nothing to reproduce yet",
			phase: "REPRODUCTION",
			want: []string{
				"webv2 repro-queue " + t7CampaignID,
				"webv2 mint " + t7CampaignID + " <finding> --exec <EXEC-id>" +
					" --description <description>",
				"webv2 run " + t7CampaignID +
					"  # reproduction proof holds; the stage auto-completes",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, got := t7Fixture(t, tc.phase)
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Errorf("phase %s next actions:\n got: %q\nwant: %q",
					tc.phase, got, tc.want)
			}
		})
	}
}

// TestNextActionsCommandsParse feeds every emitted line to the real
// dispatcher with its metavariables substituted and a root that holds no such
// campaign: the parser must accept the shape (exit 2 is a usage error; exit 1
// is the campaign-not-found the fixture intends, and no line can do any work
// because the campaign does not exist).
func TestNextActionsCommandsParse(t *testing.T) {
	root := t.TempDir()
	checked := 0
	for _, phase := range state.Phases {
		_, lines := t7Fixture(t, phase)
		for _, line := range lines {
			code := line
			if i := strings.Index(code, "  # "); i >= 0 {
				code = code[:i]
			}
			argv := []string{"--root", root}
			for _, tok := range strings.Fields(code) {
				if tok == "webv2" {
					continue
				}
				if strings.HasPrefix(tok, "<") {
					sub, ok := t7Metavars[tok]
					if !ok {
						t.Fatalf("phase %s: uncovered metavariable %q in %q",
							phase, tok, line)
					}
					tok = sub
				}
				argv = append(argv, tok)
			}
			var out, errOut strings.Builder
			exit := cli.Run(argv, &out, &errOut)
			checked++
			if exit == 2 {
				t.Errorf("phase %s: `%s` is a usage error (exit 2): %s",
					phase, line, strings.TrimSpace(errOut.String()))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no command was parse-checked")
	}
}
