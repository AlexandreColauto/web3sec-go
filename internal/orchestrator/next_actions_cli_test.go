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
	"websec/internal/completion"
	"websec/internal/findings"
	"websec/internal/orchestrator"
	"websec/internal/pipeline"
	"websec/internal/state"
	"websec/internal/validation"
)

const t7CampaignID = "C-0000000000"

// t7Metavars is the substitution table for the metavariables the catalog is
// allowed to print. A `<...>` token that is NOT here is a failure, not a
// skip: an uncovered metavariable would make check 3 blind for that line.
var t7Metavars = map[string]string{
	"<policy.json>":      "policy.json",
	"<target>":           ".",
	"<src>":              ".",
	"<plan.json>":        "plan.json",
	"<model.json>":       "model.json",
	"<payload.json>":     "payload.json",
	"<finding>":          "F-1",
	"<other>":            "F-2",
	"<EXEC-id>":          "EXEC-1",
	"<description>":      "desc",
	"<reason>":           "why",
	"<actor>":            "me",
	"<verdict>":          "confirmed",
	"<same-or-distinct>": "same",
	"<verifier>":         "independent-auditor",
	"<note>":             "note",
	"<command>":          "ls",
	"<profile>":          "p",
	"<check>":            "evidence-floor",
	"<stage>":            "discovery",
	"<memory-id>":        "M-1",
	"<text>":             "note",
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

// TestNextActionsConcreteFixtures pins the exact commands for known fixture
// campaigns — the phases a fresh campaign walks before any finding exists. A
// regex that accepted `webv2 nonsense` would pass the law above, so the
// catalog is asserted verbatim here.
//
// ORACLE BOUNDARY (applies to TestNextActionsCommandsParse too): the
// dispatcher feed proves PARSE SHAPE only — that the line's verb is
// dispatched and its flags are spelled the way that verb's own parser
// expects. It proves nothing about WORK SATISFACTION: `webv2 rank` parses
// perfectly, exits 0 and closes no proof, and `webv2 mint` parses perfectly
// and cannot set verification.independent_reproduction. Verb CHOICE is
// therefore pinned separately — verbatim here, and as a property by
// TestNextActionsLeadWithTheProofClosingCommand below.
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
				"webv2 mint " + t7CampaignID + " <finding> --exec <EXEC-id>" +
					" --description <description>",
				"webv2 repro-queue " + t7CampaignID,
				"webv2 run " + t7CampaignID +
					"  # reproduction proof holds; the stage auto-completes",
			},
		},
		{
			name:  "discovery, no plan yet",
			phase: "DISCOVERY",
			want: []string{
				"webv2 run " + t7CampaignID,
				"webv2 plan " + t7CampaignID,
				"webv2 ingest " + t7CampaignID +
					" --json-file <payload.json>",
				"webv2 prioritize " + t7CampaignID,
				"webv2 prove " + t7CampaignID +
					" --stage discovery  # 1 missing",
			},
		},
		{
			name:  "independent verification, nothing confirmed yet",
			phase: "INDEPENDENT_VERIFICATION",
			want: []string{
				"webv2 verify " + t7CampaignID + " --finding <finding>" +
					" --exec <EXEC-id> --verifier <verifier>" +
					" --description <description>",
				"webv2 mint " + t7CampaignID + " <finding> --exec <EXEC-id>" +
					" --description <description>",
				"webv2 run " + t7CampaignID,
				"webv2 run " + t7CampaignID + "  # independent-verification" +
					" proof holds; the stage auto-completes",
			},
		},
		{
			name:  "risk calibration, nothing confirmed yet",
			phase: "RISK_CALIBRATION",
			want: []string{
				"webv2 run " + t7CampaignID,
				"webv2 rank " + t7CampaignID,
				"webv2 run " + t7CampaignID + "  # risk-calibration" +
					" proof holds; the stage auto-completes",
			},
		},
		{
			name:  "mainnet fork PoC, nothing confirmed yet",
			phase: "MAINNET_FORK_POC",
			want: []string{
				"webv2 exec " + t7CampaignID + " --command <command>" +
					" --profile <profile>",
				"webv2 mint " + t7CampaignID + " <finding> --exec <EXEC-id>" +
					" --description <description> --type fork-test",
				"webv2 run " + t7CampaignID + "  # mainnet-fork-poc" +
					" proof holds; the stage auto-completes",
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

// t7ProofClosing is the phase -> the command that closes its completion
// proof. The criterion is an EFFECT, not a shape: the lead line must name the
// command whose RECORDED effect the stage's proof reads.
//
//	run    — the deterministic/model stage writes the proof's input state
//	         (risk-calibration's bands, discovery's queue dispositions, …)
//	verify — `verify --exec` is the only CLI path to
//	         MintIndependentEvidence, which sets
//	         verification.independent_reproduction{status,verifier}
//	mint   — records the reproduction attempt + its evidence
//	exec   — the fork-runner run a fork-test mint must trace to
//	plan/dedup/gate/report/memory — the stage's own artifact
//
// Read-only verbs fail it: `rank` recomputes the score and writes nothing
// (cmd_rank.go), so a RISK_CALIBRATION list led by `rank` can never close its
// proof — the exact dead end the round-1 review found.
var t7ProofClosing = []struct {
	phase string
	stage string
	verb  string
	extra []string
}{
	{"PROTOCOL_INTELLIGENCE", "protocol-model", "run", nil},
	{"CAMPAIGN_PLANNING", "campaign-planning", "plan", nil},
	{"DISCOVERY", "discovery", "run", nil},
	{"CANDIDATE_INTEL", "dedup", "dedup", nil},
	{"HOSTILE_REVIEW", "hostile-review", "run", nil},
	{"REPRODUCTION", "reproduction", "mint", nil},
	{"MAXIMAL_EXPLOITATION", "maximal-exploitation", "run", nil},
	{"INDEPENDENT_VERIFICATION", "independent-verification", "verify",
		[]string{"--exec"}},
	{"RISK_CALIBRATION", "risk-calibration", "run", nil},
	{"MAINNET_FORK_POC", "mainnet-fork-poc", "exec", nil},
	{"BOUNTY_GATE", "bounty-gate", "gate", nil},
	{"REPORTING", "report", "report", nil},
	{"LEARNING", "learning", "memory", nil},
}

// TestNextActionsLeadWithTheProofClosingCommand is the proof-closing property
// the parse oracle structurally cannot see: the FIRST line of a phase's
// catalog names the command that can close that phase's completion proof.
// TestNextActionsProofClosingPinIsNotVacuous supplies the other half — that
// the proof really is open for these phases, so the pin is not describing a
// gap that does not exist.
func TestNextActionsLeadWithTheProofClosingCommand(t *testing.T) {
	for _, tc := range t7ProofClosing {
		t.Run(tc.phase, func(t *testing.T) {
			if !completion.HasProof(tc.stage) {
				t.Fatalf("phase %s pins stage %q, which declares no "+
					"completion proof — the pin would be meaningless",
					tc.phase, tc.stage)
			}
			// The pin names the phase's own stage: a stage id typo here
			// would silently pin the wrong proof.
			found := false
			for _, s := range pipeline.Stages {
				if s.Phase == tc.phase {
					found = true
					if s.ID != tc.stage {
						t.Fatalf("phase %s runs stage %q, not %q",
							tc.phase, s.ID, tc.stage)
					}
				}
			}
			if !found {
				t.Fatalf("phase %s is in no pipeline stage", tc.phase)
			}
			_, lines := t7Fixture(t, tc.phase)
			if len(lines) == 0 {
				t.Fatalf("phase %s emitted no next actions", tc.phase)
			}
			verb, _ := t7Command(lines[0])
			if verb != tc.verb {
				t.Errorf("phase %s leads with %q, but its %s proof is "+
					"closed by `webv2 %s` — the lead line cannot advance "+
					"the campaign", tc.phase, lines[0], tc.stage, tc.verb)
			}
			for _, tok := range tc.extra {
				if !strings.Contains(lines[0], tok) {
					t.Errorf("phase %s leads with %q, which lacks %q — the "+
						"bare verb does not close the proof",
						tc.phase, lines[0], tok)
				}
			}
		})
	}
}

// TestNextActionsProofClosingPinIsNotVacuous seeds the input state each
// review-phase proof reads and asserts the proof is genuinely OPEN for the
// fixture — a campaign with one CONFIRMED finding that carries neither
// risk.validated.band nor verification.independent_reproduction. Only then
// does the catalog's lead verb matter: a lead line that cannot write those
// fields (rank, or mint-for-E6) would be a dead end against an open proof.
func TestNextActionsProofClosingPinIsNotVacuous(t *testing.T) {
	for _, tc := range []struct{ phase, stage, wantLead string }{
		{"RISK_CALIBRATION", "risk-calibration", "webv2 run "},
		{"INDEPENDENT_VERIFICATION", "independent-verification",
			"webv2 verify "},
	} {
		t.Run(tc.phase, func(t *testing.T) {
			c, _ := t7Fixture(t, tc.phase)
			t7ConfirmedFinding(t, c)
			pr, err := completion.ProofStatus(c, tc.stage)
			if err != nil {
				t.Fatalf("proof status: %v", err)
			}
			if t7Bool(pr, "done") {
				t.Fatalf("the %s proof is already done with a CONFIRMED "+
					"finding lacking its field — this pin is vacuous",
					tc.stage)
			}
			if t7Len(pr, "missing") == 0 {
				t.Fatalf("the %s proof reports done=false with no missing "+
					"item — the fixture proves nothing", tc.stage)
			}
			v, err := orchestrator.NextActions(c)
			if err != nil {
				t.Fatal(err)
			}
			lines := make([]string, 0, len(v.A))
			for _, a := range v.A {
				lines = append(lines, a.S)
			}
			if len(lines) == 0 || !strings.HasPrefix(lines[0], tc.wantLead) {
				t.Errorf("phase %s against an OPEN %s proof leads with %q, "+
					"want a %q command", tc.phase, tc.stage, lines, tc.wantLead)
			}
			last := lines[len(lines)-1]
			if !strings.Contains(last, "--stage "+tc.stage) {
				t.Errorf("phase %s does not name the open proof's printer: "+
					"%q", tc.phase, last)
			}
		})
	}
}

// t7ConfirmedFinding writes one CONFIRMED finding with no
// risk.validated.band and no verification.independent_reproduction: the
// state in which the risk-calibration and independent-verification proofs
// are open.
func t7ConfirmedFinding(t *testing.T, c *state.Campaign) string {
	t.Helper()
	payload := validation.VObj(
		validation.KV{K: "title", V: validation.VStr("t7 fixture")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("access-control")},
			validation.KV{K: "description", V: validation.VStr(
				"no risk band or independent check recorded yet")})},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/V.sol")},
			validation.KV{K: "contract", V: validation.VStr("V")},
			validation.KV{K: "function", V: validation.VStr("claim")}))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()})})
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatalf("ingest fixture finding: %v", err)
	}
	fid := t7Str(f, "finding_id")
	if fid == "" {
		t.Fatal("ingest returned no finding_id")
	}
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "status", validation.VStr("CONFIRMED"))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatalf("save CONFIRMED fixture finding: %v", err)
	}
	return fid
}

// t7Str reads one string field (the external test package has no access to
// the internal objStr helper).
func t7Str(v validation.Value, key string) string {
	for _, kv := range v.O {
		if kv.K == key && kv.V.Kind == validation.Str {
			return kv.V.S
		}
	}
	return ""
}

// t7Bool reads one boolean field.
func t7Bool(v validation.Value, key string) bool {
	for _, kv := range v.O {
		if kv.K == key && kv.V.Kind == validation.Bool {
			return kv.V.B
		}
	}
	return false
}

// t7Len is len() over one array field.
func t7Len(v validation.Value, key string) int {
	for _, kv := range v.O {
		if kv.K == key && kv.V.Kind == validation.Arr {
			return len(kv.V.A)
		}
	}
	return 0
}
