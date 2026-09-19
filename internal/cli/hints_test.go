package cli

// B9 — the capped, suppressible write-time hygiene note.
//
// What these tests pin:
//
//   - RANKING + CAP: one ingest whose affected[] shares anchors with four
//     undispositioned rows and three open priorities prints exactly THREE
//     stderr lines, most specific first (an exact path#function row match
//     beats a path-only match; rows beat priorities; a priority that claims an
//     already-named row is not printed twice);
//   - THE SILENT PATH IS A NO-OP: with no match — and with the model, the
//     surface or the plan absent, unreadable or unparsable — the run's bytes
//     are IDENTICAL to the same run under --no-hints (the pre-B9 stream), and
//     a successful ingest is never turned into a failure;
//   - SUPPRESSION: --no-hints and WEBV2_NO_HINTS=1 (the literal 1 ONLY)
//     silence the note; every other value leaves it on;
//   - MINT: the same note rides a successful mint, after its success line;
//   - STREAMS: every hint byte is stderr; stdout is untouched.
//
// The fixture is the shared seam's own vocabulary: a model mapping contract
// NAMES to snapshot-relative paths, a surface whose rows cite contract+function
// coordinates, and a plan whose priorities carry components[] (names) — the
// three spellings internal/anchorlink joins.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// b9Model is the model index: three contracts, each under its own path, plus a
// state machine (so a lifecycle-id component is a legal spelling).
const b9Model = `{"contracts":[
 {"name":"Rollup","path":"l1/rollup/Rollup.sol"},
 {"name":"Vault","path":"l2/vault/Vault.sol"},
 {"name":"Sink","path":"l1/sink/Sink.sol"}],
 "state_machines":[{"name":"BatchLifecycle"}]}`

// The row whys, and the truncated forms the note renders (60 runes + "…").
const (
	b9WhyFn      = "commitBatch#204 guards prev:state:root with a SENTINEL check"
	b9WhyVault   = "deposit custody primitive has no base anchor in the Vault row"
	b9WhyVault60 = "deposit custody primitive has no base anchor in the Vault ro…"
	b9WhySib     = "the trust assumption on otherFn is undispositioned"
	b9WhyLate    = "a late-ranked Rollup row"
)

// b9Surface is four undispositioned rows: r-fn is an exact function-level
// match for a Rollup#commitBatch payload, r-sib and r-late are path-only
// Rollup matches, r-vault is a function-level Vault match. r-late is claimed
// by the open priority Q-003 (so it is dispositioned through it), the rest by
// nothing.
const b9Surface = `{"rows":[
 {"row_id":"r-fn","probe":"assertion-strength","tier":0,"rank":1,
  "assertion_gap":4,"contract":"Rollup","consumer":"commitBatch",
  "consumer_line":204,"asserter":"finalizeBatch","asserter_line":496,
  "why":"` + b9WhyFn + `"},
 {"row_id":"r-sib","probe":"trust-assumption","tier":1,"rank":2,
  "contract":"Rollup","consumer":"otherFn","consumer_line":10,
  "why":"` + b9WhySib + `"},
 {"row_id":"r-vault","probe":"custody-primitive","tier":0,"rank":3,
  "contract":"Vault","consumer":"deposit","consumer_line":42,
  "why":"` + b9WhyVault + `"},
 {"row_id":"r-late","probe":"assertion-strength","tier":2,"rank":9,
  "contract":"Rollup","consumer":"zzz","consumer_line":99,
  "why":"` + b9WhyLate + `"}]}`

// b9Plan is five priorities: three OPEN (Q-001 Rollup, Q-002 Vault, Q-003
// Rollup — the one claiming r-late, Q-004 Sink) and one answered (Q-005), so
// both the open filter and the subsumption rule are observable.
const b9Plan = `{"priorities":[
 {"id":"Q-001","question":"is the Rollup batch commitment enforced?",
  "components":["Rollup"],"status":"open"},
 {"id":"Q-002","question":"who custodies the Vault deposits?",
  "components":["Vault"],"status":"open"},
 {"id":"Q-003","question":"the row claim","components":["Rollup"],
  "status":"open","probe":{"row_id":"r-late"}},
 {"id":"Q-004","question":"is the Sink bounded?","components":["Sink"],
  "status":"open"},
 {"id":"Q-005","question":"already answered","components":["Sink"],
  "status":"answered"}]}`

// b9SubSurface / b9SubPlan isolate the subsumption rule: ONE row, claimed by
// the open Q-003, next to the unrelated open Q-001. Without subsumption the
// note would spend three lines on two obligations.
const (
	b9SubSurface = `{"rows":[
 {"row_id":"r-late","probe":"assertion-strength","tier":2,"rank":9,
  "contract":"Rollup","consumer":"zzz","consumer_line":99,
  "why":"` + b9WhyLate + `"}]}`
	b9SubPlan = `{"priorities":[
 {"id":"Q-001","question":"is the Rollup batch commitment enforced?",
  "components":["Rollup"],"status":"open"},
 {"id":"Q-003","question":"the row claim","components":["Rollup"],
  "status":"open","probe":{"row_id":"r-late"}}]}`
	// b9AnsweredPlan claims the one row with a TERMINAL status: the row is
	// dispositioned, so neither it nor its (closed) priority is a hint.
	b9AnsweredPlan = `{"priorities":[
 {"id":"Q-001","question":"is the Rollup batch commitment enforced?",
  "components":["Rollup"],"status":"open"},
 {"id":"Q-003","question":"the row claim","components":["Rollup"],
  "status":"answered","probe":{"row_id":"r-late"}}]}`
)

// b9Artifacts writes the three artifacts internal/anchorlink indexes. An empty
// body leaves that artifact ABSENT — the silent-skip geometries.
func b9Artifacts(t *testing.T, c *state.Campaign, model, surface, plan string) {
	t.Helper()
	for _, w := range []struct{ name, body string }{
		{"protocol_model.json", model},
		{"probe_surface.json", surface},
		{"campaign_plan.json", plan},
	} {
		if w.body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(c.ArtifactsDir, w.name),
			[]byte(w.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// b9Payload is a schema-valid hypothesis payload carrying the given affected[]
// entries; it lands at E1 (the T2 fixture's reasoning item).
func b9Payload(affected string) string {
	return `{"title":"Unguarded rescue moves protocol-held tokens",` +
		`"root_cause":{"class":"access-control","description":` +
		`"rescue has no role check at all"},"affected":[` + affected + `],` +
		`"attacker":{"profile":"arbitrary EOA","capabilities":[]},` +
		`"evidence":[{"evidence_id":"EV-1","level":"E1","type":"reasoning",` +
		`"description":"rescue is reachable from the public entry point"}]}`
}

// b9Ingest runs the real verb on one payload written under name.
func b9Ingest(t *testing.T, root, cid, name, payload string,
	extra ...string) (int, string, string) {
	t.Helper()
	p := t2Write(t, root, name, payload)
	args := append([]string{"--root", root, "ingest", cid,
		"--json-file", p}, extra...)
	return run(t, args...)
}

// b9PinID pins the finding-id stream so two runs are byte-comparable.
func b9PinID(t *testing.T) {
	t.Helper()
	findings.SetFindingIDSource(func() string { return "F-abcdefabcdef" })
	t.Cleanup(func() { findings.SetFindingIDSource(nil) })
}

// TestB9HintsIngestRanksAndCaps: four rows and three open priorities share the
// payload's anchors; the note names the three most specific and stops there.
func TestB9HintsIngestRanksAndCaps(t *testing.T) {
	c, root, cid := t2Campaign(t)
	b9Artifacts(t, c, b9Model, b9Surface, b9Plan)
	b9PinID(t)

	code, out, errS := b9Ingest(t, root, cid, "p.json", b9Payload(
		`{"path":"l1/rollup/Rollup.sol","function":"commitBatch"},`+
			`{"path":"l2/vault/Vault.sol","function":"deposit"}`))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "ingested F-abcdefabcdef ") {
		t.Fatalf("stdout is not the success line: %q", out)
	}
	want := strings.Join([]string{
		"hint: row r-fn: " + b9WhyFn + " — webv2 probes " + cid + " run --emit",
		"hint: row r-vault: " + b9WhyVault60 + " — webv2 probes " + cid +
			" run --emit",
		"hint: row r-sib: " + b9WhySib + " — webv2 probes " + cid +
			" run --emit",
	}, "\n") + "\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// TestB9HintsPriorityLineAndOpenFilter: an anchor no ROW cites still reaches an
// OPEN priority (the payload's own store), and the note ends with the smallest
// acting command for it. Q-005 is answered, so it is not a hint.
func TestB9HintsPriorityLineAndOpenFilter(t *testing.T) {
	c, root, cid := t2Campaign(t)
	b9Artifacts(t, c, b9Model, b9Surface, b9Plan)
	b9PinID(t)

	code, _, errS := b9Ingest(t, root, cid, "p.json",
		b9Payload(`{"path":"l1/sink/Sink.sol"}`))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "hint: priority Q-004: is the Sink bounded? — webv2 answered " +
		cid + " Q-004 answered --reason '<why>'\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// TestB9HintsClaimedRowNamesItsPriority: an undispositioned row claimed by an
// open priority ends with the `answered` command for THAT priority (the only
// route that can disposition a probe row — it needs the --anchor the refusal
// asks for), and the priority is not printed a second time.
func TestB9HintsClaimedRowNamesItsPriority(t *testing.T) {
	c, root, cid := t2Campaign(t)
	b9Artifacts(t, c, b9Model, b9SubSurface, b9SubPlan)
	b9PinID(t)

	code, _, errS := b9Ingest(t, root, cid, "p.json",
		b9Payload(`{"path":"l1/rollup/Rollup.sol"}`))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "hint: row r-late: " + b9WhyLate + " — webv2 answered " + cid +
		" Q-003 answered --reason '<why>' --anchor <field>\n" +
		"hint: priority Q-001: is the Rollup batch commitment enforced? — " +
		"webv2 answered " + cid + " Q-001 answered --reason '<why>'\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// TestB9HintsDispositionedRowIsSilent: a row its plan priority ANSWERED is not
// an undispositioned row, and a closed priority is not an open one — the only
// remaining lead is the unrelated open Q-001.
func TestB9HintsDispositionedRowIsSilent(t *testing.T) {
	c, root, cid := t2Campaign(t)
	b9Artifacts(t, c, b9Model, b9SubSurface, b9AnsweredPlan)
	b9PinID(t)

	code, _, errS := b9Ingest(t, root, cid, "p.json",
		b9Payload(`{"path":"l1/rollup/Rollup.sol"}`))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "hint: priority Q-001: is the Rollup batch commitment enforced? — " +
		"webv2 answered " + cid + " Q-001 answered --reason '<why>'\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// b9SilentGeometry is one "nothing to say" campaign shape.
type b9SilentGeometry struct {
	name    string
	model   string
	surface string
	plan    string
}

// TestB9HintsSilentPathIsByteIdentical: the absent case must leave the bytes
// exactly as they were. --no-hints renders the pre-B9 stream (there was no
// note), so the two runs are compared byte for byte, stdout and stderr — for
// an empty campaign, for a payload whose anchors match nothing, for a corrupt
// model, surface and plan, and for a model without a plan. Every geometry
// still WRITES its finding (the note is additive, never a gate) and still
// exits 0 with a silent stderr.
func TestB9HintsSilentPathIsByteIdentical(t *testing.T) {
	geometries := []b9SilentGeometry{
		{name: "no-artifacts"},
		{name: "no-match", model: b9Model, surface: b9Surface, plan: b9Plan},
		{name: "corrupt-model", model: "{not json", surface: b9Surface,
			plan: b9Plan},
		// B9 review finding 1: probe_surface.json is the store every row
		// match goes through, so a surface that is present and unparsable
		// must take the same silent path as an absent one — and the plan
		// beside it (the third store hintJoin reads) too.
		{name: "corrupt-surface", model: b9Model, surface: "{not json",
			plan: b9Plan},
		{name: "corrupt-plan", model: b9Model, surface: b9Surface,
			plan: "{not json"},
		{name: "no-plan", model: b9Model, surface: b9Surface},
	}
	affected := `{"path":"l1/rollup/Rollup.sol","function":"commitBatch"}`
	for _, g := range geometries {
		t.Run(g.name, func(t *testing.T) {
			b9PinID(t)
			// The no-match geometry must not match; the others share the same
			// payload so the ONLY variable is the artifact geometry.
			payload := affected
			if g.name == "no-match" {
				payload = `{"path":"l9/none/Nope.sol"}`
			}
			a, rootA, cidA := t2Campaign(t)
			b9Artifacts(t, a, g.model, g.surface, g.plan)
			codeA, outA, errA := b9Ingest(t, rootA, cidA, "p.json",
				b9Payload(payload))
			if codeA != 0 {
				t.Fatalf("exit %d: %q", codeA, errA)
			}
			if errA != "" {
				t.Fatalf("the silent path wrote to stderr: %q", errA)
			}
			// A corrupt store is not a corrupt ingest: the finding still
			// lands, and the success line still names it.
			if !strings.HasPrefix(outA, "ingested F-abcdefabcdef ") {
				t.Fatalf("the finding was not written: %q", outA)
			}
			paths, err := validation.ListPrefixedOptional(a.FindingsDir,
				"F-", ".json")
			if err != nil || len(paths) != 1 {
				t.Fatalf("the finding is not on disk: %v (%v)", paths, err)
			}
			b, rootB, cidB := t2Campaign(t)
			b9Artifacts(t, b, g.model, g.surface, g.plan)
			codeB, outB, errB := b9Ingest(t, rootB, cidB, "p.json",
				b9Payload(payload), "--no-hints")
			if codeA != codeB || outA != outB || errA != errB {
				t.Fatalf("the absent case is not byte-identical to the "+
					"suppressed run:\ndefault: %d %q %q\nno-hints: %d %q %q",
					codeA, outA, errA, codeB, outB, errB)
			}
		})
	}
}

// TestB9HintsSuppressionMatrix: --no-hints and WEBV2_NO_HINTS=1 turn the note
// off; every other value (0, true, empty) leaves it on, because the switch is
// documented as the literal 1.
func TestB9HintsSuppressionMatrix(t *testing.T) {
	cases := []struct {
		name   string
		env    string
		flag   bool
		silent bool
	}{
		{name: "default", silent: false},
		{name: "flag", flag: true, silent: true},
		{name: "env-1", env: "1", silent: true},
		{name: "env-0", env: "0", silent: false},
		{name: "env-true", env: "true", silent: false},
		{name: "env-empty", env: "", silent: false},
		{name: "env-flag", env: "1", flag: true, silent: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(hintNoHintsEnv, tc.env)
			c, root, cid := t2Campaign(t)
			b9Artifacts(t, c, b9Model, b9Surface, b9Plan)
			b9PinID(t)
			extra := []string{}
			if tc.flag {
				extra = append(extra, "--no-hints")
			}
			code, _, errS := b9Ingest(t, root, cid, "p.json", b9Payload(
				`{"path":"l1/rollup/Rollup.sol","function":"commitBatch"},`+
					`{"path":"l2/vault/Vault.sol","function":"deposit"}`),
				extra...)
			if code != 0 {
				t.Fatalf("exit %d: %q", code, errS)
			}
			if tc.silent && errS != "" {
				t.Fatalf("not suppressed: %q", errS)
			}
			if !tc.silent && !strings.HasPrefix(errS, "hint: row r-fn: ") {
				t.Fatalf("suppressed but should not be: %q", errS)
			}
		})
	}
}

// TestB9HintsMintEmitsAfterTheSuccessLine: the same note rides a successful
// mint, on stderr, and --no-hints silences it there too.
func TestB9HintsMintEmitsAfterTheSuccessLine(t *testing.T) {
	for _, silent := range []bool{false, true} {
		name := "hints"
		if silent {
			name = "no-hints"
		}
		t.Run(name, func(t *testing.T) {
			c, root, cid := t2Campaign(t)
			b9Artifacts(t, c, b9Model, b9Surface, b9Plan)
			b9PinID(t)
			code, out, errS := b9Ingest(t, root, cid, "p.json", b9Payload(
				`{"path":"l1/rollup/Rollup.sol","function":"commitBatch"}`),
				"--no-hints")
			if code != 0 {
				t.Fatalf("ingest exit %d: %q", code, errS)
			}
			fid := strings.Fields(out)[1]
			exec := t2RegisterExec(t, c, fid)
			extra := []string{}
			if silent {
				extra = append(extra, "--no-hints")
			}
			args := append([]string{"--root", root, "mint", cid, fid,
				"--exec", exec, "--description", "the PoC drains it"},
				extra...)
			code, out, errS = run(t, args...)
			if code != 0 {
				t.Fatalf("mint exit %d: %q", code, errS)
			}
			if !strings.Contains(out, ": minted default evidence from ") {
				t.Fatalf("mint stdout is not the success line: %q", out)
			}
			// The SAME three lines the ingest leg renders: one renderer,
			// reached from both write paths.
			want := strings.Join([]string{
				"hint: row r-fn: " + b9WhyFn + " — webv2 probes " + cid +
					" run --emit",
				"hint: row r-sib: " + b9WhySib + " — webv2 probes " + cid +
					" run --emit",
				"hint: row r-late: " + b9WhyLate + " — webv2 answered " +
					cid + " Q-003 answered --reason '<why>' --anchor <field>",
			}, "\n") + "\n"
			if silent {
				want = ""
			}
			if errS != want {
				t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
			}
		})
	}
}

// TestB9HintsHelpDocumentsTheSwitch: the flag and the environment switch are
// discoverable from both verbs' help (the WIRING RULE: a capability the
// operator cannot find is dead code).
func TestB9HintsHelpDocumentsTheSwitch(t *testing.T) {
	for _, verb := range []string{"ingest", "mint"} {
		code, out, errS := run(t, verb, "--help")
		if code != 0 || errS != "" {
			t.Fatalf("%s --help: exit %d err %q", verb, code, errS)
		}
		for _, want := range []string{"--no-hints", "WEBV2_NO_HINTS=1"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s --help does not document %s", verb, want)
			}
		}
	}
}

// b9SastModel / b9SastSurface / b9SastPlan anchor the SAST fixture's own
// coordinates (src/Bank.sol, withdraw) so the tool-output lane's note is
// observable too.
const (
	b9SastModel   = `{"contracts":[{"name":"Bank","path":"src/Bank.sol"}]}`
	b9SastSurface = `{"rows":[
 {"row_id":"r-bank","probe":"assertion-strength","tier":0,"rank":1,
  "assertion_gap":4,"contract":"Bank","consumer":"withdraw",
  "consumer_line":6,"why":"withdraw has no reentrancy guard"}]}`
	b9SastPlan = `{"priorities":[
 {"id":"Q-009","question":"is the Bank withdraw guarded?",
  "components":["Bank"],"status":"open"}]}`
)

// TestB9HintsSASTLane: `ingest --from slither --json-file` is an ingest
// --json-file success, so the note rides it too — one capped block over every
// hypothesis the lane created.
func TestB9HintsSASTLane(t *testing.T) {
	c, root, cid := t2Campaign(t)
	b9Artifacts(t, c, b9SastModel, b9SastSurface, b9SastPlan)
	p := t2Write(t, root, "slither.json", t4SlitherJSON)
	code, out, errS := run(t, "--root", root, "ingest", cid, "--from",
		"slither", "--json-file", p)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "slither ingest: 1 hypotheses created\n") {
		t.Fatalf("stdout is not the lane summary: %q", out)
	}
	want := "hint: row r-bank: withdraw has no reentrancy guard — webv2 " +
		"probes " + cid + " run --emit\n" +
		"hint: priority Q-009: is the Bank withdraw guarded? — webv2 " +
		"answered " + cid + " Q-009 answered --reason '<why>'\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// TestB9HintsOnlyOnSuccess: a refused payload prints no note at all (the note
// is a write-time hygiene remark, not a second error channel), and a --json
// success keeps its JSON document on stdout while the note rides stderr.
func TestB9HintsOnlyOnSuccess(t *testing.T) {
	t.Run("refusal", func(t *testing.T) {
		c, root, cid := t2Campaign(t)
		b9Artifacts(t, c, b9Model, b9Surface, b9Plan)
		code, _, errS := b9Ingest(t, root, cid, "bad.json",
			`{"title":"x","affected":[{"path":"l1/rollup/Rollup.sol"}]}`)
		if code != 2 {
			t.Fatalf("exit %d, want 2: %q", code, errS)
		}
		if !strings.Contains(errS, "ingest failed: ") {
			t.Fatalf("stderr is not the refusal: %q", errS)
		}
		if strings.Contains(errS, "hint: row ") ||
			strings.Contains(errS, "hint: priority ") {
			t.Fatalf("a refused ingest printed the note: %q", errS)
		}
	})
	t.Run("json", func(t *testing.T) {
		c, root, cid := t2Campaign(t)
		b9Artifacts(t, c, b9Model, b9Surface, b9Plan)
		b9PinID(t)
		code, out, errS := b9Ingest(t, root, cid, "p.json", b9Payload(
			`{"path":"l1/rollup/Rollup.sol","function":"commitBatch"}`),
			"--json")
		if code != 0 {
			t.Fatalf("exit %d: %q", code, errS)
		}
		if !strings.HasPrefix(out, "{") ||
			!strings.Contains(out, `"finding"`) {
			t.Fatalf("stdout is not the JSON document: %q", out)
		}
		if !strings.HasPrefix(errS, "hint: row r-fn: ") {
			t.Fatalf("the note did not ride --json: %q", errS)
		}
	})
}

// TestB9HintTruncIsRuneSafeAndCollapsesWhitespace: the why is one line and the
// cut is on RUNES, so a multi-byte character is never split.
func TestB9HintTruncIsRuneSafeAndCollapsesWhitespace(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		width int
		want  string
	}{
		{"short", "abc", 60, "abc"},
		{"exact", strings.Repeat("x", 60), 60, strings.Repeat("x", 60)},
		{"cut", strings.Repeat("x", 61), 60, strings.Repeat("x", 60) + "…"},
		{"multibyte", strings.Repeat("é", 61), 60,
			strings.Repeat("é", 60) + "…"},
		{"whitespace", "a\n\tb  c", 60, "a b c"},
		{"empty", "", 60, ""},
	}
	for _, tc := range cases {
		if got := hintTrunc(tc.in, tc.width); got != tc.want {
			t.Errorf("%s: hintTrunc(%q, %d) = %q, want %q", tc.name, tc.in,
				tc.width, got, tc.want)
		}
	}
}

// TestB9HintsNeverFailASuccessfulIngest is the loudest form of the silent-skip
// contract: every broken geometry still exits 0 with the success line on
// stdout, and the campaign keeps the finding it wrote.
func TestB9HintsNeverFailASuccessfulIngest(t *testing.T) {
	// A protocol_model.json that is a DIRECTORY: ReadJson fails with EISDIR
	// while Stat succeeds — the geometry the plan-view disclosure was fixed
	// for (cmd_plan.go r46), and exactly the kind of artifact damage a hint
	// must not turn into a failed ingest.
	c, root, cid := t2Campaign(t)
	if err := os.MkdirAll(filepath.Join(c.ArtifactsDir,
		"protocol_model.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	b9Artifacts(t, c, "", b9Surface, b9Plan)
	b9PinID(t)
	code, out, errS := b9Ingest(t, root, cid, "p.json", b9Payload(
		`{"path":"l1/rollup/Rollup.sol","function":"commitBatch"}`))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "ingested F-abcdefabcdef ") {
		t.Fatalf("stdout is not the success line: %q", out)
	}
	if errS != "" {
		t.Fatalf("a broken model wrote to stderr: %q", errS)
	}
	if _, err := os.Stat(filepath.Join(c.FindingsDir,
		"F-abcdefabcdef.json")); err != nil {
		t.Fatalf("the finding was not written: %v", err)
	}
}
