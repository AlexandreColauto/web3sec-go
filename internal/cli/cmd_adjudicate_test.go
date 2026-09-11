package cli

// cmd_adjudicate tests (ord 80): the record/list surface of the NON-GOLD
// adjudication (internal/evalscore/adjudicate.go; the campaign_state key
// "eval_adjudications").
//
// The fixture pins the campaign program to ES03BankReentrancy — one dev case
// in the real pack (CASE-000000000003, reentrancy @
// src/ES03BankReentrancy.sol) — so the standing tally printed after a record
// exercises the SAME eval join the '## eval' audit section renders, on a
// campaign that actually matches a suite case. A finding whose class is not
// `reentrancy` anchors nothing, which is exactly the population an
// adjudication exists for; a finding on the gold class AND the gold location
// anchors the case, and a verdict on it is stale.
//
// argparse vectors pin the usage block and the error precedence, including
// the looksLikeOption guard on every value flag ("--verdict --json" must be
// "expected one argument", never a verdict named "--json").

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"websec/internal/evalscore"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// adjudicateCampaign opens a scratch campaign pinning an eval-suite program.
func adjudicateCampaign(t *testing.T, program string) (*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, program, state.InitOpts{})
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	return c, root
}

// adjudicateFinding ingests one live hypothesis through the schema-valid
// path and returns its id. class and path are the only anchor keys the eval
// join reads (root_cause.class, affected[0].path).
func adjudicateFinding(t *testing.T, c *state.Campaign, class, path string) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kvT("title", validation.VStr("a live finding")),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr(class)),
			kvT("description", validation.VStr("the mechanism described in detail")),
		)),
		kvT("affected", validation.VArr(validation.VObj(
			kvT("path", validation.VStr(path)),
			kvT("function", validation.VStr("f")),
		))),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("arbitrary EOA")),
			kvT("capabilities", validation.VArr()),
		)),
	), "code", "", "")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return objStr(f, "finding_id")
}

// adjCmd is one record-mode command line, so a test can mutate one field at
// a time and render it in the documented flag order.
type adjCmd struct {
	campaign   string
	finding    string
	verdict    string
	severity   string
	basis      string
	assumption string
	exec       string
	actor      string
	reason     string
}

func (a adjCmd) args() []string {
	out := []string{"adjudicate", a.campaign}
	if a.finding != "" {
		out = append(out, a.finding)
	}
	for _, f := range []struct{ name, val string }{
		{"--verdict", a.verdict}, {"--severity", a.severity},
		{"--basis", a.basis}, {"--assumption", a.assumption},
		{"--exec", a.exec}, {"--actor", a.actor}, {"--reason", a.reason},
	} {
		if f.val != "" {
			out = append(out, f.name, f.val)
		}
	}
	return out
}

// good is the reference record: everything the record mode requires, with a
// reason long enough for evalscore.AdjudicationReasonMin.
func (c adjCmd) good(finding string) adjCmd {
	c.finding = finding
	c.verdict = "additional-true-positive"
	c.basis = "author-review"
	c.actor = "alice"
	c.reason = "the oracle spot price is never validated"
	return c
}

// adjArgs prepends --root and appends any extra flags (the verb's own args
// stay contiguous, as on a real command line).
func adjArgs(root string, a adjCmd, extra ...string) []string {
	return append(append([]string{"--root", root}, a.args()...), extra...)
}

func TestAdjudicateHelp(t *testing.T) {
	code, out, errS := run(t, "adjudicate", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if out != adjudicateHelp {
		t.Fatalf("help\n%q\nwant\n%q", out, adjudicateHelp)
	}
	if !strings.HasPrefix(out, adjudicateUsage) ||
		!strings.Contains(out, "positional arguments:") ||
		!strings.Contains(out, "options:") {
		t.Fatalf("help shape: %q", out)
	}
	// The three verdicts are taught, one sentence each, and the two claims
	// an operator cannot guess are stated: a row replaces its predecessor,
	// and the eval section's adjusted precision is printed from these rows.
	for _, want := range []string{
		"additional-true-positive: the finding is real and the\n" +
			"                        gold dataset does not contain it",
		"false-positive: the\n" +
			"                        finding is wrong",
		"assumption-gated: the finding is\n" +
			"                        real only if the named assumption holds",
		"A row REPLACES the prior row for the same finding.",
		"adjusted precision is printed from these rows",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q", want)
		}
	}
	for _, want := range []string{"--verdict V", "--severity S", "--basis B",
		"--assumption TEXT", "--exec EXEC", "--actor A", "--reason R",
		"--gold FILE"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q", want)
		}
	}
	// The --gold prose names the pack an answer key and the time it is used.
	if !strings.Contains(out, "grading-time; not part of a campaign run") {
		t.Errorf("help missing the --gold prose")
	}
}

func TestAdjudicateArgparse(t *testing.T) {
	vec := []struct {
		name string
		args []string
		want string
	}{
		{"no args", []string{"adjudicate"},
			adjudicateUsage + "webv2 adjudicate: error: the following " +
				"arguments are required: campaign\n"},
		{"no record flags", []string{"adjudicate", "C-aaaaaaaaaa", "F-aaaaaaaaaaaa"},
			adjudicateUsage + "webv2 adjudicate: error: the following " +
				"arguments are required: --verdict, --basis, --actor, --reason\n"},
		{"one record flag", []string{"adjudicate", "C-aaaaaaaaaa",
			"F-aaaaaaaaaaaa", "--verdict", "additional-true-positive"},
			adjudicateUsage + "webv2 adjudicate: error: the following " +
				"arguments are required: --basis, --actor, --reason\n"},
		{"json value", []string{"adjudicate", "C-aaaaaaaaaa", "--json=1"},
			adjudicateUsage + "webv2 adjudicate: error: argument --json: " +
				"ignored explicit argument '1'\n"},
		{"help value", []string{"adjudicate", "-h=1"},
			adjudicateUsage + "webv2 adjudicate: error: argument -h/--help: " +
				"ignored explicit argument '1'\n"},
		{"verdict without value", []string{"adjudicate", "C-aaaaaaaaaa",
			"F-aaaaaaaaaaaa", "--verdict"},
			adjudicateUsage + "webv2 adjudicate: error: argument --verdict: " +
				"expected one argument\n"},
		// The looksLikeOption guard: an option token is never a value.
		{"verdict eats an option", []string{"adjudicate", "C-aaaaaaaaaa",
			"F-aaaaaaaaaaaa", "--verdict", "--json"},
			adjudicateUsage + "webv2 adjudicate: error: argument --verdict: " +
				"expected one argument\n"},
		{"unknown flag", []string{"adjudicate", "C-aaaaaaaaaa", "--bogus"},
			t14TopUsage + "webv2: error: unrecognized arguments: --bogus\n"},
		// A second leftover positional is unrecognized, but the missing
		// required options are reported first (argparse's own precedence).
		{"third positional", []string{"adjudicate", "C-aaaaaaaaaa",
			"F-aaaaaaaaaaaa", "F-bbbbbbbbbbbb"},
			adjudicateUsage + "webv2 adjudicate: error: the following " +
				"arguments are required: --verdict, --basis, --actor, " +
				"--reason\n"},
	}
	for _, v := range vec {
		code, out, errS := run(t, v.args...)
		if code != 2 || out != "" || errS != v.want {
			t.Errorf("%s: exit %d out %q err %q want %q",
				v.name, code, out, errS, v.want)
		}
	}
}

func TestAdjudicateMissingCampaign(t *testing.T) {
	code, out, errS := run(t, "--root", t.TempDir(), "adjudicate", "C-0000000000")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if !strings.Contains(errS, "no such campaign") {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestAdjudicateRecordPrintsRowAndTally: the record mode writes the row,
// prints the documented sentence, then the standing tally — the same numbers
// the eval section renders. The single live finding is unanchored (wrong
// class for the matched gold case) and judged additional-true-positive, so
// it leaves the false-positive penalty: the adjusted denominator keeps only
// the anchored and unadjudicated findings, which here is none (0/0).
func TestAdjudicateRecordPrintsRowAndTally(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	fid := adjudicateFinding(t, c, "oracle-manipulation",
		"src/ES03BankReentrancy.sol")

	code, out, errS := run(t, adjArgs(root,
		adjCmd{campaign: c.CampaignID}.good(fid))...)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := "adjudicated " + fid + " as additional-true-positive " +
		"(author-review) by alice\n" +
		"non-gold adjudications: 1 of 1 unanchored findings adjudicated " +
		"(additional-true-positive 1, false-positive 0, assumption-gated 0)\n" +
		"adjusted precision (denominator excludes findings adjudicated true " +
		"or gated): precision: 0/0 (95% CI n/a)\n" +
		"unadjudicated unanchored findings: 0\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
	rows, err := evalscore.Load(c)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("stored rows = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.Finding != fid || got.Verdict != "additional-true-positive" ||
		got.Severity != "tbd" || got.Basis != "author-review" ||
		got.Actor != "alice" ||
		got.Reason != "the oracle spot price is never validated" ||
		got.Assumption != "" || got.Exec != "" {
		t.Fatalf("stored row = %+v", got)
	}
	if got.At == "" {
		t.Fatal("Record must stamp the row's `at`")
	}
}

// TestAdjudicateRecordReplaces: a second verdict on the same finding
// replaces the prior row — one row, the new verdict — and the tally moves
// with it. Appending instead of replacing would count the finding twice.
func TestAdjudicateRecordReplaces(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	fid := adjudicateFinding(t, c, "oracle-manipulation",
		"src/ES03BankReentrancy.sol")

	first := adjCmd{campaign: c.CampaignID}.good(fid)
	if code, _, errS := run(t, adjArgs(root, first)...); code != 0 {
		t.Fatalf("first record exit %d: %q", code, errS)
	}
	second := first
	second.verdict = "false-positive"
	second.basis = "reproduction"
	second.actor = "bob"
	second.severity = "low"
	second.reason = "the attack path needs an admin key we do not have"
	code, out, errS := run(t, adjArgs(root, second)...)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.HasPrefix(out, "adjudicated "+fid+" as false-positive "+
		"(reproduction) by bob\n") {
		t.Fatalf("out = %q", out)
	}
	if !strings.Contains(out, "non-gold adjudications: 1 of 1 unanchored "+
		"findings adjudicated (additional-true-positive 0, false-positive 1, "+
		"assumption-gated 0)\n") {
		t.Fatalf("tally did not move to the new verdict: %q", out)
	}
	rows, err := evalscore.Load(c)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 (replace, not append)", len(rows))
	}
	row := evalscore.Index(rows)[fid]
	if row.Verdict != "false-positive" || row.Actor != "bob" ||
		row.Severity != "low" {
		t.Fatalf("row after replace = %+v", row)
	}
}

// TestAdjudicateStaleLine: a row whose finding DOES anchor a gold case
// applies to no unanchored finding. The tally says so — otherwise the
// operator would believe the score moved when it did not.
func TestAdjudicateStaleLine(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	// Gold class AND gold location: this finding anchors CASE-000000000003.
	fid := adjudicateFinding(t, c, "reentrancy", "src/ES03BankReentrancy.sol")

	code, out, errS := run(t, adjArgs(root,
		adjCmd{campaign: c.CampaignID}.good(fid))...)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := "adjudicated " + fid + " as additional-true-positive " +
		"(author-review) by alice\n" +
		"non-gold adjudications: 0 of 0 unanchored findings adjudicated " +
		"(additional-true-positive 0, false-positive 0, assumption-gated 0)\n" +
		"adjusted precision (denominator excludes findings adjudicated true " +
		"or gated): precision: 1/1 (95% CI 20.7–100.0%)\n" +
		"unadjudicated unanchored findings: 0\n" +
		"stale adjudications (rows that apply to no unanchored finding): 1\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestAdjudicateListEmpty pins the empty line, byte for byte.
func TestAdjudicateListEmpty(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	code, out, errS := run(t, "--root", root, "adjudicate", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if out != "no adjudications recorded\n" {
		t.Fatalf("out = %q", out)
	}
}

// TestAdjudicateListTwoRows: two records, two lines, every column aligned to
// the widest cell — the widest verdict (24 chars) fixes the verdict column,
// the widest basis (13) the basis column — and no trailing whitespace.
func TestAdjudicateListTwoRows(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	id1 := adjudicateFinding(t, c, "oracle-manipulation",
		"src/ES03BankReentrancy.sol")
	id2 := adjudicateFinding(t, c, "oracle-manipulation", "src/Lender.sol")

	one := adjCmd{campaign: c.CampaignID}.good(id1)
	two := adjCmd{campaign: c.CampaignID}
	two.finding = id2
	two.verdict = "false-positive"
	two.basis = "reproduction"
	two.actor = "bob"
	two.reason = "the borrow is capped below the profit floor"
	for _, a := range []adjCmd{one, two} {
		if code, _, errS := run(t, adjArgs(root, a)...); code != 0 {
			t.Fatalf("record exit %d: %q", code, errS)
		}
	}
	code, out, errS := run(t, "--root", root, "adjudicate", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := fmt.Sprintf("%s  %-24s  %-3s  %-13s  %-5s  %s\n"+
		"%s  %-24s  %-3s  %-13s  %-5s  %s\n",
		id1, "additional-true-positive", "tbd", "author-review", "alice",
		"the oracle spot price is never validated",
		id2, "false-positive", "tbd", "reproduction", "bob",
		"the borrow is capped below the profit floor")
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.TrimRight(line, " ") != line {
			t.Errorf("trailing space in %q", line)
		}
	}
}

// TestAdjudicateJSONShape: --json is one object with the keys in a fixed
// order. No rows means an EMPTY array (never null) and no zero-valued
// stale_adjudications key; a recorded row carries the section's row shape,
// with `assumption` and `exec` present only when they are set.
func TestAdjudicateJSONShape(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	fid := adjudicateFinding(t, c, "oracle-manipulation",
		"src/ES03BankReentrancy.sol")

	topKeys := []string{"campaign_id", "adjudications", "adjusted_precision",
		"unanchored", "additional_true_positive", "false_positive",
		"assumption_gated", "unadjudicated"}

	code, out, errS := run(t, "--root", root, "adjudicate", c.CampaignID, "--json")
	if code != 0 || errS != "" {
		t.Fatalf("empty --json exit %d err %q", code, errS)
	}
	if got := keyOrder(t, out); !equalStrs(got, topKeys) {
		t.Fatalf("empty key order = %v, want %v", got, topKeys)
	}
	empty := mustJSON(t, out)
	if rows := objAt(empty, "adjudications"); rows.Kind != validation.Arr ||
		len(rows.A) != 0 {
		t.Fatalf("empty adjudications = %s, want []",
			validation.CanonCompact(rows))
	}
	if v := objAt(empty, "stale_adjudications"); v.Kind != validation.Null {
		t.Fatalf("stale_adjudications = %s, want absent when zero",
			validation.CanonCompact(v))
	}
	// With no rows the single unanchored finding is still unadjudicated, so
	// the adjusted denominator is the raw one — the penalty is not lifted
	// by silence.
	if got := objStr(empty, "adjusted_precision"); got !=
		"precision: 0/1 (95% CI 0.0–79.3%)" {
		t.Fatalf("empty adjusted_precision = %q", got)
	}
	if n := objInt(empty, "unadjudicated"); n != 1 {
		t.Fatalf("empty unadjudicated = %d, want 1", n)
	}

	// A gated verdict: the assumption is required, and it is stored.
	gated := adjCmd{campaign: c.CampaignID}
	gated.finding = fid
	gated.verdict = "assumption-gated"
	gated.basis = "code-argument"
	gated.actor = "carol"
	gated.assumption = "the sequencer never reorders the deposit"
	gated.exec = "EXEC-0000000001"
	gated.reason = "gated on the ordering assumption above"
	code, out, errS = run(t, adjArgs(root, gated, "--json")...)
	if code != 0 || errS != "" {
		t.Fatalf("record --json exit %d err %q", code, errS)
	}
	if got := keyOrder(t, out); !equalStrs(got, topKeys) {
		t.Fatalf("recorded key order = %v, want %v", got, topKeys)
	}
	doc := mustJSON(t, out)
	rows := objListAt(doc, "adjudications")
	if len(rows) != 1 {
		t.Fatalf("adjudications = %d, want 1", len(rows))
	}
	// The row's own key order: finding, verdict, severity, basis,
	// assumption (set), exec (set), actor, reason.
	prev := -1
	for _, k := range []string{"finding", "verdict", "severity", "basis",
		"assumption", "exec", "actor", "reason"} {
		i := strings.Index(out, `"`+k+`":`)
		if i < 0 {
			t.Fatalf("row key %q missing from %s", k, out)
		}
		if i < prev {
			t.Fatalf("row key %q out of order in %s", k, out)
		}
		prev = i
	}
	if got := objStr(rows[0], "assumption"); got !=
		"the sequencer never reorders the deposit" {
		t.Fatalf("assumption = %q", got)
	}
	if got := objStr(rows[0], "exec"); got != "EXEC-0000000001" {
		t.Fatalf("exec = %q", got)
	}
	if got := objStr(rows[0], "verdict"); got != "assumption-gated" {
		t.Fatalf("verdict = %q", got)
	}
	if got := objStr(rows[0], "severity"); got != "tbd" {
		t.Fatalf("severity = %q, want the tbd default", got)
	}
	if n := objInt(doc, "assumption_gated"); n != 1 {
		t.Fatalf("assumption_gated = %d, want 1", n)
	}
	if n := objInt(doc, "unanchored"); n != 1 {
		t.Fatalf("unanchored = %d, want 1", n)
	}
}

// TestAdjudicateValidationErrors: everything evalscore.Validate/Record
// rejects exits 1 and prints the library's own message — only argparse-level
// problems exit 2 (TestAdjudicateArgparse).
func TestAdjudicateValidationErrors(t *testing.T) {
	vec := []struct {
		name    string
		mutate  func(a *adjCmd)
		wantErr string
	}{
		{"bad verdict", func(a *adjCmd) { a.verdict = "maybe" },
			"adjudication verdict 'maybe' is not one of"},
		{"bad basis", func(a *adjCmd) { a.basis = "vibes" },
			"adjudication basis 'vibes' is not one of"},
		{"bad severity", func(a *adjCmd) { a.severity = "urgent" },
			"adjudication severity 'urgent' is not one of"},
		{"short reason", func(a *adjCmd) { a.reason = "too short" },
			"requires a written reason"},
		{"gated without assumption", func(a *adjCmd) {
			a.verdict = "assumption-gated"
		}, "requires the assumption that must hold"},
		{"assumption on a non-gated verdict", func(a *adjCmd) {
			a.assumption = "the sequencer is honest"
		}, "an assumption is only meaningful with the assumption-gated verdict"},
	}
	for _, v := range vec {
		c, root := adjudicateCampaign(t, "ES03BankReentrancy")
		fid := adjudicateFinding(t, c, "oracle-manipulation",
			"src/ES03BankReentrancy.sol")
		a := adjCmd{campaign: c.CampaignID}.good(fid)
		v.mutate(&a)
		code, out, errS := run(t, adjArgs(root, a)...)
		if code != 1 || out != "" {
			t.Errorf("%s: exit %d out %q err %q", v.name, code, out, errS)
			continue
		}
		if !strings.HasPrefix(errS, "error: ") ||
			!strings.Contains(errS, v.wantErr) {
			t.Errorf("%s: stderr = %q, want %q", v.name, errS, v.wantErr)
		}
	}
}

// TestAdjudicateUnknownFinding: an id that is not in the campaign's live set
// is refused (exit 1) — an adjudication is a claim about a finding that
// exists.
func TestAdjudicateUnknownFinding(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	known := adjudicateFinding(t, c, "oracle-manipulation",
		"src/ES03BankReentrancy.sol")
	if known == "F-ffffffffffff" {
		t.Fatal("fixture id collides with the unknown id under test")
	}
	a := adjCmd{campaign: c.CampaignID}.good("F-ffffffffffff")
	code, out, errS := run(t, adjArgs(root, a)...)
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if !strings.Contains(errS, "no live finding 'F-ffffffffffff' in campaign "+
		c.CampaignID) {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestAdjudicateSeverityExplicit: an explicit severity is stored and listed
// (the tbd default is pinned by TestAdjudicateRecordPrintsRowAndTally).
func TestAdjudicateSeverityExplicit(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	fid := adjudicateFinding(t, c, "oracle-manipulation",
		"src/ES03BankReentrancy.sol")
	a := adjCmd{campaign: c.CampaignID}.good(fid)
	a.severity = "critical"
	if code, _, errS := run(t, adjArgs(root, a)...); code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	rows, err := evalscore.Load(c)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rows) != 1 || rows[0].Severity != "critical" {
		t.Fatalf("rows = %+v", rows)
	}
	code, out, errS := run(t, "--root", root, "adjudicate", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("list exit %d err %q", code, errS)
	}
	if !strings.Contains(out, "  critical  ") {
		t.Fatalf("list does not show the severity column: %q", out)
	}
}

// TestAdjudicateListEscapesControlCharacters: a reason may carry a newline
// (nothing in the schema forbids it), and the renderer pads every column but
// the last, so a raw newline would print a second, unlabelled line and the
// row would read as two records. The cell is escaped BEFORE it is measured
// and printed: the stored row stays exactly one printed line and carries the
// two-character \n.
func TestAdjudicateListEscapesControlCharacters(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	fid := adjudicateFinding(t, c, "oracle-manipulation",
		"src/ES03BankReentrancy.sol")
	if _, err := evalscore.Record(c, evalscore.Adjudication{
		Finding: fid, Verdict: "additional-true-positive", Severity: "tbd",
		Basis: "author-review", Actor: "alice",
		Reason: "the oracle is stale\nand the guard reads it twice",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	code, out, errS := run(t, "--root", root, "adjudicate", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := fid + "  additional-true-positive  tbd  author-review  alice  " +
		`the oracle is stale\nand the guard reads it twice` + "\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("the row spans %d lines: %q", n, out)
	}
}

// TestAdjudicateBrokenStateWithholdsTally: a campaign_state that no longer
// validates gives evalscore.Score ok=false with a zero Report. Printing that
// Report would show "unanchored: 0" and an empty adjusted precision as if
// they were measurements, so both modes name the failure instead: text gets
// the single unavailable line, --json a `note` key and NO counter at all.
func TestAdjudicateBrokenStateWithholdsTally(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	adjudicateFinding(t, c, "oracle-manipulation", "src/ES03BankReentrancy.sol")
	adjudicateBreakState(t, c)

	code, out, errS := run(t, "--root", root, "adjudicate", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("list exit %d err %q", code, errS)
	}
	want := "no adjudications recorded\n" + adjudicateJoinUnavailable + "\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}

	code, out, errS = run(t, "--root", root, "adjudicate", c.CampaignID, "--json")
	if code != 0 || errS != "" {
		t.Fatalf("--json exit %d err %q", code, errS)
	}
	if got := keyOrder(t, out); !equalStrs(got,
		[]string{"campaign_id", "adjudications", "note"}) {
		t.Fatalf("key order = %v, want the note shape with no counters", got)
	}
	doc := mustJSON(t, out)
	if got := objStr(doc, "note"); got != adjudicateJoinUnavailable {
		t.Fatalf("note = %q", got)
	}
	for _, k := range []string{"adjusted_precision", "unanchored",
		"additional_true_positive", "false_positive", "assumption_gated",
		"unadjudicated", "stale_adjudications", "invalid_adjudications"} {
		if v := objAt(doc, k); v.Kind != validation.Null {
			t.Fatalf("%s = %s, want the key absent",
				k, validation.CanonCompact(v))
		}
	}
}

// TestAdjudicateHandRowWithoutSeverityIsTbd: the schema does not require a
// severity, so a hand-written row may omit it while Record stores "tbd" for
// the same logical case. Both projections show the SAME "tbd" — the stored
// row is not rewritten.
func TestAdjudicateHandRowWithoutSeverityIsTbd(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	fid := adjudicateFinding(t, c, "oracle-manipulation",
		"src/ES03BankReentrancy.sol")
	adjudicateHandRow(t, c, validation.VObj(
		kvT("finding", validation.VStr(fid)),
		kvT("verdict", validation.VStr("false-positive")),
		kvT("basis", validation.VStr("author-review")),
		kvT("reason", validation.VStr("hand written without a severity")),
		kvT("actor", validation.VStr("dave")),
		kvT("at", validation.VStr(state.NowIso())),
	))

	code, out, errS := run(t, "--root", root, "adjudicate", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("list exit %d err %q", code, errS)
	}
	want := fid + "  false-positive  tbd  author-review  dave  " +
		"hand written without a severity\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}

	code, out, errS = run(t, "--root", root, "adjudicate", c.CampaignID, "--json")
	if code != 0 || errS != "" {
		t.Fatalf("--json exit %d err %q", code, errS)
	}
	rows := objListAt(mustJSON(t, out), "adjudications")
	if len(rows) != 1 || objStr(rows[0], "severity") != "tbd" {
		t.Fatalf("json severity = %v, want tbd", rows)
	}
}

// TestAdjudicateInvalidRowsReported: a row the SCHEMA accepts but
// evalscore.Validate refuses (here the schema measures the raw reason and
// Validate measures the trimmed one) is not an adjudication, but it must not
// disappear without a trace either. The post-record tally and the --json
// object both name the count, and both do it ONLY when it is non-zero.
func TestAdjudicateInvalidRowsReported(t *testing.T) {
	c, root := adjudicateCampaign(t, "ES03BankReentrancy")
	fid := adjudicateFinding(t, c, "oracle-manipulation",
		"src/ES03BankReentrancy.sol")
	adjudicateHandRow(t, c, adjudicationRow("F-0000000000",
		"false-positive", "author-review", "abc       ", "mallory"))

	a := adjCmd{campaign: c.CampaignID}.good(fid)
	code, out, errS := run(t, adjArgs(root, a)...)
	if code != 0 || errS != "" {
		t.Fatalf("record exit %d err %q", code, errS)
	}
	if !strings.Contains(out,
		"invalid adjudication rows (refused by validation): 1\n") {
		t.Fatalf("tally does not report the refused row: %q", out)
	}

	code, out, errS = run(t, "--root", root, "adjudicate", c.CampaignID, "--json")
	if code != 0 || errS != "" {
		t.Fatalf("--json exit %d err %q", code, errS)
	}
	tail := []string{"campaign_id", "adjudications", "adjusted_precision",
		"unanchored", "additional_true_positive", "false_positive",
		"assumption_gated", "unadjudicated", "invalid_adjudications"}
	if got := keyOrder(t, out); !equalStrs(got, tail) {
		t.Fatalf("key order = %v, want %v", got, tail)
	}
	if n := objInt(mustJSON(t, out), "invalid_adjudications"); n != 1 {
		t.Fatalf("invalid_adjudications = %d, want 1", n)
	}

	// The counter is presence-gated: a campaign whose rows all validate has
	// no such key (TestAdjudicateJSONShape pins the same topKeys).
	clean, cleanRoot := adjudicateCampaign(t, "ES03BankReentrancy")
	cleanID := adjudicateFinding(t, clean, "oracle-manipulation",
		"src/ES03BankReentrancy.sol")
	if code, _, errS := run(t, adjArgs(cleanRoot,
		adjCmd{campaign: clean.CampaignID}.good(cleanID))...); code != 0 {
		t.Fatalf("clean record exit %d: %q", code, errS)
	}
	code, out, errS = run(t, "--root", cleanRoot, "adjudicate",
		clean.CampaignID, "--json")
	if code != 0 || errS != "" {
		t.Fatalf("clean --json exit %d err %q", code, errS)
	}
	if v := objAt(mustJSON(t, out), "invalid_adjudications"); v.Kind != validation.Null {
		t.Fatalf("invalid_adjudications = %s, want the key absent",
			validation.CanonCompact(v))
	}
}

// adjudicateBreakState drops the REQUIRED `phase` key from campaign_state.
// The doc still parses as JSON — evalscore.Load still reads its rows — but it
// no longer validates, which is the case evalscore.Score cannot express
// through the Report alone.
func adjudicateBreakState(t *testing.T, c *state.Campaign) {
	t.Helper()
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatalf("ReadJson: %v", err)
	}
	kept := make([]validation.KV, 0, len(st.O))
	for _, kv := range st.O {
		if kv.K != "phase" {
			kept = append(kept, kv)
		}
	}
	st.O = kept
	if err := os.WriteFile(c.StatePath,
		[]byte(validation.DumpIndentedASCII(st)), 0o644); err != nil {
		t.Fatalf("write broken state: %v", err)
	}
}

// adjudicationRow is one hand-written state row, in schema order.
func adjudicationRow(finding, verdict, basis, reason, actor string) validation.Value {
	return validation.VObj(
		kvT("finding", validation.VStr(finding)),
		kvT("verdict", validation.VStr(verdict)),
		kvT("basis", validation.VStr(basis)),
		kvT("reason", validation.VStr(reason)),
		kvT("actor", validation.VStr(actor)),
		kvT("at", validation.VStr(state.NowIso())),
	)
}

// adjudicateHandRow appends a row to the state doc WITHOUT going through
// evalscore.Record, which is the only writer the CLI has: the hand-edited
// shape (a row with no severity, a row Validate refuses) is exactly what a
// human editing campaign_state produces, and the schema still accepts it.
func adjudicateHandRow(t *testing.T, c *state.Campaign, row validation.Value) {
	t.Helper()
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatalf("ReadJson: %v", err)
	}
	prior := []validation.Value{}
	for _, kv := range st.O {
		if kv.K == "eval_adjudications" && kv.V.Kind == validation.Arr {
			prior = kv.V.A
		}
	}
	st.O = validation.SetOrAppend(st.O, "eval_adjudications",
		validation.VArr(append(prior, row)...))
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatalf("WriteJson: %v", err)
	}
}

// TestAdjudicateRegistered guards the registration: the verb is in the usage
// block (the runbook parity test owns the documentation side).
func TestAdjudicateRegistered(t *testing.T) {
	cmd, ok := commandByName("adjudicate")
	if !ok {
		t.Fatal("adjudicate is not registered")
	}
	if cmd.ord != 80 {
		t.Fatalf("ord = %d, want 80", cmd.ord)
	}
	if !strings.Contains(usageText(), "adjudicate") {
		t.Fatal("usage block does not list adjudicate")
	}
}

// equalStrs is reflect.DeepEqual for two short string slices.
func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestAdjudicateGoldPackListProvenance: in list mode --gold loads the
// operator's answer key and prints its provenance — the suite the tally
// would be computed against. Without the flag no such line appears.
func TestAdjudicateGoldPackListProvenance(t *testing.T) {
	c, root := adjudicateCampaign(t, "Morph")
	path, digest := scGoldWrite(t, t.TempDir(), "Morph", "dos-griefing", true)

	code, out, errS := run(t, "--root", root, "adjudicate", c.CampaignID,
		"--gold", path)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := "no adjudications recorded\n" +
		"gold pack: " + path + " (sha256 " + digest[:12] + ")\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}

	// Unverified: a pack with no sidecar says so rather than implying a hash.
	dir := t.TempDir()
	plain, _ := scGoldWrite(t, dir, "Morph", "dos-griefing", false)
	code, out, errS = run(t, "--root", root, "adjudicate", c.CampaignID,
		"--gold", plain)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out, "gold pack: "+plain+
		" (unverified - no sha256 sidecar found)\n") {
		t.Fatalf("missing unverified provenance:\n%s", out)
	}

	// No flag: byte-identical to before this option existed.
	code, out, errS = run(t, "--root", root, "adjudicate", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if out != "no adjudications recorded\n" {
		t.Fatalf("no-flag out\n%q", out)
	}

	// --json carries the same fact, presence-gated.
	code, out, errS = run(t, "--root", root, "adjudicate", c.CampaignID,
		"--gold", path, "--json")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	gp, _ := doc["gold_pack"].(map[string]any)
	if gp == nil || gp["path"] != path || gp["sha256"] != digest ||
		gp["verified"] != true {
		t.Fatalf("gold_pack = %v\n%s", gp, out)
	}
}

// TestAdjudicateGoldPackRefused: a bad pack is a fail-loud refusal (exit 1),
// never a silently smaller suite.
func TestAdjudicateGoldPackRefused(t *testing.T) {
	c, root := adjudicateCampaign(t, "Morph")
	dir := t.TempDir()
	p, digest := scGoldWrite(t, dir, "Morph", "dos-griefing", true)
	if err := os.WriteFile(strings.TrimSuffix(p, ".json")+".sha256",
		[]byte(strings.Repeat("0", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "adjudicate", c.CampaignID,
		"--gold", p)
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q, want a refusal", code, out)
	}
	for _, want := range []string{"does not match its sidecar", digest} {
		if !strings.Contains(errS, want) {
			t.Fatalf("stderr %q does not name %q", errS, want)
		}
	}
}

// TestAdjudicateRecordGoldTally: with --gold the provenance line heads the
// tally, and the tally's numbers come from the pack's suite — without it a
// held-out campaign would print "no gold case matches" forever.
func TestAdjudicateRecordGoldTally(t *testing.T) {
	c, root := adjudicateCampaign(t, "Morph")
	path, digest := scGoldWrite(t, t.TempDir(), "Morph", "dos-griefing", true)
	fid := adjudicateFinding(t, c, "oracle-manipulation", "src/Elsewhere.sol")

	code, out, errS := run(t, adjArgs(root,
		adjCmd{campaign: c.CampaignID}.good(fid), "--gold", path)...)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := "adjudicated " + fid + " as additional-true-positive " +
		"(author-review) by alice\n" +
		"gold pack: " + path + " (sha256 " + digest[:12] + ")\n" +
		"non-gold adjudications: 1 of 1 unanchored findings adjudicated " +
		"(additional-true-positive 1, false-positive 0, assumption-gated 0)\n" +
		"adjusted precision (denominator excludes findings adjudicated true " +
		"or gated): precision: 0/0 (95% CI n/a)\n" +
		"unadjudicated unanchored findings: 0\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}
