// cmd_probes_list_summary_test.go — B5(a) regression: `probes <C> list
// --summary` is the per-axis count cockpit (rows, undispositioned,
// risky = tier 0 or assertion_gap >= 3 via planner.HighRiskRow) plus the
// pending pointer, with NO row table and NO per-row lines; the quota
// disclosures (warning + missing) ride stderr exactly as `probes run` renders
// them. The ABSENT case — `list` with no --summary — is pinned byte-for-byte
// here, because the flag must not have moved one existing byte; `--json
// --summary` is pinned to be the plain --json view (one machine shape).
//
// Counts come from probes.SurfaceSummary (summary.open_rows, which already
// carries tier + assertion_gap): the risky count is over the UNDISPOSITIONED
// rows — a cockpit asks how much dangerous work is still open.
package cli

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"websec/internal/validation"
)

// summaryDefaultListStdout is the whole `list` stdout on the t29 fixture with
// no plan: the header, the one emitted axis line and the ten row lines.
const summaryDefaultListStdout = `probe surface: 10 rows (0 dispositioned, 10 open)
  enforcement-timing (L-03, assertion-strength): sites 77, rows 10, emitted 10, tail 0 — emitted
    81dfad6492 rank 1 tier 0 gap 4 Rollup.sol#L45, Rollup.sol#L66 — — open (not emitted)
    66c7d14d35 rank 2 tier 0 gap 4 Rollup.sol#L49, Rollup.sol#L97 — — open (not emitted)
    b6fe31cdf7 rank 3 tier 0 gap 4 Rollup.sol#L61, Rollup.sol#L105 — — open (not emitted)
    63904ecbc1 rank 4 tier 0 gap 4 Rollup.sol#L53, Rollup.sol#L93 — — open (not emitted)
    46ebc2a5a1 rank 5 tier 0 gap 4 Rollup.sol#L57, Rollup.sol#L101 — — open (not emitted)
    748abbf715 rank 6 tier 0 gap 4 contracts/mock/MockRollup.sol#L15, contracts/mock/MockRollup.sol#L121 — — open (not emitted)
    d549f9e66a rank 7 tier 1 gap 4 Rollup.sol#L73, Rollup.sol#L121 — — open (not emitted)
    d6e1821dc6 rank 8 tier 1 gap 4 Rollup.sol#L79, Rollup.sol#L109 — — open (not emitted)
    dd489a9a69 rank 9 tier 1 gap 4 Rollup.sol#L83, Rollup.sol#L113 — — open (not emitted)
    954d79770b rank 10 tier 1 gap 4 Rollup.sol#L87, Rollup.sol#L117 — — open (not emitted)
`

// summaryDefaultListAllStdout is `list --all` whole: the same header, all six
// axis lines (incl. no-sites) with the published blind keys, then the rows.
// Pinned because the blind-key block was factored into probeBlindLines for the
// summary's reuse — the row view's bytes must not have moved.
const summaryDefaultListAllStdout = `probe surface: 10 rows (0 dispositioned, 10 open)
  accumulator-skew (L-01, accumulator-basis-skew): sites 0, rows 0, emitted 0, tail 0 — no-sites
  enforcement-timing (L-03, assertion-strength): sites 77, rows 10, emitted 10, tail 0 — emitted
      blind: MockRollup::finalizeBatch::batch:index — finalizeBatch guards batch:index at class 4; the strongest assertion (class 4) adds nothing
      blind: MockRollup::finalizeBatch::prev:state — finalizeBatch asserts prev:state itself (class 4) — no asymmetry
      blind: MockRollup::finalizeBatch::prev:state:root — finalizeBatch asserts prev:state:root itself (class 4) — no asymmetry
      blind: MockRollup::finalizeBatch::state:root — finalizeBatch asserts state:root itself (class 4) — no asymmetry
  primitive-symmetry (L-04, custody-primitive): sites 0, rows 0, emitted 0, tail 0 — no-sites
  liveness (L-01, sequential-cursor): sites 0, rows 0, emitted 0, tail 0 — no-sites
  guard-short-circuit (L-01, short-circuitable-guard): sites 0, rows 0, emitted 0, tail 0 — no-sites
  incentive-inversion (L-02, trust-assumption): sites 0, rows 0, emitted 0, tail 0 — no-sites
    81dfad6492 rank 1 tier 0 gap 4 Rollup.sol#L45, Rollup.sol#L66 — — open (not emitted)
    66c7d14d35 rank 2 tier 0 gap 4 Rollup.sol#L49, Rollup.sol#L97 — — open (not emitted)
    b6fe31cdf7 rank 3 tier 0 gap 4 Rollup.sol#L61, Rollup.sol#L105 — — open (not emitted)
    63904ecbc1 rank 4 tier 0 gap 4 Rollup.sol#L53, Rollup.sol#L93 — — open (not emitted)
    46ebc2a5a1 rank 5 tier 0 gap 4 Rollup.sol#L57, Rollup.sol#L101 — — open (not emitted)
    748abbf715 rank 6 tier 0 gap 4 contracts/mock/MockRollup.sol#L15, contracts/mock/MockRollup.sol#L121 — — open (not emitted)
    d549f9e66a rank 7 tier 1 gap 4 Rollup.sol#L73, Rollup.sol#L121 — — open (not emitted)
    d6e1821dc6 rank 8 tier 1 gap 4 Rollup.sol#L79, Rollup.sol#L109 — — open (not emitted)
    dd489a9a69 rank 9 tier 1 gap 4 Rollup.sol#L83, Rollup.sol#L113 — — open (not emitted)
    954d79770b rank 10 tier 1 gap 4 Rollup.sol#L87, Rollup.sol#L117 — — open (not emitted)
`

// summaryStdout is `list --summary` whole on the same fixture: header, one
// line per axis IN THE SURFACE (no-sites axes included), the pending pointer —
// and nothing else.
const summaryStdout = `probe surface: 10 rows (0 dispositioned, 10 open)
  accumulator-skew (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  enforcement-timing (L-03): rows 10, undispositioned 10, risky(tier 0/gap>=3) 10
  primitive-symmetry (L-04): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  liveness (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  guard-short-circuit (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  incentive-inversion (L-02): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
10 pending — see webv2 probes C-probecli01 pending
`

// summaryAxisStdout is `list --summary --axis L-01`: only the three L-01 axes
// are counted, while the header and the pointer stay campaign-wide (they name
// a campaign-wide command).
const summaryAxisStdout = `probe surface: 10 rows (0 dispositioned, 10 open)
  accumulator-skew (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  liveness (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  guard-short-circuit (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
10 pending — see webv2 probes C-probecli01 pending
`

// summaryAllClearStdout is `list --summary` after every emitted row has been
// dispositioned: the rows are still there (rows 10) but nothing is open and
// nothing risky is open — the risky count is over the open set, so it drops to
// 0 with the work.
const summaryAllClearStdout = `probe surface: 10 rows (10 dispositioned, 0 open)
  accumulator-skew (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  enforcement-timing (L-03): rows 10, undispositioned 0, risky(tier 0/gap>=3) 0
  primitive-symmetry (L-04): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  liveness (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  guard-short-circuit (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  incentive-inversion (L-02): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
all clear: 0 pending — every surface row is dispositioned
`

// summaryOverrunStdout is `list --summary` on the over-tight-quota surface
// (`run --total 2`): the axis kept 10 ranked rows but only 3 are on the
// surface, so undispositioned/risky count the 3 emitted rows — and the two
// quota disclosures go to stderr (asserted in the disclosure test).
const summaryOverrunStdout = `probe surface: 3 rows (0 dispositioned, 3 open)
  accumulator-skew (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  enforcement-timing (L-03): rows 10, undispositioned 3, risky(tier 0/gap>=3) 3
  primitive-symmetry (L-04): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  liveness (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  guard-short-circuit (L-01): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
  incentive-inversion (L-02): rows 0, undispositioned 0, risky(tier 0/gap>=3) 0
3 pending — see webv2 probes C-probecli01 pending
`

// TestProbesListSummaryAbsentCaseIsByteIdentical is the byte-discipline pin:
// with --summary absent, `list` and `list --all` render exactly the bytes they
// rendered before the flag existed, stderr stays empty, and the new words
// ("risky(", "pending — see") appear nowhere. `--json --summary` is the plain
// --json view, byte for byte and key for key (one machine shape).
func TestProbesListSummaryAbsentCaseIsByteIdentical(t *testing.T) {
	ws, _, _, _ := t29Setup(t, t29Ranking, false)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list")
	if code != 0 {
		t.Fatalf("list exit %d: out=%q err=%q", code, out, errS)
	}
	if out != summaryDefaultListStdout {
		t.Errorf("default list stdout changed:\ngot  %q\nwant %q", out,
			summaryDefaultListStdout)
	}
	if errS != "" {
		t.Errorf("default list stderr must stay empty: %q", errS)
	}
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "list", "--all")
	if code != 0 {
		t.Fatalf("list --all exit %d: out=%q err=%q", code, out, errS)
	}
	if out != summaryDefaultListAllStdout {
		t.Errorf("list --all stdout changed (the blind block moved?):\ngot  "+
			"%q\nwant %q", out, summaryDefaultListAllStdout)
	}
	if errS != "" {
		t.Errorf("list --all stderr must stay empty: %q", errS)
	}
	if strings.Contains(out, "risky(") || strings.Contains(out, "pending — see") {
		t.Errorf("the summary's new lines leaked into the absent case: %q", out)
	}

	// --json is the machine view; --summary must not invent a second shape.
	code, plain, errS := run(t, "--root", ws, "probes", t29CID, "list", "--json")
	if code != 0 {
		t.Fatalf("list --json exit %d: %q", code, errS)
	}
	code, withSummary, errS := run(t, "--root", ws, "probes", t29CID, "list",
		"--json", "--summary")
	if code != 0 {
		t.Fatalf("list --json --summary exit %d: %q", code, errS)
	}
	if withSummary != plain {
		t.Errorf("--json --summary is not the plain --json view:\ngot  %q\n"+
			"want %q", withSummary, plain)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(plain), &doc); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "axes,campaign_id,current_index_sha,dispositioned,index_sha,open," +
		"rows,stale,surface_rows"
	if got := strings.Join(keys, ","); got != want {
		t.Errorf("--json top-level keys = %q, want %q", got, want)
	}
}

// TestProbesListSummaryCountsPerAxisAndPointsAtPending pins the cockpit whole
// on the t29 fixture: one line per axis in the surface (no-sites axes
// included), the risky count via planner.HighRiskRow (every row here is tier 0
// or gap 4, so 10), the pending pointer naming the drain command — and NO row
// table, no per-row line, no lens-closure line.
func TestProbesListSummaryCountsPerAxisAndPointsAtPending(t *testing.T) {
	ws, _, _, surface := t29Setup(t, t29Ranking, false)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list",
		"--summary")
	if code != 0 {
		t.Fatalf("list --summary exit %d: out=%q err=%q", code, out, errS)
	}
	if out != summaryStdout {
		t.Fatalf("summary stdout:\ngot  %q\nwant %q", out, summaryStdout)
	}
	if errS != "" {
		t.Errorf("a clean summary must write nothing to stderr: %q", errS)
	}
	for _, leak := range []string{" rank ", "    ", "open (not emitted)",
		"dispositioned\n        reason:"} {
		if strings.Contains(out, leak) {
			t.Errorf("the summary leaked a row-table fragment %q: %q", leak,
				out)
		}
	}
	// The count is the surface's own: 10 rows, all open, all high-risk.
	if n := len(t29ObjList(surface, "rows")); n != 10 {
		t.Fatalf("fixture rows = %d, want 10", n)
	}
	if !strings.Contains(out, "enforcement-timing (L-03): rows 10, "+
		"undispositioned 10, risky(tier 0/gap>=3) 10") {
		t.Errorf("the emitted axis line is wrong: %q", out)
	}
	// The pointer names the campaign-wide drain command, not a row.
	if !strings.Contains(out, "10 pending — see webv2 probes C-probecli01 "+
		"pending\n") {
		t.Errorf("missing the pending pointer: %q", out)
	}
}

// TestProbesListSummaryAllReusesTheRowViewsBlindKeys checks that --summary
// --all prints exactly the blind lines the row view prints for the same axes —
// the shared probeBlindLines seam — and still prints no rows.
func TestProbesListSummaryAllReusesTheRowViewsBlindKeys(t *testing.T) {
	ws, _, _, _ := t29Setup(t, t29Ranking, false)
	code, rowView, errS := run(t, "--root", ws, "probes", t29CID, "list",
		"--all")
	if code != 0 {
		t.Fatalf("list --all exit %d: %q", code, errS)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list",
		"--summary", "--all")
	if code != 0 {
		t.Fatalf("list --summary --all exit %d: %q", code, errS)
	}
	wantBlind := []string{}
	for _, line := range strings.Split(rowView, "\n") {
		if strings.HasPrefix(line, "      blind: ") {
			wantBlind = append(wantBlind, line)
		}
	}
	if len(wantBlind) != 4 {
		t.Fatalf("the row view published %d blind lines, want 4: %q",
			len(wantBlind), rowView)
	}
	for _, line := range wantBlind {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("summary --all lost the blind line %q:\n%s", line, out)
		}
	}
	if !strings.Contains(out, "  enforcement-timing (L-03): rows 10, "+
		"undispositioned 10, risky(tier 0/gap>=3) 10\n      blind: ") {
		t.Errorf("the blind lines are not nested under their axis: %q", out)
	}
	if strings.Contains(out, " rank ") {
		t.Errorf("summary --all printed the row table: %q", out)
	}
}

// TestProbesListSummaryAxisFilterKeepsTheCampaignPointer pins --axis: the
// per-axis lines are the selected axes only, while the header and the pointer
// stay campaign-wide — `probes <C> pending` has no --axis, so a filtered
// pointer would name a command that cannot reproduce the count.
func TestProbesListSummaryAxisFilterKeepsTheCampaignPointer(t *testing.T) {
	ws, _, _, _ := t29Setup(t, t29Ranking, false)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list",
		"--summary", "--axis", "L-01")
	if code != 0 {
		t.Fatalf("list --summary --axis L-01 exit %d: out=%q err=%q", code,
			out, errS)
	}
	if out != summaryAxisStdout {
		t.Fatalf("filtered summary:\ngot  %q\nwant %q", out, summaryAxisStdout)
	}
	if strings.Contains(out, "enforcement-timing") {
		t.Errorf("the L-01 filter leaked L-03: %q", out)
	}
	if !strings.Contains(out, "10 pending — see webv2 probes C-probecli01 "+
		"pending") {
		t.Errorf("the pointer must stay campaign-wide: %q", out)
	}
}

// TestProbesListSummaryAllClearAfterEveryRowIsDispositioned walks the fixture
// to a drained surface: the rows stay (rows 10) but undispositioned and risky
// both read 0 — the risky count is over the OPEN set, so a dispositioned
// tier-0 row stops being counted — and the pointer becomes the all-clear line.
func TestProbesListSummaryAllClearAfterEveryRowIsDispositioned(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list",
		"--summary")
	if code != 0 {
		t.Fatalf("list --summary exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "risky(tier 0/gap>=3) 10") ||
		!strings.Contains(out, "10 pending — see") {
		t.Fatalf("the undrained summary is wrong: %q", out)
	}
	// morph §6.1/§7.1: enforcement-timing rows owe the interim pricing now;
	// the arm exercises the all-clear summary, so each drained row is priced
	// (citing its own consumer) instead of being refused upstream.
	for _, row := range t29ObjList(surface, "rows") {
		p := t29ProbePriority(t, c, validation.ObjStr(row, "row_id"))
		code, out, errS = run(t, "--root", ws, "answered", t29CID,
			validation.ObjStr(p, "id"), "answered", "--anchor", "consumer",
			"--reason", "the batch:index join is anchored elsewhere",
			"--interim", cliInterimFor(row),
			"--actor", "pytest")
		if code != 0 {
			t.Fatalf("answered exit %d: out=%q err=%q", code, out, errS)
		}
	}
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "list",
		"--summary")
	if code != 0 {
		t.Fatalf("drained list --summary exit %d: out=%q err=%q", code, out,
			errS)
	}
	if out != summaryAllClearStdout {
		t.Fatalf("all-clear summary:\ngot  %q\nwant %q", out,
			summaryAllClearStdout)
	}
	if strings.Contains(out, "pending — see") {
		t.Errorf("a drained surface must not point at pending work: %q", out)
	}
}

// TestProbesListSummaryDisclosuresRideStderr: the summary carries the missing[]
// and warning[] lines the row view hides, as the SAME byte-exact stderr lines
// `probes run` renders (r35 F1 / B5(b) convention) — stdout keeps the counts.
func TestProbesListSummaryDisclosuresRideStderr(t *testing.T) {
	ws, _, _, _ := t29Setup(t, t29Ranking, false)
	code, _, errS := run(t, "--root", ws, "probes", t29CID, "run",
		"--total", "2")
	if code != 0 {
		t.Fatalf("run --total 2 exit %d: %q", code, errS)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list",
		"--summary")
	if code != 0 {
		t.Fatalf("list --summary exit %d: out=%q err=%q", code, out, errS)
	}
	if out != summaryOverrunStdout {
		t.Errorf("overrun summary stdout:\ngot  %q\nwant %q", out,
			summaryOverrunStdout)
	}
	if !strings.Contains(errS, probesOverrunWarning) {
		t.Errorf("stderr missing the byte-exact warning line: %q", errS)
	}
	if !strings.Contains(errS, probesOverrunMissing) {
		t.Errorf("stderr missing the byte-exact missing line: %q", errS)
	}
	if strings.Contains(out, "warning:") || strings.Contains(out, "missing:") {
		t.Errorf("the disclosures leaked onto stdout: %q", out)
	}
}

// TestProbesListSummaryHelpAdvertisesTheFlag pins the additive help/usage
// bytes: the flag is on the usage line, described in the options block, and
// named in the parent verb's list entry.
func TestProbesListSummaryHelpAdvertisesTheFlag(t *testing.T) {
	code, out, errS := run(t, "probes", "campaign", "list", "--help")
	if code != 0 {
		t.Fatalf("list --help exit %d: out=%q err=%q", code, out, errS)
	}
	for _, want := range []string{
		"usage: webv2 probes campaign list [-h] [--axis A] [--all] " +
			"[--json] [--summary]\n",
		"  --summary   the cockpit instead of the table: one line per axis",
		"risky = tier 0 or assertion_gap >= 3",
		"with --json it is the plain --json view\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("list --help missing %q:\n%s", want, out)
		}
	}
	code, out, errS = run(t, "probes", "--help")
	if code != 0 {
		t.Fatalf("probes --help exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out,
		"(--summary: per-axis counts + the pending pointer, no\n") {
		t.Errorf("the parent verb help does not mention --summary:\n%s", out)
	}
}
