// cmd_probes_quota_stream_test.go — B5(b) regression: the probes quota
// disclosures ("  warning: floor-reserve-exceeds-total…" from
// probes/quotaWarnings and "  missing: quota under-filled…" from
// probes/missingEntry) are WARNINGS, so they ride STDERR; stdout keeps the two
// count lines, the axis lines and the emit summary. See the convention note at
// cmd_artifact_register.go kept-ghost disclosure (r35 F1) and the print sites in
// cmd_probes_run.go:51-59 and cmd_probes_list.go:209-214.
package cli

import (
	"strings"
	"testing"
)

// probesOverrunWarning is the byte-exact line quotaWarnings renders for the
// t29 fixture run with --total 2 (floor 3 on the single axis that has rows).
const probesOverrunWarning = "  warning: floor reserve 3 (floor 3 x 1 axes " +
	"with rows) exceeds --total 2: the ceiling may not trim below the " +
	"reserve, so the surface emits 3 rows and every axis with a floor " +
	"reports `under-filled`. Raise --total to >= 3 or lower the floor\n"

// probesOverrunMissing is the byte-exact line the missing[] loop renders for
// the same run (assertion-strength: 10 rows, emitted 3).
const probesOverrunMissing = "  missing: quota under-filled: assertion-" +
	"strength produced 10 rows, emitted 3 — raise --per-axis or disposition " +
	"the tail\n"

// TestProbesQuotaDisclosuresRideStderr is the B5(b) regression: an over-tight
// floor puts BOTH disclosures on stderr (byte-identical lines, warnings before
// missing as before the move) and leaves stdout clean of both, while the
// contractual stdout lines stay put. `probes list` shares the split.
func TestProbesQuotaDisclosuresRideStderr(t *testing.T) {
	ws, _, _, _ := t29Setup(t, t29Ranking, false)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run",
		"--total", "2")
	if code != 0 {
		t.Fatalf("run exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, probesOverrunWarning) {
		t.Errorf("stderr missing the byte-exact warning line: %q", errS)
	}
	if !strings.Contains(errS, probesOverrunMissing) {
		t.Errorf("stderr missing the byte-exact missing line: %q", errS)
	}
	if w, m := strings.Index(errS, probesOverrunWarning),
		strings.Index(errS, probesOverrunMissing); w > m {
		t.Errorf("stderr order flipped (warning %d, missing %d): %q", w, m, errS)
	}
	if strings.Contains(out, "warning:") || strings.Contains(out, "missing:") {
		t.Errorf("the disclosures leaked onto stdout: %q", out)
	}
	// The count lines and the axis lines are the results and stay on stdout.
	for _, want := range []string{"probe surface: ", "quotas: --per-axis 12 ",
		"  enforcement-timing (L-03, assertion-strength): sites 77, rows 10, " +
			"emitted 3, tail 7 — under-filled"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q: %q", want, out)
		}
	}

	// `probes list` reads the same over-tight surface: same split.
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "list")
	if code != 0 {
		t.Fatalf("list exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, probesOverrunWarning) {
		t.Errorf("list stderr missing the warning line: %q", errS)
	}
	if strings.Contains(out, "warning:") || strings.Contains(out, "missing:") {
		t.Errorf("list leaked the disclosures onto stdout: %q", out)
	}
	if !strings.Contains(out, "probe surface: 3 rows (0 dispositioned, 3 open)") {
		t.Errorf("list stdout lost its summary line: %q", out)
	}
}

// probesCleanRunStdout is the byte-exact stdout of a normal (no warning, no
// missing) `probes <c> run` on the t29 fixture: the recorded --per-axis 12 /
// --total 40 emit every ranked row, so neither disclosure fires. Pinned whole
// so the B5(b) stream move cannot have changed a single stdout byte on the
// silent path.
const probesCleanRunStdout = `probe surface: 10 rows emitted (10 ranked, 77 sites) — index_sha 4649be945ad0
quotas: --per-axis 12 --total 40 (recorded in probe_surface.json)
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
next: webv2 probes C-probecli01 run --emit  (turn the rows into plan obligations)
`

// TestProbesSilentRunStdoutIsByteIdentical pins the silent path: with no
// warning and no missing entry, stdout is exactly the pinned block and stderr
// is empty — the disclosures are the ONLY bytes that moved streams.
func TestProbesSilentRunStdoutIsByteIdentical(t *testing.T) {
	ws, _, _, _ := t29Setup(t, t29Ranking, false)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if out != probesCleanRunStdout {
		t.Errorf("silent-run stdout changed:\ngot  %q\nwant %q", out,
			probesCleanRunStdout)
	}
	if errS != "" {
		t.Errorf("a silent run must write nothing to stderr: %q", errS)
	}
}
