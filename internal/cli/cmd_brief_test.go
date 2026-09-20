package cli

// cmd_brief_test: the `brief` operator-cockpit rendering (cli.py cmd_brief).
// Regression (T32, P3): the prescreen summary line joins the matched
// archetype ids with ", " and renders the literal "none" for an EMPTY
// list — Python is `', '.join(ps['matched']) or 'none'`. The Go twin used
// to print a bare "prescreen: matched " (empty tail) when no archetype
// matched, which diverged from the reference on every clean tree.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
)

// briefEmptyTree is a contract no archetype prescreen matches: the
// regression needs the EMPTY branch, so this deliberately avoids the
// `unguarded-initialize` shape cmd_prescreen_test.go's fixture uses.
const briefEmptyTree = "contract Empty { uint256 public x; }\n"

func TestBriefPrescreenEmptyMatchRendersNone(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "Empty.sol"),
		[]byte(briefEmptyTree), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatal(err)
	}
	// The prescreen artifact is what brief reads (archetype_prescreen.json).
	code, out, errS := run(t, "--root", root, "prescreen", cid, "--src", src)
	if code != 0 {
		t.Fatalf("prescreen exit = %d: out=%q err=%q", code, out, errS)
	}
	if strings.Contains(out, "[MATCH]") {
		t.Fatalf("fixture must match no archetype: %q", out)
	}
	code, out, errS = run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit = %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "  prescreen: matched none\n") {
		t.Fatalf("brief must render an empty match list as \"none\":\n%s", out)
	}
	if strings.Contains(out, "prescreen: matched \n") {
		t.Fatalf("brief rendered an empty tail:\n%s", out)
	}
}

// TestBriefToolFlagsRenderGated is the G1 text surface: TOOL FLAGS (SAST
// hypotheses) appears only when a finding carries detector provenance, and
// then reports the census and the corroborated count.
func TestBriefToolFlagsRenderGated(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit = %d: out=%q err=%q", code, out, errS)
	}
	if strings.Contains(out, "TOOL FLAGS") {
		t.Fatalf("clean campaign must not render tool flags:\n%s", out)
	}
	row := `{"finding_id":"F-tool",` +
		`"provenance":{"sast_tools":["slither:tx-origin"]},` +
		`"verification":{"critic_verdict":"confirmed"}}`
	if err := os.WriteFile(filepath.Join(c.FindingsDir, "F-tool.json"),
		[]byte(row), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS = run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit = %d: out=%q err=%q", code, out, errS)
	}
	for _, want := range []string{
		"TOOL FLAGS (SAST hypotheses)\n",
		"  flags: 1, corroborated: 0\n",
		"  by verdict: confirmed 1\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("brief missing %q:\n%s", want, out)
		}
	}
}

// briefMemoryRows asserts which memory-decision rows a brief view printed:
// every id in want carries a `memory decision:` line, every id in absent
// does not.
func briefMemoryRows(t *testing.T, out string, want, absent []string) {
	t.Helper()
	for _, id := range want {
		if !strings.Contains(out, "memory decision: "+id) {
			t.Errorf("brief must keep %s:\n%s", id, out)
		}
	}
	for _, id := range absent {
		if strings.Contains(out, "memory decision: "+id) {
			t.Errorf("brief must hide %s:\n%s", id, out)
		}
	}
}

// TestBriefLiveOnlyHidesClutterRows is the §7.5 cockpit filter: a pending
// memory row whose finding status is DUPLICATE is ingest bookkeeping, not a
// decision the operator triages, so --live-only drops it and says how many
// rows went away. OUT_OF_SCOPE deliberately stays visible (scope is a
// judgment the operator re-checks), and the default view is byte-unchanged —
// no footer without the flag.
func TestBriefLiveOnlyHidesClutterRows(t *testing.T) {
	root, cid, c := noopCamp(t)
	live := queueMemoryRow(t, c, "a live disproved pattern")
	dup := queueMemoryStatusRow(t, c, "DUPLICATE", "twin of an ingested finding")
	scope := queueMemoryStatusRow(t, c, "OUT_OF_SCOPE", "outside program scope")

	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit %d: %s%s", code, out, errS)
	}
	briefMemoryRows(t, out, []string{live, dup, scope}, nil)
	if strings.Contains(out, "live-only:") {
		t.Errorf("default brief must not print the filter footer:\n%s", out)
	}

	code, out, errS = run(t, "--root", root, "brief", cid, "--live-only")
	if code != 0 {
		t.Fatalf("brief --live-only exit %d: %s%s", code, out, errS)
	}
	briefMemoryRows(t, out, []string{live, scope}, []string{dup})
	if !strings.Contains(out, "live-only: 1 rows hidden\n") {
		t.Errorf("--live-only must report the hidden row count:\n%s", out)
	}
}
