package sections

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/regression"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func regressSectionCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// acmeTarget records the one scabench target the section tests read.
func acmeTarget(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	target, err := regression.AddTarget(c, regression.TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// TestRegressionSuiteIsPresenceGated is the test that protects the pinned
// section lists in scripts/verify-full.sh and scripts/check-golden.py: a
// campaign that is not a regression target must render NOTHING, so those two
// gates do not need editing when this section lands.
func TestRegressionSuiteIsPresenceGated(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectgate01")
	if _, err := RegressionSuite(c); !errors.Is(err, ErrSkip) {
		t.Fatalf("a campaign with no regression target must ErrSkip, got %v", err)
	}
}

func TestRegressionSuiteReportsAnUnpinnedTarget(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectread01")
	acmeTarget(t, c)
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	problems := validation.ObjAt(sec, "problems")
	if len(problems.A) != 1 {
		t.Fatalf("%d problem(s), want exactly the unpinned-target one", len(problems.A))
	}
	if !strings.Contains(problems.A[0].S, "resolved_sha") {
		t.Fatalf("problem = %q, want it to name resolved_sha", problems.A[0].S)
	}
	assertSectionBool(t, sec, "ok", false) // still unpinned
}

// TestRegressionSuiteCatchesARunWithNoTargetRecord is the drift the section
// exists to catch: a run whose target has no target record cannot be reached
// through the writer (RecordRun refuses an unknown target), so the record is
// written by hand here.
func TestRegressionSuiteCatchesARunWithNoTargetRecord(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectrun01")
	acmeTarget(t, c)
	writeOrphanRun(t, c)
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	problems := validation.ObjAt(sec, "problems")
	found := false
	for _, p := range problems.A {
		if strings.Contains(p.S, "T-000000000000") &&
			strings.Contains(p.S, "no target record") {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems = %v, want one naming the orphan run's target",
			problems.A)
	}
}

// assertSectionInt / assertSectionBool pin one leaf of a section document.
func assertSectionInt(t *testing.T, v validation.Value, key string, want int64) {
	t.Helper()
	if got := validation.ObjAt(v, key); got.Kind != validation.Int || got.I != want {
		t.Fatalf("%s = %v, want %d", key, got, want)
	}
}

func assertSectionBool(t *testing.T, v validation.Value, key string, want bool) {
	t.Helper()
	if got := validation.ObjAt(v, key); got.Kind != validation.Bool || got.B != want {
		t.Fatalf("%s = %v, want %v", key, got, want)
	}
}

func TestRegressionSuiteGoesGreenAfterThePin(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectgreen01")
	target := acmeTarget(t, c)
	if err := writeRunFor(t, c, target); err != nil {
		t.Fatal(err)
	}
	sha, sid := pinRealTree(t, c, target)
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(sec, "problems"); len(got.A) != 0 {
		t.Fatalf("problems = %v, want none after the pin", got.A)
	}
	assertSectionBool(t, sec, "ok", true)
	assertSectionInt(t, sec, "checked", 2) // one target + one run
	row := validation.ObjAt(sec, "targets").A[0]
	if got := validation.ObjStr(row, "resolved_sha"); got != sha {
		t.Fatalf("target row resolved_sha = %q, want %q", got, sha)
	}
	if got := validation.ObjStr(row, "snapshot_id"); got != sid {
		t.Fatalf("target row snapshot_id = %q, want %q", got, sid)
	}
	assertSectionInt(t, row, "runs", 1)
}

// gitTreeWithCommit writes a one-file tree, commits it, and returns the
// directory plus its HEAD commit.
func gitTreeWithCommit(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Vault.sol"),
		[]byte("contract Vault {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	for _, args := range [][]string{
		{"-c", "init.defaultBranch=main", "init", "-q"},
		{"add", "-A"}, {"commit", "-q", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	rev, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return dir, strings.TrimSpace(string(rev))
}

// pinRealTree snapshots a real git tree into the campaign and pins the target
// to it, through the real producers (snapshot.PinSourceSnapshot +
// regression.PinTarget) — never a hand-written record.
func pinRealTree(t *testing.T, c *state.Campaign, target validation.Value) (string, string) {
	t.Helper()
	dir, sha := gitTreeWithCommit(t)
	snap, err := snapshot.PinSourceSnapshot(c, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sid := validation.ObjStr(snap, "snapshot_id")
	if _, err := regression.PinTarget(c, regression.PinSpec{
		TargetID: validation.ObjStr(target, "target_id"), ResolvedSHA: sha,
		SnapshotID: sid, ResolvedBy: "operator",
	}); err != nil {
		t.Fatal(err)
	}
	return sha, sid
}

// writeRunFor records one run through the REAL writer (the realism law): the
// score file is the real scorer's own output shape — found/missed are arrays
// of gold ids.
func writeRunFor(t *testing.T, c *state.Campaign, target validation.Value) error {
	t.Helper()
	score := filepath.Join(t.TempDir(), "score.json")
	if err := os.WriteFile(score, []byte(`{"found": [], "missed": ["G-99"],
		"false_positives": 0, "pass": false, "bonus": false, "verdict": "FAIL",
		"verdict_note": "", "operator_confirmed": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := regression.RecordRun(c, regression.RunSpec{
		TargetID: validation.ObjStr(target, "target_id"),
		Scorer:   "eval-gold", ScoreFile: score,
	})
	return err
}

// writeOrphanRun writes a schema-valid run record naming a target that has no
// target record — the one state the writer cannot produce, so the section's
// drift check needs it by hand.
func writeOrphanRun(t *testing.T, c *state.Campaign) {
	t.Helper()
	if err := os.MkdirAll(regression.RunsDir(c), 0o755); err != nil {
		t.Fatal(err)
	}
	doc := validation.VObj(
		validation.KV{K: "run_id", V: validation.VStr("RUN-000000000001")},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "target_id", V: validation.VStr("T-000000000000")},
		validation.KV{K: "scorer", V: validation.VStr("eval-gold")},
		validation.KV{K: "score", V: validation.VObj(
			validation.KV{K: "found", V: validation.VInt(0)},
			validation.KV{K: "missed", V: validation.VInt(0)},
			validation.KV{K: "false_positives", V: validation.VInt(0)},
			validation.KV{K: "verdict", V: validation.VStr("FAIL")},
		)},
		validation.KV{K: "measurement", V: validation.VStr("rediscovery")},
		validation.KV{K: "is_detection_rate", V: validation.VBool(false)},
		validation.KV{K: "created_at", V: validation.VStr("2026-09-21T00:00:00Z")},
		validation.KV{K: "schema_version", V: validation.VInt(1)},
	)
	path := filepath.Join(regression.RunsDir(c), "RUN-000000000001.json")
	if err := validation.WriteJson(path, doc, "regression_run"); err != nil {
		t.Fatal(err)
	}
}
