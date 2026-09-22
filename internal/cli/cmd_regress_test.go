package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegressOneTargetEndToEnd is this plan's end-to-end branch test: it
// drives the real verbs in sequence — add a target, pin it, record a run,
// read it all back through `audit` — and asserts the joined-up result. It is
// the test that would have caught the P1 "feed validated the declaration and
// never recorded it" defect, which no scoped task review could see.
func TestRegressOneTargetEndToEnd(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	tid := regressAddTarget(t, root, cid)
	// Half-pinned state must be RED, and the red must name the reason: the
	// exit criterion is "every snapshot carries a resolved SHA", so a target
	// that has not been pinned is a suite problem, not a blank.
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if code == 0 {
		t.Fatalf("audit PASSed with an unpinned target: %q", out)
	}
	if !strings.Contains(out+errS, "resolved_sha") {
		t.Fatalf("the unpinned-target problem does not name resolved_sha: %q", out+errS)
	}
	sha, _ := regressSnapAndPin(t, root, cid, tid)
	regressRecordRun(t, root, cid, tid)
	regressAuditIsGreen(t, root, cid, sha)
	regressStatusCarriesTheLabel(t, root, cid)
}

// regressAddTarget runs `regress target add` and returns the printed id.
func regressAddTarget(t *testing.T, root, cid string) string {
	t.Helper()
	code, out, errS := run(t, "--root", root, "regress", cid, "target", "add",
		"--kind", "scabench", "--program", "Acme Vault",
		"--record-id", "acme-vault", "--repo", "acme/vault",
		"--shape", "vault-erc4626", "--commit-hint", "main")
	if code != 0 {
		t.Fatalf("target add exit %d: out=%q err=%q", code, out, errS)
	}
	tid := firstID(out, "T-")
	if tid == "" {
		t.Fatalf("target add printed no T- id: %q", out)
	}
	return tid
}

// regressSnapAndPin snapshots a real git tree and pins the target to that
// snapshot, returning the resolved SHA and the snapshot id.
func regressSnapAndPin(t *testing.T, root, cid, tid string) (string, string) {
	t.Helper()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"),
		[]byte("contract Vault {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitInitCommit(t, target)
	code, out, errS := run(t, "--root", root, "snap", cid, target)
	if code != 0 {
		t.Fatalf("snap exit %d: out=%q err=%q", code, out, errS)
	}
	snapID := firstID(out, "src-")
	if snapID == "" {
		t.Fatalf("snap printed no snapshot id: %q", out)
	}
	sha := gitRevParse(t, target)
	code, out, errS = run(t, "--root", root, "regress", cid, "target", "pin",
		tid, "--resolved-sha", sha, "--snapshot", snapID, "--actor", "operator")
	if code != 0 {
		t.Fatalf("target pin exit %d: out=%q err=%q", code, out, errS)
	}
	return sha, snapID
}

// regressRecordRun records one eval-gold run and checks the D8 label is in the
// operator's face.
func regressRecordRun(t *testing.T, root, cid, tid string) {
	t.Helper()
	score := filepath.Join(t.TempDir(), "score.json")
	if err := os.WriteFile(score, []byte(evalGoldCLIFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "regress", cid, "run",
		"--target", tid, "--scorer", "eval-gold", "--score-file", score)
	if code != 0 {
		t.Fatalf("run exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "rediscovery") {
		t.Fatalf("the run output does not carry the D8 label: %q", out)
	}
}

// regressAuditIsGreen is the joined-up assertion: after the pin and the run,
// the audit passes and its report carries the section, the SHA and the label.
func regressAuditIsGreen(t *testing.T, root, cid, sha string) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if code != 0 {
		t.Fatalf("audit exit %d after pin+run: out=%q err=%q", code, out, errS)
	}
	for _, want := range []string{"regression_suite", sha, "rediscovery"} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit --json does not carry %q: %q", want, out)
		}
	}
}

// regressStatusCarriesTheLabel checks the human view carries the same label.
func regressStatusCarriesTheLabel(t *testing.T, root, cid string) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "regress", cid, "status")
	if code != 0 {
		t.Fatalf("status exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "measurement: rediscovery") {
		t.Fatalf("status = %q, want the measurement label", out)
	}
}

// evalGoldCLIFixture is a REAL scorer output — the same capture
// internal/regression's run_test.go pins, verbatim from
// `python3 scripts/eval-gold.py --gold <one-gold file> --campaign <empty
// campaign>`: `found` and `missed` are arrays of gold ids (the plan's
// hand-written `"found": 3` is a vocabulary the scorer does not have), and the
// verdict is FAIL because a ScaBench target has no G-01/G-02 pass concept
// (the plan's own Step 21).
const evalGoldCLIFixture = `{
  "found": [],
  "missed": ["G-99"],
  "false_positives": 0,
  "pass": false,
  "bonus": false,
  "verdict": "FAIL",
  "verdict_note": "",
  "operator_confirmed": {}
}
`

func TestRegressRefusalsAreExit1AndArgparseErrorsAreExit2(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	// usage error (argparse contract)
	code, _, errS := run(t, "--root", root, "regress", cid, "target", "add",
		"--kind", "scabench", "--program", "Acme", "--shape", "vault-erc4626")
	if code != 2 || !strings.Contains(errS, "usage: webv2 regress") {
		t.Fatalf("code = %d err = %q, want 2 with the usage block", code, errS)
	}
	// refusal (a real answer of "no")
	code, _, errS = run(t, "--root", root, "regress", cid, "target", "pin",
		"T-000000000000", "--resolved-sha", strings.Repeat("a", 40),
		"--snapshot", "src-abc123def456")
	if code != 1 || !strings.Contains(errS, "no target") {
		t.Fatalf("code = %d err = %q, want 1 naming the missing target", code, errS)
	}
}

func campaignIDOf(t *testing.T, root string) string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(root, "campaigns"))
	if err != nil || len(ents) != 1 {
		t.Fatalf("campaigns dir: %v (%d entries)", err, len(ents))
	}
	return ents[0].Name()
}

// firstID returns the first "<prefix><hex-or-dash run>" token in s. The scan
// starts AFTER the prefix: the prefix's own characters are not part of the id.
func firstID(s, prefix string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	j := i + len(prefix)
	for j < len(s) && (s[j] == '-' || (s[j] >= '0' && s[j] <= '9') ||
		(s[j] >= 'a' && s[j] <= 'f')) {
		j++
	}
	return s[i:j]
}

func gitInitCommit(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
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
}

func gitRevParse(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
