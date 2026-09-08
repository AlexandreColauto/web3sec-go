package cli

// P0 CLI tests (Task 14). Port of the P0-reachable CLI surface:
// tests/test_cli.py::test_init_status_log_verify_audit,
// test_snap_pins_a_source_snapshot, test_unknown_campaign_is_a_clean_error,
// test_snap_toolchain.py::test_cli_snap_prints_toolchain_line, and
// tests/test_root_default.py (adapted: `brief` is P1+, so `status` stands
// in — the --root defaulting/hint behavior under test lives in main's
// error handler, which is command-independent).
//
// Where the plan and cli.py disagree, cli.py wins (see cli.go header).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/state"
)

var initIDRe = regexp.MustCompile(`initialized (C-[0-9a-z]+) at `)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, err strings.Builder
	code := Run(args, &out, &err)
	return code, out.String(), err.String()
}

func mkroot(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// initOne runs init and returns the new campaign id.
func initOne(t *testing.T, root string) string {
	t.Helper()
	code, out, errS := run(t, "--root", root, "init", "--program", "CLI Test")
	if code != 0 {
		t.Fatalf("init exit %d: out=%q err=%q", code, out, errS)
	}
	m := initIDRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("init output missing id: %q", out)
	}
	if !strings.Contains(out, "next: webv2 snap") {
		t.Fatalf("init missing next-step line: %q", out)
	}
	return m[1]
}

func TestInitStatus(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "status", cid)
	if code != 0 {
		t.Fatalf("status exit %d: %q", code, errS)
	}
	var st map[string]any
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("status not JSON: %v\n%s", err, out)
	}
	if st["campaign_id"] != cid {
		t.Fatalf("campaign_id = %v, want %s", st["campaign_id"], cid)
	}
	if st["phase"] != "SCOPE" {
		t.Fatalf("phase = %v, want SCOPE", st["phase"])
	}
	// Key order is contractual (Python dict order).
	wantKeys := []string{"campaign_id", "program", "phase", "pass",
		"active_snapshot", "findings", "coverage_summary", "stages"}
	got := keyOrder(t, out)
	for i, k := range wantKeys {
		if i >= len(got) || got[i] != k {
			t.Fatalf("status key order = %v, want %v", got, wantKeys)
		}
	}
}

func keyOrder(t *testing.T, doc string) []string {
	t.Helper()
	var m []string
	dec := json.NewDecoder(strings.NewReader(doc))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %v", err)
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		m = append(m, k.(string))
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("val: %v", err)
		}
	}
	return m
}

func TestLogTail(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"phase.transition", "artifact.registered", "budget.limit_set"} {
		if _, err := c.Log(typ, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errS := run(t, "--root", root, "log", cid, "--tail", "2")
	if code != 0 {
		t.Fatalf("log exit %d: %q", code, errS)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("tail 2 gave %d lines: %q", len(lines), out)
	}
	if !strings.Contains(lines[0], "artifact.registered") ||
		!strings.Contains(lines[1], "budget.limit_set") {
		t.Fatalf("wrong tail: %q", out)
	}
	lineRe := regexp.MustCompile(`(?m)^\s*\d+ \S+  \S+`)
	if !lineRe.MatchString(out) {
		t.Fatalf("bad log line format: %q", out)
	}
	// campaign.created is in the full log.
	code, out, _ = run(t, "--root", root, "log", cid)
	if code != 0 || !strings.Contains(out, "campaign.created") {
		t.Fatalf("full log missing campaign.created: %q", out)
	}
}

func TestAuditClean(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "audit", cid)
	if code != 0 {
		t.Fatalf("audit exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.HasPrefix(out, "audit PASS") {
		t.Fatalf("missing summary line: %q", out)
	}
	code, out, _ = run(t, "--root", root, "audit", cid, "--json")
	if code != 0 {
		t.Fatalf("audit --json exit %d", code)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("audit --json not JSON: %v", err)
	}
	secs := rep["sections"].(map[string]any)
	if len(secs) != 6 {
		t.Fatalf("sections = %d, want 6", len(secs))
	}
	if rep["ok"] != true {
		t.Fatalf("ok = %v", rep["ok"])
	}
}

func TestDuplicateInitErrorMapping(t *testing.T) {
	// The CLI mints a random id per init, so a same-id collision is
	// unreachable through the CLI surface (same as Python: init takes no
	// id). What IS contractual is the mapping: a FileExistsError becomes
	// exit 1 with the exact message on stderr.
	root := mkroot(t)
	if _, err := state.Init(root, "Acme Program", state.InitOpts{CampaignID: "C-duptest01"}); err != nil {
		t.Fatal(err)
	}
	_, dupErr := state.Init(root, "Acme Program", state.InitOpts{CampaignID: "C-duptest01"})
	if dupErr == nil || !strings.Contains(dupErr.Error(), "campaign already exists: ") {
		t.Fatalf("dup err = %v", dupErr)
	}
	var eb strings.Builder
	code := mapRunError(root, dupErr, &eb)
	if code != 1 || !strings.Contains(eb.String(), "error: campaign already exists: ") {
		t.Fatalf("duplicate mapping = %d %q", code, eb.String())
	}
}

func TestBadCampaignID(t *testing.T) {
	root := mkroot(t)
	code, _, errS := run(t, "--root", root, "status", "INVALID ID")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errS, "malformed campaign id: 'INVALID ID'") {
		t.Fatalf("err = %q", errS)
	}
}

func TestUnknownCampaignCleanError(t *testing.T) {
	root := mkroot(t)
	code, _, errS := run(t, "--root", root, "status", "C-0000000000")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errS, "no such campaign") {
		t.Fatalf("err = %q", errS)
	}
}

func TestVerifyCleanAndTampered(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "verify", cid)
	if code != 0 {
		t.Fatalf("verify exit %d: %q", code, errS)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("verify not JSON: %v", err)
	}
	if res["ok"] != true || res["chained"].(float64) < 1 {
		t.Fatalf("res = %v", res)
	}
	got := keyOrder(t, out)
	want := []string{"events", "ok", "problems", "chained", "legacy_unchained", "malformed_lines"}
	for i, k := range want {
		if got[i] != k {
			t.Fatalf("verify key order = %v, want %v", got, want)
		}
	}
	// Tamper: append a non-JSON line.
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(c.EventsPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fh.WriteString("not json\n")
	_ = fh.Close()
	code, out, _ = run(t, "--root", root, "verify", cid)
	if code != 1 {
		t.Fatalf("tampered exit = %d, want 1", code)
	}
	if !strings.Contains(out, "not valid JSON") {
		t.Fatalf("tampered output missing problem: %q", out)
	}
}

func writeFoundryTarget(t *testing.T, dir string) string {
	t.Helper()
	tgt := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(tgt, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tgt, "foundry.toml"),
		[]byte("[profile.default]\nsol = \"0.8.24\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tgt, "src", "Vault.sol"),
		[]byte("contract Vault { uint public total; }"), 0o644); err != nil {
		t.Fatal(err)
	}
	return tgt
}

func TestSnapFoundryToolchainLine(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := writeFoundryTarget(t, root)
	code, out, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("snap exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "toolchain: foundry — solc 0.8.24") {
		t.Fatalf("missing toolchain line: %q", out)
	}
	if !strings.Contains(out, "pinned src-content-") {
		t.Fatalf("missing pinned line: %q", out)
	}
	// Re-pin is a noop: same id.
	_, out2, _ := run(t, "--root", root, "snap", cid, tgt)
	first := strings.SplitN(out, "\n", 2)[0]
	second := strings.SplitN(out2, "\n", 2)[0]
	if first != second {
		t.Fatalf("re-pin changed id:\n%s\n%s", first, second)
	}
}

func TestSnapExcludedReported(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := writeFoundryTarget(t, root)
	if err := os.MkdirAll(filepath.Join(tgt, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tgt, "data", "big.csv"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "EXCLUDED from the pin") || !strings.Contains(out, "data") {
		t.Fatalf("missing exclusion report: %q", out)
	}
}

// Port of test_cli_snap_exclude_flag: --exclude GLOB drops that top-level
// name from the pin and the report names it.
func TestSnapExcludeFlag(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := writeFoundryTarget(t, root)
	if err := os.MkdirAll(filepath.Join(tgt, "generated"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tgt, "generated", "x.bin"), []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "snap", cid, tgt, "--exclude", "generated")
	if code != 0 {
		t.Fatalf("snap --exclude exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "generated") {
		t.Fatalf("exclusion report must name the excluded dir: %q", out)
	}
}

func TestRootDefaultAndHint(t *testing.T) {
	// (a) --root defaults to cwd when run from the workspace.
	root := mkroot(t)
	cid := initOne(t, root)
	cwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "status", cid)
	if code != 0 {
		t.Fatalf("cwd-default status exit %d: %q", code, errS)
	}
	if !strings.Contains(out, cid) {
		t.Fatalf("status missing id: %q", out)
	}
	if strings.Contains(errS, "--root") {
		t.Fatalf("unexpected hint: %q", errS)
	}
	// (b) wrong directory (no campaigns/) gets the self-correcting hint.
	empty := mkroot(t)
	if err := os.Chdir(empty); err != nil {
		t.Fatal(err)
	}
	code, _, errS = run(t, "status", "C-doesnotexist")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	for _, s := range []string{"no such campaign", "no campaigns/ under .",
		"pass --root WORKSPACE", "Run from the workspace"} {
		if !strings.Contains(errS, s) {
			t.Fatalf("hint missing %q: %q", s, errS)
		}
	}
	// (c) right directory, wrong id: no hint.
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	code, _, errS = run(t, "status", "C-doesnotexist")
	if code != 1 || !strings.Contains(errS, "no such campaign") {
		t.Fatalf("code=%d err=%q", code, errS)
	}
	if strings.Contains(errS, "no campaigns/ under") {
		t.Fatalf("hint must not fire: %q", errS)
	}
}

func TestExplicitRootWins(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, _ := run(t, "--root", root, "status", cid)
	if code != 0 || !strings.Contains(out, cid) {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestHelpListsSix(t *testing.T) {
	code, out, _ := run(t, "help")
	if code != 0 {
		t.Fatalf("help exit = %d", code)
	}
	for _, s := range []string{"init", "status", "snap", "log", "audit", "verify"} {
		if !strings.Contains(out, s) {
			t.Fatalf("help missing %q:\n%s", s, out)
		}
	}
	code, _, errS := run(t)
	if code != 2 {
		t.Fatalf("no-arg exit = %d, want 2", code)
	}
	for _, s := range []string{"init", "status", "snap", "log", "audit", "verify"} {
		if !strings.Contains(errS, s) {
			t.Fatalf("usage missing %q:\n%s", s, errS)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, errS := run(t, "frobnicate")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errS, "unknown command") {
		t.Fatalf("err = %q", errS)
	}
}

func TestInitRequiresProgram(t *testing.T) {
	code, _, _ := run(t, "init")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}
