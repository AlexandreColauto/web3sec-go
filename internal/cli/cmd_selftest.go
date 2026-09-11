package cli

// cmd_selftest: `webv2 selftest [--full]` — the port of the Python twin's
// `verify.py` (web3sec-final/verify.py), spec 1.5 DoD item 1: "verify-
// equivalent: fast self-check (import/build sweep + deterministic
// walkthrough + CLI init→snap→audit scratch campaign) passes; `--full` adds
// the ported suite (~1,380 tests, all green)".
//
// OUTPUT CONTRACT — byte-for-byte shape, Go specifics where the spec allows
// (the mapping is asserted in cmd_selftest_test.go):
//
//	Python verify.py                       this command
//	-----------------------------------    -----------------------------------
//	web3sec-final self-check (fast …)      web3sec-go self-check (fast …)
//	[PASS] import-sweep  all modules …     [PASS] build-sweep  … (go build +
//	                                       embedded assets + command registry)
//	[PASS] walkthrough  done. campaign …   [PASS] walkthrough  done. campaign …
//	[PASS] cli-audit    audit PASS: …      [PASS] cli-audit    audit PASS: …
//	(--full) [PASS] pytest  <tail>         (--full) [PASS] go-test  <tail>
//	                                       (--full) [PASS] evalsuite-selfcheck
//	                                       <tail> (gold suite self-scores
//	                                       17/17, FP 0 — scorer proof, not a
//	                                       detector claim)
//	ALL PASS / N check(s) FAILED           identical
//	exit 0 pass / 1 fail                   identical
//
// The three check NAMES differ where the Go mechanism differs (Python's
// import sweep has no in-binary analogue — the Go compiler already proved
// every package links; the replacement sweeps the embedded assets and the
// command registry, plus `go build ./...` when a module tree is present).
// Detail lines are compared by SHAPE, not bytes, because they carry
// twin-specific text (module list, campaign path, package count).
//
// `--full` mirrors the Python contract: it runs the ported suite and exits
// 0/1 on the suite's verdict. Built from a module tree it runs
// `go test ./... -count=1` there; a RELEASED binary (no go.mod above the
// cwd) reports where the suite lives instead of failing — the Python twin
// has the same split (verify.py is a source-tree script; a wheel install
// has no tests/ to run).

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"websec/assets"
	"websec/internal/adapter"
	"websec/internal/archetypes"
	"websec/internal/audit"
	"websec/internal/evalscore"
	"websec/internal/orchestrator"
	"websec/internal/playbooks"
	"websec/internal/state"
	"websec/internal/validation"
	"websec/internal/wilson"
)

// selftestCheck is one named PASS/FAIL line.
type selftestCheck struct {
	name string
	run  func() (bool, string)
}

// selftestPlan builds the check list. A package var so
// cmd_selftest_test.go can inject a failing check and prove the exit-1
// path without breaking the real checks (Python's verify.py has no seam;
// this is the test seam, and it is never touched by production code).
var selftestPlan = func(full bool) []selftestCheck {
	checks := []selftestCheck{
		{"build-sweep", checkBuildSweep},
		{"walkthrough", checkWalkthrough},
		{"cli-audit", checkCLIAudit},
	}
	if full {
		checks = append(checks, selftestCheck{"go-test", checkGoTest})
		checks = append(checks, selftestCheck{"evalsuite-selfcheck", checkEvalsuiteSelfcheck})
	}
	return checks
}

// selftestRule is Python's `"=" * 60`.
const selftestRule = "============================================================"

// runSelftest is the command body: one PASS/FAIL line per check, exit 0
// only when every check passes (verify.py main()).
func runSelftest(_ string, args []string, r *Runner) int {
	if helpRequested(r.Out, "selftest", args) {
		return 0
	}

	ensureSeams()
	audit.Setup() // the walkthrough's audit check needs the section registry
	full := false
	for _, a := range args {
		if a == "--full" {
			full = true
			continue
		}
		if a == "-h" || a == "--help" {
			continue // handled above
		}
		// Python ignored every other argv token because it only tested
		// membership. That reason is gone: a typo like --ful used to run the
		// fast plan and report PASS, which reads as "the full suite is green".
		if strings.HasPrefix(a, "-") {
			fmt.Fprint(r.Err, "usage: webv2 selftest [--full]\n")
			fmt.Fprintf(r.Err,
				"webv2 selftest: error: unrecognized arguments: %s\n", a)
			return 2
		}
	}
	mode := "fast — pass --full for the go test suite"
	if full {
		mode = "full"
	}
	fmt.Fprintf(r.Out, "web3sec-go self-check (%s)\n", mode)
	fmt.Fprintln(r.Out, selftestRule)
	failures := 0
	for _, chk := range selftestPlan(full) {
		ok, detail := runSelftestCheck(chk)
		status := "PASS"
		if !ok {
			status = "FAIL"
			failures++
		}
		fmt.Fprintf(r.Out, "[%s] %-12s %s\n", status, chk.name, clipRunes(detail, 120))
	}
	fmt.Fprintln(r.Out, selftestRule)
	if failures == 0 {
		fmt.Fprintln(r.Out, "ALL PASS")
		return 0
	}
	fmt.Fprintf(r.Out, "%d check(s) FAILED\n", failures)
	return 1
}

// runSelftestCheck runs one check, converting a panic into FAIL ("exception:
// …"), exactly like verify.py's try/except around every check.
func runSelftestCheck(chk selftestCheck) (ok bool, detail string) {
	defer func() {
		if e := recover(); e != nil {
			ok, detail = false, fmt.Sprintf("exception: %v", e)
		}
	}()
	if chk.run == nil {
		return false, "no runner"
	}
	return chk.run()
}

// clipRunes is Python's `detail[:120]` (runes, not bytes).
func clipRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// --- check 1: build sweep ------------------------------------------------

// checkBuildSweep is the import-sweep analogue. It proves the shipped
// install is intact from the binary alone: every embedded schema compiles,
// every stage prompt loads, the playbook/archetype packs parse, and every
// registered command has a runner. When the cwd sits inside a Go module it
// additionally runs `go build ./...` — the source tree builds.
func checkBuildSweep() (bool, string) {
	nSchemas, err := sweepSchemas()
	if err != nil {
		return false, err.Error()
	}
	nPrompts, err := sweepPrompts()
	if err != nil {
		return false, err.Error()
	}
	books, err := playbooks.AvailablePlaybooks()
	if err != nil {
		return false, "playbooks: " + err.Error()
	}
	arches, err := archetypes.AvailableArchetypes()
	if err != nil {
		return false, "archetypes: " + err.Error()
	}
	if err := sweepCommands(); err != nil {
		return false, err.Error()
	}
	assetsDetail := fmt.Sprintf("%d schemas, %d stage prompts, %d playbooks, "+
		"%d archetypes, %d commands", nSchemas, nPrompts, len(books),
		len(arches), len(registered))
	mod := findGoModuleRoot()
	if mod == "" {
		return true, "embedded assets ok: " + assetsDetail
	}
	bin, err := exec.LookPath("go")
	if err != nil {
		return true, "embedded assets ok (go not on PATH): " + assetsDetail
	}
	cmd := exec.Command(bin, "build", "./...")
	cmd.Dir = mod
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, "go build ./...: " + lastLine(string(out), err)
	}
	return true, "go build ./... ok + " + assetsDetail
}

// sweepSchemas compiles every embedded schema. A *validation.SchemaError
// means "compiled, input rejected" (expected for a null instance); any
// other error is a broken schema.
func sweepSchemas() (int, error) {
	entries, err := assets.FS.ReadDir("schema")
	if err != nil {
		return 0, fmt.Errorf("schema dir: %w", err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".schema.json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".schema.json")
		verr := validation.Validate(validation.VNull(), name, 1)
		var se *validation.SchemaError
		if verr != nil && !errors.As(verr, &se) {
			return n, fmt.Errorf("schema %s: %w", name, verr)
		}
		n++
	}
	if n == 0 {
		return 0, errors.New("no embedded schemas")
	}
	return n, nil
}

// sweepPrompts loads every stage prompt through the adapter (the same path
// the CLI uses to print `prompt_path`), counting the resolved pack.
func sweepPrompts() (int, error) {
	n := 0
	for _, stage := range adapter.StageIDs() {
		_, prompt, err := adapter.StageConfig(stage)
		if err != nil {
			return n, fmt.Errorf("stage %s: %w", stage, err)
		}
		if prompt != "" {
			n++
		}
	}
	if n == 0 {
		return 0, errors.New("no stage prompts")
	}
	return n, nil
}

// sweepCommands checks the registry is complete: every command has a name,
// a usage line and a runner.
func sweepCommands() error {
	for _, c := range registered {
		if c.name == "" || c.line == "" || c.run == nil {
			return fmt.Errorf("incomplete command registration: %q", c.name)
		}
	}
	if len(registered) == 0 {
		return errors.New("no commands registered")
	}
	return nil
}

// findGoModuleRoot walks up from the cwd looking for this module's go.mod
// ("module websec"). Returns "" when the binary runs outside its source
// tree (a released binary).
func findGoModuleRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil {
			first := strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
			if first == "module websec" {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// lastLine renders a subprocess failure as "exit N: <last output line>".
func lastLine(out string, err error) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	tail := ""
	if len(lines) > 0 {
		tail = strings.TrimSpace(lines[len(lines)-1])
	}
	if tail == "" {
		return err.Error()
	}
	return err.Error() + ": " + tail
}

// --- check 2: the deterministic walkthrough ------------------------------

// selftestFinding is a schema-valid hypothesis (the golden fixture shape
// scripts/golden/h1-withdraw-double-count.json), embedded so the check
// needs no repo access.
const selftestFinding = `{
  "title": "Withdraw path double-counts the caller's shares",
  "root_cause": {
    "class": "logic-error",
    "cwe": "CWE-682",
    "description": "withdraw() credits the caller's shares to the payout before burning them",
    "mechanism": "withdraw() adds the share balance to the payout then subtracts it"
  },
  "affected": [
    {"path": "src/MiniVault.sol", "contract": "MiniVault", "function": "withdraw",
     "lines": [1, 2], "entry_point": true}
  ],
  "attacker": {"profile": "arbitrary EOA", "capabilities": ["withdraw"]},
  "preconditions": [
    {"kind": "state", "description": "the attacker holds any positive share balance",
     "satisfied_by": "deposit one wei"}
  ],
  "dedup": {"economic_signature": "1111111111111111"}
}`

// selftestSolidity is the Python walkthrough's MiniVault spine (a
// withdraw that pays before it burns), trimmed to what the walkthrough
// needs.
const selftestSolidity = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MiniVault {
    uint256 public totalDeposited;
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        totalDeposited += msg.value;
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        deposits[msg.sender] -= amount;
        totalDeposited -= amount;
    }
}
`

// checkWalkthrough builds a real campaign through the packages (the
// deterministic end-to-end example, verify.py's check 2) with the clock and
// id stream pinned through WEBV2_NOW / WEBV2_UUID: init -> pin -> index ->
// ingest -> dedup -> audit, and the audit must be clean. The campaign is
// KEPT on disk (Python's walkthrough keeps its temp dir too) and the detail
// line mirrors Python's "done. campaign kept at <dir>".
func checkWalkthrough() (bool, string) {
	restore := pinSelftestClock()
	defer restore()
	state.ResetIDStream()

	root, err := os.MkdirTemp("", "webv2-walkthrough-")
	if err != nil {
		return false, "tempdir: " + err.Error()
	}
	c, err := state.Init(root, "selftest walkthrough", state.InitOpts{})
	if err != nil {
		return false, "init: " + err.Error()
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(filepath.Join(target, "src"), 0o755); err != nil {
		return false, "target: " + err.Error()
	}
	if err := os.WriteFile(filepath.Join(target, "src", "MiniVault.sol"),
		[]byte(selftestSolidity), 0o644); err != nil {
		return false, "target source: " + err.Error()
	}
	o := orchestrator.New(c)
	if _, err := o.Snapshot(target, orchestrator.SnapshotOpts{}); err != nil {
		return false, "snapshot: " + err.Error()
	}
	if _, err := o.BuildStructuralIndex(); err != nil {
		return false, "index: " + err.Error()
	}
	payload, err := validation.ParseOrdered([]byte(selftestFinding))
	if err != nil {
		return false, "payload: " + err.Error()
	}
	if _, err := o.Ingest(payload, orchestrator.IngestOpts{
		Trajectory: "code", Stage: "selftest"}); err != nil {
		return false, "ingest: " + err.Error()
	}
	if _, err := o.RunDedup(); err != nil {
		return false, "dedup: " + err.Error()
	}
	report, err := audit.AuditCampaign(c)
	if err != nil {
		return false, "audit: " + err.Error()
	}
	if !objBool(report, "ok") {
		return false, "audit not ok: " + audit.AuditSummaryLine(report)
	}
	return true, fmt.Sprintf("done. campaign kept at %s",
		filepath.Join(root, "campaigns", c.CampaignID))
}

// pinSelftestClock sets WEBV2_NOW / WEBV2_UUID when the caller has not,
// so the walkthrough is reproducible; it returns the restore func.
func pinSelftestClock() func() {
	const (
		now  = "2026-09-09T12:00:00.000000+00:00"
		seed = "webv2-selftest"
	)
	restores := []func(){}
	for _, kv := range []struct{ key, val string }{
		{"WEBV2_NOW", now}, {"WEBV2_UUID", seed},
	} {
		if os.Getenv(kv.key) != "" {
			continue
		}
		if err := os.Setenv(kv.key, kv.val); err != nil {
			continue
		}
		key := kv.key
		restores = append(restores, func() { _ = os.Unsetenv(key) })
	}
	return func() {
		for _, f := range restores {
			f()
		}
	}
}

// --- check 3: CLI init -> snap -> audit ----------------------------------

// selftestCIDRe is verify.py's `initialized (C-[0-9a-z]+)`.
var selftestCIDRe = regexp.MustCompile(`initialized (C-[0-9a-z]+)`)

// checkCLIAudit is verify.py's check 3: a scratch campaign through
// init -> snap -> audit, proving the hash chain + integrity audit work from
// disk. Python shells out to `python3 -m webv2.cli`; the Go twin calls
// cli.Run in-process — the SAME entry point main() uses — so the check
// works from a released binary and from a test binary alike.
func checkCLIAudit() (bool, string) {
	ws, err := os.MkdirTemp("", "webv2-selftest-")
	if err != nil {
		return false, "tempdir: " + err.Error()
	}
	defer os.RemoveAll(ws)
	target := filepath.Join(ws, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		return false, "target: " + err.Error()
	}
	if err := os.WriteFile(filepath.Join(target, "T.sol"),
		[]byte("contract T { function f() public pure returns (uint) { return 1; } }"),
		0o644); err != nil {
		return false, "target source: " + err.Error()
	}
	code, out := selftestCLI("--root", ws, "init", "--program", "selftest scratch")
	if code != 0 {
		return false, "init failed: " + strings.TrimSpace(out)
	}
	m := selftestCIDRe.FindStringSubmatch(out)
	if m == nil {
		return false, "init id not found: " + strings.TrimSpace(out)
	}
	cid := m[1]
	if code, out = selftestCLI("--root", ws, "snap", cid, target); code != 0 {
		return false, "snap failed: " + strings.TrimSpace(out)
	}
	code, out = selftestCLI("--root", ws, "audit", cid)
	if code != 0 || !strings.Contains(out, "audit PASS") {
		return false, "audit failed: " + strings.TrimSpace(out)
	}
	first := ""
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) > 0 {
		first = lines[0]
	}
	return true, first
}

// selftestCLI runs one CLI invocation in-process and returns (exit, output).
func selftestCLI(argv ...string) (int, string) {
	var buf bytes.Buffer
	code := Run(argv, &buf, &buf)
	return code, buf.String()
}

// --- --full: the ported suite --------------------------------------------

// checkGoTest is verify.py's --full: run the ported suite and pass iff it
// is green. From a module tree that is `go test ./... -count=1`; from a
// released binary there is no source tree to test, so the check reports
// where the suite lives (the Python twin behaves the same way: verify.py
// --full needs the source tree).
func checkGoTest() (bool, string) {
	mod := findGoModuleRoot()
	if mod == "" {
		return true, "suite not in this binary (released binary) — run " +
			"`go test ./... -count=1` in the source tree"
	}
	bin, err := exec.LookPath("go")
	if err != nil {
		return false, "go not on PATH"
	}
	cmd := exec.Command(bin, "test", "./...", "-count=1")
	cmd.Dir = mod
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err = cmd.Run()
	tail := "(no output)"
	if lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n"); len(lines) > 0 {
		tail = strings.TrimSpace(lines[len(lines)-1])
	}
	if err != nil {
		return false, tail
	}
	return true, tail
}

// --- --full: eval-suite self-score --------------------------------------

// evalNotExploitable is the gold outcome that inverts the hit rule (a
// clean control scores iff it carries zero live findings).
const evalNotExploitable = "confirmed-not-exploitable"

// checkEvalsuiteSelfcheck is the --full scorer proof: it builds live
// findings synthetically from each gold case (one finding per
// confirmed-exploitable case, class + gold location basename; empty
// slices for the ES16/ES17 controls) and scores the whole suite with
// evalscore.ScoreSuite, failing unless recall is total and FP is zero.
// No docker, no detector: a scorer that scores the suite against itself
// proves the data, not the detector.
func checkEvalsuiteSelfcheck() (bool, string) {
	restore := pinSelftestClock()
	defer restore()
	cases, err := assets.LoadEvalCases()
	if err != nil {
		return false, "evalsuite: " + err.Error()
	}
	var programs []string
	seen := map[string]bool{}
	live := map[string][]validation.Value{}
	for _, cs := range cases {
		prog := objStr(objAt(cs, "program"), "program")
		gold := objAt(cs, "gold")
		if !seen[prog] {
			seen[prog] = true
			programs = append(programs, prog)
		}
		if _, ok := live[prog]; !ok {
			live[prog] = []validation.Value{}
		}
		if objStr(gold, "outcome") == evalNotExploitable {
			continue
		}
		path := ""
		for _, l := range objAt(gold, "locations").A {
			if f := objStr(l, "file"); f != "" {
				if i := strings.LastIndex(f, "/"); i >= 0 {
					f = f[i+1:]
				}
				path = f
				break
			}
		}
		live[prog] = append(live[prog], validation.VObj(
			validation.KV{K: "root_cause", V: validation.VObj(
				validation.KV{K: "class", V: validation.VStr(objStr(gold, "bug_class"))})},
			validation.KV{K: "affected", V: validation.VArr(validation.VObj(
				validation.KV{K: "path", V: validation.VStr(path)}))},
		))
	}
	r := evalscore.ScoreSuite(programs, live, cases)
	if r.Hits != r.GoldTotal || r.FP != 0 {
		return false, fmt.Sprintf("self-score %d/%d hits, %d FP (want %d/%d, 0 FP)",
			r.Hits, r.GoldTotal, r.FP, r.GoldTotal, r.GoldTotal)
	}
	lo, hi := wilson.Interval(r.Hits, r.GoldTotal)
	return true, fmt.Sprintf("ok: gold suite self-scores %d/%d "+
		"(95%% CI %.1f–%.1f%%) — scorer semantics proven, NOT a detector claim",
		r.Hits, r.GoldTotal,
		math.Round(lo*1000)/10, math.Round(hi*1000)/10)
}

func runSelftestCmd(root string, args []string, r *Runner) int {
	return runSelftest(root, args, r)
}

func init() {
	register(command{ord: 67, name: "selftest",
		line: "selftest [--full]                    one-command self-check " +
			"(verify.py port)",
		run: runSelftestCmd})
}
