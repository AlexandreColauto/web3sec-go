package cli

// Port of tests/test_sft_cli.py (Task C): the webv2 sft CLI exit-code
// contract, driven in-process — 0 pass, 1 lint failure, 2 usage/error — plus
// the backfill draft writer from test_sft_backfill.py.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/adapter"
	"websec/internal/boundary"
	"websec/internal/sft"
	"websec/internal/state"
	"websec/internal/validation"
)

func sftKv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func sftPrompt(t *testing.T) string {
	t.Helper()
	text, err := adapter.PromptText("prompts/47_proposer_system.md")
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func sftIsolatedStore(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(root, "sft"), 0o755); err != nil {
		t.Fatal(err)
	}
	sft.SetStorePath(filepath.Join(root, "sft", sft.ExamplesName))
	t.Cleanup(func() { sft.SetStorePath("") })
	return root
}

// sftExampleFile is `_example_file(tmp_path, **over)`.
func sftExampleFile(t *testing.T, over ...validation.KV) string {
	t.Helper()
	ex := []validation.KV{
		sftKv("id", validation.VStr("SFT-0001")),
		sftKv("version", validation.VInt(1)),
		sftKv("source", validation.VObj(
			sftKv("kind", validation.VStr("historical")),
			sftKv("ref", validation.VStr("cli-fixture")),
			sftKv("cluster", validation.VStr("cli-fixture")))),
		sftKv("taxonomy", validation.VStr("confirmed-critical")),
		sftKv("status", validation.VStr("draft")),
		sftKv("rejection_reasons", validation.VArr()),
		sftKv("partition", validation.VNull()),
		sftKv("messages", validation.VArr(
			validation.VObj(
				sftKv("role", validation.VStr("system")),
				sftKv("content", validation.VStr(sftPrompt(t)))),
			validation.VObj(
				sftKv("role", validation.VStr("user")),
				sftKv("content", validation.VStr("<bundle>"))),
			validation.VObj(
				sftKv("role", validation.VStr("assistant")),
				sftKv("content", validation.VStr(
					"OBSERVATION: deposit() mints shares against totalAssets.\n"+
						"INITIAL FRAMING: inflation hypothesis.\n"+
						"A1 (x): does y hold?\n  -> CONFIRMED. because z w v u t s r "+
						"q p o n\n"+
						"INVARIANT: shares proportional to value contributed.\n"+
						"IMPACT: attacker extracts 5,000 tokens from the victim "+
						"deposit."))))),
		sftKv("structured", validation.VObj(
			sftKv("bug_class", validation.VStr("first-depositor-inflation")),
			sftKv("claim", validation.VStr(
				"attacker inflates the share price before a victim deposit")),
			sftKv("assumptions", validation.VArr(validation.VObj(
				sftKv("id", validation.VStr("A1")),
				sftKv("text", validation.VStr("direct transfer bypasses deposit()")),
				sftKv("status", validation.VStr("CONFIRMED")),
				sftKv("reason", validation.VStr(
					"ERC20 transfer is open to anyone; no guard"))))),
			sftKv("invariants", validation.VArr(validation.VObj(
				sftKv("statement", validation.VStr(
					"shares minted proportional to value contributed")),
				sftKv("status", validation.VStr("VIOLATED"))))),
			sftKv("expected_impact", validation.VStr(
				"victim receives zero shares")),
			sftKv("next_test", validation.VStr("fork PoC")),
			sftKv("pivot_count", validation.VInt(0)))),
		sftKv("provenance", validation.VObj(
			sftKv("bundle_provenance", validation.VStr("hand-written")))),
		sftKv("created_at", validation.VStr("2026-07-15T00:00:00Z")),
	}
	for _, o := range over {
		replaced := false
		for i := range ex {
			if ex[i].K == o.K {
				ex[i].V = o.V
				replaced = true
				break
			}
		}
		if !replaced {
			ex = append(ex, o)
		}
	}
	text := validation.DumpIndented(validation.VObj(ex...)) + "\n"
	p := filepath.Join(t.TempDir(), "example.json")
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func runSFTCLI(t *testing.T, argv ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := Run(argv, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestSFTCLILintPassExit0(t *testing.T) {
	sftIsolatedStore(t)
	f := sftExampleFile(t)
	code, out, _ := runSFTCLI(t, "sft", "lint", f)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out, "PASS") {
		t.Fatalf("out = %q", out)
	}
}

func TestSFTCLILintFailExit1(t *testing.T) {
	sftIsolatedStore(t)
	f := sftExampleFile(t)
	text, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	ex, err := validation.ParseOrdered(text)
	if err != nil {
		t.Fatal(err)
	}
	assumptions := validation.ObjAt(validation.ObjAt(ex, "structured"), "assumptions").A
	assumptions[0] = setKv(assumptions[0], "reason", validation.VStr("nope"))
	ex = setAtKv(ex, validation.VArr(assumptions...), "structured", "assumptions")
	if err := os.WriteFile(f, []byte(validation.DumpIndented(ex)+"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runSFTCLI(t, "sft", "lint", f)
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out, "reason:") {
		t.Fatalf("out = %q", out)
	}
}

func TestSFTCLILintErrorExit2(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	code, _, errOut := runSFTCLI(t, "sft", "lint", missing)
	if code != 2 {
		t.Fatalf("code = %d", code)
	}
	if strings.Contains(errOut, "Traceback") {
		t.Fatalf("err = %q", errOut)
	}
}

func TestSFTCLIAddThenList(t *testing.T) {
	sftIsolatedStore(t)
	f := sftExampleFile(t)
	text, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	ex, err := validation.ParseOrdered(text)
	if err != nil {
		t.Fatal(err)
	}
	ex = dropKey(ex, "id")
	ex = dropKey(ex, "version")
	if err := os.WriteFile(f, []byte(validation.DumpIndented(ex)+"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runSFTCLI(t, "sft", "add", f)
	if code != 0 || !strings.Contains(out, "SFT-0001") {
		t.Fatalf("code = %d out = %q", code, out)
	}
	code, out, _ = runSFTCLI(t, "sft", "list")
	if code != 0 || !strings.Contains(out, "SFT-0001") {
		t.Fatalf("code = %d out = %q", code, out)
	}
}

func TestSFTCLIAddLintFailureExit2(t *testing.T) {
	sftIsolatedStore(t)
	f := sftExampleFile(t)
	text, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	ex, err := validation.ParseOrdered(text)
	if err != nil {
		t.Fatal(err)
	}
	assumptions := validation.ObjAt(validation.ObjAt(ex, "structured"), "assumptions").A
	assumptions[0] = setKv(assumptions[0], "reason", validation.VStr("nope"))
	ex = setAtKv(ex, validation.VArr(assumptions...), "structured", "assumptions")
	if err := os.WriteFile(f, []byte(validation.DumpIndented(ex)+"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runSFTCLI(t, "sft", "add", f)
	if code != 2 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(errOut, "lint failed") {
		t.Fatalf("err = %q", errOut)
	}
}

func TestSFTCLISplitAndReport(t *testing.T) {
	sftIsolatedStore(t)
	f := sftExampleFile(t)
	code, _, _ := runSFTCLI(t, "sft", "add", f, "--status", "curated")
	if code != 0 {
		t.Fatalf("add code = %d", code)
	}
	if code, _, errOut := runSFTCLI(t, "sft", "split"); code != 0 {
		t.Fatalf("split code = %d err = %q", code, errOut)
	}
	code, out, errOut := runSFTCLI(t, "sft", "report")
	if code != 0 {
		t.Fatalf("report code = %d err = %q", code, errOut)
	}
	if !strings.Contains(out, "confirmed-critical") ||
		!strings.Contains(strings.ToLower(out), "pivot") {
		t.Fatalf("out = %q", out)
	}
}

func TestSFTCLIExportCuratedOnly(t *testing.T) {
	sftIsolatedStore(t)
	f := sftExampleFile(t)
	if code, _, _ := runSFTCLI(t, "sft", "add", f); code != 0 {
		t.Fatalf("add code = %d", code)
	}
	code, out, _ := runSFTCLI(t, "sft", "export")
	if code != 0 {
		t.Fatalf("export code = %d", code)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("out = %q", out)
	}
}

// TestSFTCLIBackfillWritesDraftFile is
// tests/test_sft_backfill.py::test_cli_backfill_writes_draft_file.
func TestSFTCLIBackfillWritesDraftFile(t *testing.T) {
	sftIsolatedStore(t)
	root := t.TempDir()
	c, err := state.Init(root, "sft-cli-test", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	f, err := boundary.IngestModelHypothesis(c, cliBackfillHypothesis(),
		boundary.HypothesisOpts{})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "draft.json")
	code, stdout, errOut := runSFTCLI(t, "--root", root, "sft", "backfill",
		c.CampaignID, validation.ObjStr(f, "finding_id"), "-o", out)
	if code != 0 {
		t.Fatalf("code = %d err = %q", code, errOut)
	}
	if !strings.Contains(stdout, "wrote draft to "+out) {
		t.Fatalf("stdout = %q", stdout)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(draft, "status") != "draft" ||
		validation.ObjAt(draft, "taxonomy").Kind != validation.Null {
		t.Fatalf("draft = %s", validation.CanonCompact(draft))
	}
}

// cliBackfillHypothesis is tests/test_trajectory.py::valid_hypothesis.
func cliBackfillHypothesis() validation.Value {
	return validation.VObj(
		sftKv("bug_class", validation.VStr("oracle-manipulation")),
		sftKv("claim", validation.VStr("The vault prices redemptions against "+
			"a manipulable TWAP, allowing a flash loan to push the price and "+
			"redeem shares above NAV.")),
		sftKv("target", validation.VObj(
			sftKv("path", validation.VStr("src/Vault.sol")),
			sftKv("function", validation.VStr("redeem")))),
		sftKv("assumptions", validation.VArr(validation.VObj(
			sftKv("id", validation.VStr("A1")),
			sftKv("type", validation.VStr("reachability")),
			sftKv("claim", validation.VStr("the TWAP window is longer than "+
				"the flash-loan manipulation horizon, so the price push holds")),
			sftKv("status", validation.VStr("UNKNOWN")),
			sftKv("model_belief", validation.VFloat(0.9)),
			sftKv("blocking", validation.VBool(true))))),
		sftKv("initial_plan", validation.VArr(validation.VObj(
			sftKv("step", validation.VInt(1)),
			sftKv("tool_id", validation.VStr("callgraph")),
			sftKv("target_assumptions", validation.VArr(
				validation.VStr("A1"))),
			sftKv("expected_observation", validation.VStr(
				"redeem() has no modifier and reads TWAP"))))),
		sftKv("uncertainty", validation.VObj(
			sftKv("open_questions", validation.VArr(
				validation.VStr("current pool TVL"))))))
}

func setKv(v validation.Value, key string, val validation.Value) validation.Value {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return v
		}
	}
	v.O = append(v.O, validation.KV{K: key, V: val})
	return v
}

func setAtKv(v, val validation.Value, path ...string) validation.Value {
	if len(path) == 1 {
		return setKv(v, path[0], val)
	}
	return setKv(v, path[0], setAtKv(validation.ObjAt(v, path[0]), val, path[1:]...))
}

func dropKey(v validation.Value, key string) validation.Value {
	out := make([]validation.KV, 0, len(v.O))
	for _, kv := range v.O {
		if kv.K != key {
			out = append(out, kv)
		}
	}
	v.O = out
	return v
}
