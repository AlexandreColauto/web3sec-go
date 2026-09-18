package cli

// B8 cmd_anchors tests: `webv2 anchors <campaign> <pattern>`.
//
// FIXTURE PROVENANCE (§B8 acceptance). The artifacts below MIRROR — they do
// not embed — the shapes of the real C-f4e27261f7 campaign and of
// internal/anchorlink/testdata/replay_g01: the two gold row ids
// (34589e8588 = G-01, a047e6509f = G-02), the path-level open priority ids
// Q-008/Q-050/Q-098/Q-100, the closed decoy Q-999, the ambiguous
// L1ERC20Gateway name (one name, two model paths — the seam's live collision
// case) and the repo-prefixed finding affected[] path are the morph ones. The
// §B8 acceptance replay is therefore reproduced as a unit test rather than
// only against a campaign on disk.
//
// The artifacts are written with NO schema validation (WriteJson's schemaName
// ""), exactly like the seam's own reduced fixture: internal/anchorlink reads
// fields, it does not schema-validate, and the acceptance names that reduced
// shape. The verb itself must never schema-validate either — a campaign whose
// artifacts predate a schema bump is still a campaign an operator can ask a
// question about.

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// b8CID is the fixture campaign id (state's id regex: C- + 8..16 [0-9a-z]).
const b8CID = "C-anchors01"

// b8Contract is one protocol_model.contracts[] entry.
func b8Contract(name, path string) validation.Value {
	return validation.VObj(
		validation.KV{K: "name", V: validation.VStr(name)},
		validation.KV{K: "path", V: validation.VStr(path)})
}

// b8Model is the reduced protocol model: Rollup, the queue, the LIVE
// ambiguous L1ERC20Gateway (l1 + l2 — the basename collision the seam's
// collision rule exists for), the G-02 row's base contract, and one contract
// no other store names.
func b8Model() validation.Value {
	return validation.VObj(
		validation.KV{K: "protocol_id", V: validation.VStr("anchors-fixture")},
		validation.KV{K: "name", V: validation.VStr("Anchors fixture")},
		validation.KV{K: "contracts", V: validation.VArr(
			b8Contract("Rollup", "l1/rollup/Rollup.sol"),
			b8Contract("L1MessageQueueWithGasPriceOracle",
				"l1/rollup/L1MessageQueueWithGasPriceOracle.sol"),
			b8Contract("L1ERC20Gateway", "l1/gateways/L1ERC20Gateway.sol"),
			b8Contract("L1ERC20Gateway", "l2/gateways/L1ERC20Gateway.sol"),
			b8Contract("L1ReverseCustomGateway",
				"l1/gateways/L1ReverseCustomGateway.sol"),
			b8Contract("Unmentioned", "l1/misc/Unmentioned.sol"),
		)},
		validation.KV{K: "state_machines", V: validation.VArr(validation.VObj(
			validation.KV{K: "name", V: validation.VStr("rollup/BatchLifecycle")}))},
	)
}

// b8Sibling is one probe_surface row's siblings[] entry.
func b8Sibling(contract string, line int) validation.Value {
	return validation.VObj(
		validation.KV{K: "contract", V: validation.VStr(contract)},
		validation.KV{K: "line", V: validation.VInt(int64(line))})
}

// b8Surface is the reduced probe surface: the two gold rows, a second Rollup
// row (so a bare `Rollup.sol` widens past the G-01 row) and a row whose
// contract no other store names (so a query can match rows alone).
func b8Surface() validation.Value {
	return validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr(b8CID)},
		validation.KV{K: "rows", V: validation.VArr(
			// G-01: the round-1 miss. tier 0, undispositioned, L-03.
			validation.VObj(
				validation.KV{K: "row_id", V: validation.VStr("34589e8588")},
				validation.KV{K: "probe", V: validation.VStr("assertion-strength")},
				validation.KV{K: "axis", V: validation.VStr("enforcement-timing")},
				validation.KV{K: "lens", V: validation.VStr("L-03")},
				validation.KV{K: "tier", V: validation.VInt(0)},
				validation.KV{K: "rank", V: validation.VInt(1)},
				validation.KV{K: "assertion_gap", V: validation.VInt(4)},
				validation.KV{K: "gate", V: validation.VStr("OnlyActiveStaker")},
				// The sibling repeats the consumer's own coordinate: the
				// render must drop it (anchorsSites).
				validation.KV{K: "siblings", V: validation.VArr(b8Sibling("Rollup", 204))},
				validation.KV{K: "contract", V: validation.VStr("Rollup")},
				validation.KV{K: "consumer", V: validation.VStr("commitBatch")},
				validation.KV{K: "consumer_line", V: validation.VInt(204)},
				validation.KV{K: "asserter", V: validation.VStr("finalizeBatch")},
				validation.KV{K: "asserter_line", V: validation.VInt(496)}),
			// G-02: the custody row. No asserter — the asserting site is the
			// row's base (the forward path it compares against).
			validation.VObj(
				validation.KV{K: "row_id", V: validation.VStr("a047e6509f")},
				validation.KV{K: "probe", V: validation.VStr("custody-primitive")},
				validation.KV{K: "axis", V: validation.VStr("primitive-symmetry")},
				validation.KV{K: "lens", V: validation.VStr("L-04")},
				validation.KV{K: "tier", V: validation.VInt(1)},
				validation.KV{K: "rank", V: validation.VInt(7)},
				validation.KV{K: "gate", V: validation.VStr("onlyInDropContext")},
				validation.KV{K: "siblings", V: validation.VArr(b8Sibling("L1ERC20Gateway", 74))},
				validation.KV{K: "contract", V: validation.VStr("L1ERC20Gateway")},
				validation.KV{K: "consumer", V: validation.VStr("onDropMessage")},
				validation.KV{K: "consumer_line", V: validation.VInt(74)},
				validation.KV{K: "base", V: validation.VStr("L1ReverseCustomGateway")},
				validation.KV{K: "base_line", V: validation.VInt(122)}),
			// A second Rollup row: `Rollup.sol` must reach more than G-01.
			validation.VObj(
				validation.KV{K: "row_id", V: validation.VStr("594befa6cf")},
				validation.KV{K: "probe", V: validation.VStr("assertion-strength")},
				validation.KV{K: "axis", V: validation.VStr("enforcement-timing")},
				validation.KV{K: "lens", V: validation.VStr("L-03")},
				validation.KV{K: "tier", V: validation.VInt(0)},
				validation.KV{K: "gate", V: validation.VStr("onlyOwner")},
				validation.KV{K: "siblings", V: validation.VArr(b8Sibling("Rollup", 204))},
				validation.KV{K: "contract", V: validation.VStr("Rollup")},
				validation.KV{K: "consumer", V: validation.VStr("revertBatch")},
				validation.KV{K: "consumer_line", V: validation.VInt(210)},
				validation.KV{K: "asserter", V: validation.VStr("finalizeBatch")},
				validation.KV{K: "asserter_line", V: validation.VInt(496)}),
			// A row no priority and no finding names.
			validation.VObj(
				validation.KV{K: "row_id", V: validation.VStr("b000000001")},
				validation.KV{K: "probe", V: validation.VStr("assertion-strength")},
				validation.KV{K: "axis", V: validation.VStr("enforcement-timing")},
				validation.KV{K: "lens", V: validation.VStr("L-03")},
				validation.KV{K: "tier", V: validation.VInt(2)},
				validation.KV{K: "gate", V: validation.VStr("pokeGate")},
				validation.KV{K: "contract", V: validation.VStr("Unmentioned")},
				validation.KV{K: "consumer", V: validation.VStr("poke")},
				validation.KV{K: "consumer_line", V: validation.VInt(12)}),
		)},
		validation.KV{K: "axes", V: validation.VArr()},
		validation.KV{K: "missing", V: validation.VArr()},
		validation.KV{K: "warnings", V: validation.VArr()},
	)
}

// b8Prio is one campaign_plan.priorities[] entry.
func b8Prio(id, status string, risk float64, components ...string) validation.Value {
	comps := make([]validation.Value, 0, len(components))
	for _, c := range components {
		comps = append(comps, validation.VStr(c))
	}
	return validation.VObj(
		validation.KV{K: "id", V: validation.VStr(id)},
		validation.KV{K: "question", V: validation.VStr("fixture question " + id)},
		validation.KV{K: "risk", V: validation.VFloat(risk)},
		validation.KV{K: "components", V: validation.VArr(comps...)},
		validation.KV{K: "status", V: validation.VStr(status)})
}

// b8Plan is the reduced campaign plan: the four path-level open priorities the
// acceptance names (all naming Rollup), the closed decoy Q-999, and one
// priority on the ambiguous gateway name.
func b8Plan() validation.Value {
	return validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr(b8CID)},
		validation.KV{K: "priorities", V: validation.VArr(
			b8Prio("Q-008", "open", 0.8, "Rollup"),
			b8Prio("Q-050", "open", 0.7, "Rollup",
				"L1MessageQueueWithGasPriceOracle"),
			b8Prio("Q-098", "open", 0.7, "Rollup"),
			// A component the model does not carry: it must resolve to
			// nothing and must not hide the Rollup citation beside it.
			b8Prio("Q-100", "open", 0.7, "BatchHeaderCodecV0", "Rollup"),
			b8Prio("Q-999", "closed", 0.1, "Rollup"),
			b8Prio("Q-012", "open", 0.5, "L1ERC20Gateway"),
		)})
}

// b8Finding is one findings/*.json, with the repo-prefixed affected path the
// morph findings carry (the seam's one directional suffix rule).
func b8Finding(id, title, path, fn string, lo, hi int) validation.Value {
	return validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr(id)},
		validation.KV{K: "title", V: validation.VStr(title)},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr(path)},
			validation.KV{K: "function", V: validation.VStr(fn)},
			validation.KV{K: "lines", V: validation.VArr(
				validation.VInt(int64(lo)), validation.VInt(int64(hi)))}))})
}

// b8Write writes one artifact with no schema validation (see the header).
func b8Write(t *testing.T, path string, v validation.Value) {
	t.Helper()
	if err := validation.WriteJson(path, v, ""); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// b8Init is the bare fixture campaign: a real campaign directory (state.Init)
// with no artifacts at all.
func b8Init(t *testing.T, root string) *state.Campaign {
	t.Helper()
	c, err := state.Init(root, "Anchors CLI", state.InitOpts{CampaignID: b8CID})
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	return c
}

// b8WriteModel / b8WriteSurface write just the one artifact (the absence and
// corruption cases need them independently).
func b8WriteModel(t *testing.T, c *state.Campaign) {
	t.Helper()
	b8Write(t, filepath.Join(c.ArtifactsDir, anchorsModelArtifact), b8Model())
}

func b8WriteSurface(t *testing.T, c *state.Campaign) {
	t.Helper()
	b8Write(t, filepath.Join(c.ArtifactsDir, anchorsSurfaceArtifact), b8Surface())
}

// b8Fixture is the FULL fixture: model + surface + plan + findings.
func b8Fixture(t *testing.T, root string) *state.Campaign {
	t.Helper()
	c := b8Init(t, root)
	b8WriteModel(t, c)
	b8WriteSurface(t, c)
	b8Write(t, filepath.Join(c.ArtifactsDir, anchorsPlanArtifact), b8Plan())
	b8Write(t, filepath.Join(c.FindingsDir, "F-000000000001.json"),
		b8Finding("F-000000000001",
			"commitBatch authentication is a stub: any active staker commits "+
				"arbitrary state/withdrawal roots",
			"contracts/contracts/l1/rollup/Rollup.sol", "commitBatch", 204, 320))
	b8Write(t, filepath.Join(c.FindingsDir, "F-000000000002.json"),
		b8Finding("F-000000000002",
			"the drop path pays out an unfunded balance",
			"contracts/l1/gateways/L1ERC20Gateway.sol", "onDropMessage", 74, 80))
	return c
}

// b8Run runs `anchors <pattern>` against the fixture root.
func b8Run(t *testing.T, root, pattern string) (int, string, string) {
	t.Helper()
	return run(t, "--root", root, "anchors", b8CID, pattern)
}

// b8Tree is every file under dir as rel-path -> content, for the read-only
// assertion: a query verb that silently appended an event or rewrote an
// artifact would show up here.
func b8Tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		out[rel] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	return out
}

// b8Want is a small Contains table: every want must appear, every absent must
// not. It keeps the acceptance assertions readable.
func b8Want(t *testing.T, label, got string, want, absent []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("%s: missing %q in:\n%s", label, w, got)
		}
	}
	for _, a := range absent {
		if strings.Contains(got, a) {
			t.Errorf("%s: unexpected %q in:\n%s", label, a, got)
		}
	}
}

// b8LensLine is the exact L-03 stderr line for the G-01 fixture row.
const b8LensG01 = "the surface asserts OnlyActiveStaker at " +
	"Rollup#finalizeBatch:496 and consumes it at Rollup#commitBatch:204 — " +
	"at which stage is it enforced? (lens L-03)\n"

// ---- help and argparse shapes --------------------------------------------

// TestAnchorsHelpDocumentsEveryPatternForm: -h/--help answers before any
// validation (exit 0, stdout, empty stderr) and the help names every accepted
// pattern form — path, suffix, #function and :line.
func TestAnchorsHelpDocumentsEveryPatternForm(t *testing.T) {
	root := t.TempDir()
	for _, flag := range []string{"-h", "--help"} {
		code, out, errS := run(t, "--root", root, "anchors", flag)
		if code != 0 {
			t.Fatalf("%s: exit %d, want 0 (stderr %q)", flag, code, errS)
		}
		if errS != "" {
			t.Errorf("%s: stderr must stay empty; got %q", flag, errS)
		}
		b8Want(t, flag, out, []string{
			"usage: webv2 anchors [-h] campaign pattern",
			"Rollup.sol#commitBatch:204", // path#function:line
			"Rollup.sol#commitBatch",     // path#function
			"l1/rollup/Rollup.sol:204",   // path:line
			"l1/rollup/Rollup.sol",       // the full model path
			"rollup/Rollup.sol",          // a directory tail
			"Rollup.sol",                 // a basename
			"segment boundary",
			"lens L-03",
		}, nil)
	}
	// `webv2 help anchors` routes to the same block (cli.go's delegation).
	code, out, errS := run(t, "--root", root, "help", "anchors")
	if code != 0 || !strings.Contains(out, "usage: webv2 anchors") {
		t.Errorf("help anchors: exit %d out=%q err=%q", code, out, errS)
	}
}

// TestAnchorsUsageErrorsExitTwo pins the argparse shapes: the missing
// positionals in declaration order, and the surplus positional / unknown flag
// through the root parser's "unrecognized arguments" text.
func TestAnchorsUsageErrorsExitTwo(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"both missing", []string{"anchors"},
			"the following arguments are required: campaign, pattern"},
		{"pattern missing", []string{"anchors", b8CID},
			"the following arguments are required: pattern"},
		{"surplus positional", []string{"anchors", b8CID, "Rollup.sol", "extra"},
			"unrecognized arguments: extra"},
		{"unknown flag", []string{"anchors", "--bogus"},
			"unrecognized arguments: --bogus"},
	}
	for _, tc := range cases {
		code, out, errS := run(t, append([]string{"--root", root}, tc.args...)...)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2 (stderr %q)", tc.name, code, errS)
		}
		if !strings.Contains(errS, tc.want) {
			t.Errorf("%s: stderr missing %q; got %q", tc.name, tc.want, errS)
		}
		if out != "" {
			t.Errorf("%s: usage failures must write nothing to stdout; got %q",
				tc.name, out)
		}
	}
	// The missing-argument shape also carries the verb's own usage line.
	_, _, errS := run(t, "--root", root, "anchors")
	if !strings.Contains(errS, anchorsUsage) {
		t.Errorf("stderr missing the usage block %q; got %q", anchorsUsage, errS)
	}
}

// ---- refusals (exit 2) and their heal lines ------------------------------

// TestAnchorsMissingCampaignRefusesAtTwo: a missing campaign is a refusal at
// 2, not the generic exit-1 mapper, and it heals by naming the verb that
// reports on a campaign.
func TestAnchorsMissingCampaignRefusesAtTwo(t *testing.T) {
	root := t.TempDir()
	code, out, errS := run(t, "--root", root, "anchors", "C-nosuchcam", "Rollup.sol")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (out=%q err=%q)", code, out, errS)
	}
	b8Want(t, "stderr", errS, []string{
		"anchors: no such campaign",
		"`webv2 status C-nosuchcam`",
		"`webv2 init`",
	}, []string{"error:"})
	if out != "" {
		t.Errorf("a refusal writes nothing to stdout; got %q", out)
	}
}

// TestAnchorsMissingModelHealsWithTheModelCommand: the model is required, and
// its absence names the command that produces it.
func TestAnchorsMissingModelHealsWithTheModelCommand(t *testing.T) {
	root := t.TempDir()
	b8Init(t, root)
	code, _, errS := b8Run(t, root, "Rollup.sol")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (err=%q)", code, errS)
	}
	b8Want(t, "stderr", errS, []string{
		"anchors: no protocol model for " + b8CID,
		anchorsModelArtifact,
		"`webv2 model " + b8CID + " model.json`",
	}, nil)
}

// TestAnchorsMissingSurfaceHealsWithTheIndexCommand: the surface is required,
// and its absence names BOTH commands that produce it (index then probes).
func TestAnchorsMissingSurfaceHealsWithTheIndexCommand(t *testing.T) {
	root := t.TempDir()
	c := b8Init(t, root)
	b8WriteModel(t, c)
	code, _, errS := b8Run(t, root, "Rollup.sol")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (err=%q)", code, errS)
	}
	b8Want(t, "stderr", errS, []string{
		"anchors: no probe surface for " + b8CID,
		"`webv2 index " + b8CID + " --src <target>`",
		"`webv2 probes " + b8CID + " run`",
	}, nil)
}

// TestAnchorsUnparseableArtifactsRefuseAtTwo: an artifact that is PRESENT and
// unreadable is always a refusal — never a silent empty group (the r43a
// discipline) — and the heal line names the command that rebuilds it.
func TestAnchorsUnparseableArtifactsRefuseAtTwo(t *testing.T) {
	cases := []struct {
		name string
		rel  string // relative to the campaign dir
		want []string
	}{
		{"model", "artifacts/" + anchorsModelArtifact, []string{
			"unreadable", anchorsModelArtifact,
			"`webv2 model " + b8CID + " model.json`"}},
		{"surface", "artifacts/" + anchorsSurfaceArtifact, []string{
			"unreadable", anchorsSurfaceArtifact,
			"`webv2 index " + b8CID + " --src <target>`"}},
		{"plan", "artifacts/" + anchorsPlanArtifact, []string{
			"unreadable", anchorsPlanArtifact,
			"`webv2 plan " + b8CID + " <plan.json>`"}},
		{"finding", "findings/F-000000000001.json", []string{
			"unreadable finding", "F-000000000001.json",
			"`webv2 ingest " + b8CID + " --json-file"}},
	}
	for _, tc := range cases {
		root := t.TempDir()
		b8Fixture(t, root)
		p := filepath.Join(root, "campaigns", b8CID, filepath.FromSlash(tc.rel))
		if err := os.WriteFile(p, []byte("{ this is not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		code, out, errS := b8Run(t, root, "Rollup.sol")
		if code != 2 {
			t.Errorf("%s: exit %d, want 2 (out=%q err=%q)", tc.name, code, out, errS)
		}
		b8Want(t, tc.name, errS, tc.want, nil)
		if out != "" {
			t.Errorf("%s: a refusal writes nothing to stdout; got %q", tc.name, out)
		}
	}
}

// ---- §B8 acceptance: the two gold shapes ---------------------------------

// TestAnchorsG01RowAndPathLevelPriorities is the §B8 acceptance replay, half
// one: `anchors <C> Rollup.sol#commitBatch` returns the G-01 row AND the
// path-level open priorities Q-008/Q-050/Q-098/Q-100 — priorities carry no
// function coordinates, so a function-qualified query still lists the ones
// that name its path (B7 review finding 1). The closed decoy Q-999 and the
// gateway priority Q-012 must not appear.
func TestAnchorsG01RowAndPathLevelPriorities(t *testing.T) {
	root := t.TempDir()
	b8Fixture(t, root)
	code, out, errS := b8Run(t, root, "Rollup.sol#commitBatch")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	b8Want(t, "stdout", out, []string{
		"anchors: Rollup.sol#commitBatch",
		"34589e8588",
		"tier 0",
		"UNDISPOSITIONED",
		"paths l1/rollup/Rollup.sol",
		"consumer Rollup#commitBatch:204",
		"asserter Rollup#finalizeBatch:496",
		"open priorities:",
		"Q-008", "Q-050", "Q-098", "Q-100",
		"F-000000000001",
	}, []string{
		"Q-999", // closed: the seam's open-only rule
		"Q-012", // the gateway priority cannot match a Rollup path
		"a047e6509f",
		"594befa6cf",
	})
	// The L-03 line: the question the round-1 miss never asked.
	if !strings.Contains(errS, b8LensG01) {
		t.Errorf("stderr missing the L-03 line %q; got %q", b8LensG01, errS)
	}
	if strings.Count(errS, "\n") != 1 {
		t.Errorf("stderr must carry exactly one line; got %q", errS)
	}
}

// TestAnchorsG02Row is the acceptance replay, half two:
// `anchors <C> L1ERC20Gateway.sol#onDropMessage` returns the G-02 row — which
// cites the AMBIGUOUS contract name, so the row line carries both model paths
// the seam resolves for it.
func TestAnchorsG02Row(t *testing.T) {
	root := t.TempDir()
	b8Fixture(t, root)
	code, out, errS := b8Run(t, root, "L1ERC20Gateway.sol#onDropMessage")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	b8Want(t, "stdout", out, []string{
		"anchors: L1ERC20Gateway.sol#onDropMessage",
		"a047e6509f",
		"tier 1",
		"UNDISPOSITIONED",
		"paths l1/gateways/L1ERC20Gateway.sol, l2/gateways/L1ERC20Gateway.sol",
		"consumer L1ERC20Gateway#onDropMessage:74",
		"Q-012",
		"F-000000000002",
	}, []string{
		"34589e8588",
		"Q-008",
		"F-000000000001",
	})
	// The G-02 row carries no asserter, so the asserting site is its base:
	// the forward-path contract the custody row compares against.
	want := "the surface asserts onlyInDropContext at L1ReverseCustomGateway:122 " +
		"and consumes it at L1ERC20Gateway#onDropMessage:74 — at which stage is " +
		"it enforced? (lens L-03)\n"
	if !strings.Contains(errS, want) {
		t.Errorf("stderr missing the L-03 line %q; got %q", want, errS)
	}
}

// TestAnchorsBareBasenameWidensToTheWholePath: the acceptance's third claim —
// bare `anchors <C> Rollup.sol` adds 594befa6cf and the rest of the Rollup
// members, and still appends exactly ONE lens line.
func TestAnchorsBareBasenameWidensToTheWholePath(t *testing.T) {
	root := t.TempDir()
	b8Fixture(t, root)
	code, out, errS := b8Run(t, root, "Rollup.sol")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	b8Want(t, "stdout", out, []string{
		"anchors: Rollup.sol",
		"34589e8588",
		"594befa6cf",
		"2 surface rows",
		// 594befa6cf's sibling is a coordinate of its own (204 vs consumer 210)
		"sibling Rollup:204",
		"Q-008", "Q-050", "Q-098", "Q-100",
		"F-000000000001",
	}, []string{"b000000001", "a047e6509f"})
	if strings.Count(errS, "\n") != 1 {
		t.Errorf("exactly one lens line per run; got %q", errS)
	}
}

// TestAnchorsG01StdoutIsBytePinned pins the whole stdout of the acceptance
// query: the group order, the column separators, the two-space indent and the
// em dash are contractual bytes, not cosmetics.
func TestAnchorsG01StdoutIsBytePinned(t *testing.T) {
	root := t.TempDir()
	b8Fixture(t, root)
	code, out, errS := b8Run(t, root, "Rollup.sol#commitBatch")
	if code != 0 {
		t.Fatalf("exit %d: err=%q", code, errS)
	}
	want := "anchors: Rollup.sol#commitBatch — 1 surface rows, 4 open priorities, " +
		"1 findings\n" +
		"surface rows:\n" +
		"  34589e8588  tier 0  UNDISPOSITIONED  paths l1/rollup/Rollup.sol  " +
		"consumer Rollup#commitBatch:204  asserter Rollup#finalizeBatch:496\n" +
		"open priorities:\n" +
		"  Q-008  open  risk 0.8\n" +
		"  Q-050  open  risk 0.7\n" +
		"  Q-098  open  risk 0.7\n" +
		"  Q-100  open  risk 0.7\n" +
		"findings:\n" +
		"  F-000000000001  commitBatch authentication is a stub: any active " +
		"staker commits arbitrary state/withdrawal roots\n"
	if out != want {
		t.Errorf("stdout bytes differ:\n got %q\nwant %q", out, want)
	}
	if errS != b8LensG01 {
		t.Errorf("stderr bytes differ:\n got %q\nwant %q", errS, b8LensG01)
	}
}

// TestAnchorsWritesNothingToTheCampaign is the seam's no-write-join contract
// as a CLI invariant: a query must not append an event, stamp an anchor or
// touch an artifact.
func TestAnchorsWritesNothingToTheCampaign(t *testing.T) {
	root := t.TempDir()
	b8Fixture(t, root)
	dir := filepath.Join(root, "campaigns", b8CID)
	before := b8Tree(t, dir)
	if code, out, errS := b8Run(t, root, "Rollup.sol"); code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	after := b8Tree(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("anchors changed the campaign tree:\nbefore=%v\nafter=%v",
			before, after)
	}
}

// ---- empty groups, no-match patterns, the lens trigger -------------------

// TestAnchorsAbsentPlanAndFindingsAreEmptyNotAnError: a campaign that has no
// plan and no findings yet is a legitimate campaign. The two stores read as
// empty groups, the exit stays 0, and (nothing having converged) no lens line
// is written.
func TestAnchorsAbsentPlanAndFindingsAreEmptyNotAnError(t *testing.T) {
	root := t.TempDir()
	c := b8Init(t, root)
	b8WriteModel(t, c)
	b8WriteSurface(t, c)
	code, out, errS := b8Run(t, root, "Rollup.sol#commitBatch")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (out=%q err=%q)", code, out, errS)
	}
	b8Want(t, "stdout", out, []string{
		"anchors: Rollup.sol#commitBatch — 1 surface rows, 0 open priorities, " +
			"0 findings",
		"34589e8588",
		"open priorities:\n  (none)",
		"findings:\n  (none)",
	}, nil)
	if errS != "" {
		t.Errorf("no convergence means no lens line; got %q", errS)
	}
}

// TestAnchorsPatternMatchingNothingExitsZero: "nothing names this code" is the
// answer to the question, not a failure to answer it — exit 0 and three
// explicit empty groups, byte-pinned.
func TestAnchorsPatternMatchingNothingExitsZero(t *testing.T) {
	root := t.TempDir()
	b8Fixture(t, root)
	code, out, errS := b8Run(t, root, "NothingHere.sol")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (out=%q err=%q)", code, out, errS)
	}
	want := "anchors: NothingHere.sol — 0 surface rows, 0 open priorities, " +
		"0 findings\n" +
		"surface rows:\n  (none)\n" +
		"open priorities:\n  (none)\n" +
		"findings:\n  (none)\n"
	if out != want {
		t.Errorf("stdout bytes differ:\n got %q\nwant %q", out, want)
	}
	if errS != "" {
		t.Errorf("a no-match query writes nothing to stderr; got %q", errS)
	}
}

// TestAnchorsRowsWithoutConvergencePrintNoLensLine pins the trigger: the L-03
// line needs rows AND (priorities OR findings). Rows alone are just a surface
// answer, and a reminder machine that fires on every row would be noise.
func TestAnchorsRowsWithoutConvergencePrintNoLensLine(t *testing.T) {
	root := t.TempDir()
	b8Fixture(t, root)
	code, out, errS := b8Run(t, root, "Unmentioned.sol")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (out=%q err=%q)", code, out, errS)
	}
	b8Want(t, "stdout", out, []string{
		"b000000001",
		"consumer Unmentioned#poke:12",
		"0 open priorities, 0 findings",
	}, nil)
	if errS != "" {
		t.Errorf("rows without a co-naming store must not trigger L-03; got %q", errS)
	}
}

// TestAnchorsRowsAndFindingsAloneStillTriggerTheLensLine: the second half of
// the trigger — rows AND findings, with no priority in sight.
func TestAnchorsRowsAndFindingsAloneStillTriggerTheLensLine(t *testing.T) {
	root := t.TempDir()
	c := b8Init(t, root)
	b8WriteModel(t, c)
	b8WriteSurface(t, c)
	b8Write(t, filepath.Join(c.FindingsDir, "F-000000000001.json"),
		b8Finding("F-000000000001", "a stub assertion",
			"contracts/contracts/l1/rollup/Rollup.sol", "commitBatch", 204, 320))
	code, out, errS := b8Run(t, root, "Rollup.sol#commitBatch")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (out=%q err=%q)", code, out, errS)
	}
	b8Want(t, "stdout", out, []string{
		"1 surface rows, 0 open priorities, 1 findings",
		"F-000000000001",
	}, nil)
	if errS != b8LensG01 {
		t.Errorf("rows+findings must trigger L-03; got %q want %q", errS, b8LensG01)
	}
}

// TestAnchorsClosedPriorityIsNeverListed pins the seam's open-only rule at the
// verb boundary, independently of the acceptance query.
func TestAnchorsClosedPriorityIsNeverListed(t *testing.T) {
	root := t.TempDir()
	c := b8Init(t, root)
	b8WriteModel(t, c)
	b8WriteSurface(t, c)
	b8Write(t, filepath.Join(c.ArtifactsDir, anchorsPlanArtifact),
		validation.VObj(validation.KV{K: "priorities", V: validation.VArr(
			b8Prio("Q-999", "closed", 0.1, "Rollup"),
			b8Prio("Q-100", "deprioritized", 0.1, "Rollup"),
			b8Prio("Q-008", "open", 0.8, "Rollup"))}))
	code, out, errS := b8Run(t, root, "Rollup.sol")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (err=%q)", code, errS)
	}
	b8Want(t, "stdout", out, []string{"Q-008", "1 open priorities"},
		[]string{"Q-999", "Q-100"})
}

// ---- render units ---------------------------------------------------------

// TestAnchorsTitleCapsWithAnEllipsis: a title at the cap is untouched; one
// past it is cut at the cap and marked.
func TestAnchorsTitleCapsWithAnEllipsis(t *testing.T) {
	atCap := strings.Repeat("x", anchorsTitleCap)
	if got := anchorsTitle(atCap); got != atCap {
		t.Errorf("a title at the cap must be untouched; got %q", got)
	}
	long := strings.Repeat("x", anchorsTitleCap+40)
	got := anchorsTitle(long)
	if runes := []rune(got); len(runes) != anchorsTitleCap+1 {
		t.Errorf("truncated title has %d runes, want %d", len(runes),
			anchorsTitleCap+1)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("a truncated title must end in an ellipsis; got %q", got)
	}
}

// TestAnchorsSitesDropsARedundantSibling: the probes name the very site they
// compare against, so the render must not print the consumer's coordinate
// twice — and must keep a sibling that is a genuinely different coordinate.
func TestAnchorsSitesDropsARedundantSibling(t *testing.T) {
	row := validation.VObj(
		validation.KV{K: "contract", V: validation.VStr("Rollup")},
		validation.KV{K: "consumer", V: validation.VStr("commitBatch")},
		validation.KV{K: "consumer_line", V: validation.VInt(204)},
		validation.KV{K: "asserter", V: validation.VStr("finalizeBatch")},
		validation.KV{K: "asserter_line", V: validation.VInt(496)},
		validation.KV{K: "siblings", V: validation.VArr(
			b8Sibling("Rollup", 204),   // == the consumer's own coordinate
			b8Sibling("Rollup", 496),   // == the asserter's own coordinate
			b8Sibling("Rollup", 210))}, // a coordinate of its own
	)
	got := []string{}
	for _, s := range anchorsSites(row) {
		got = append(got, s.kind+" "+s.text)
	}
	want := []string{
		"consumer Rollup#commitBatch:204",
		"asserter Rollup#finalizeBatch:496",
		"sibling Rollup:210",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("anchorsSites = %v, want %v", got, want)
	}
}

// TestAnchorsRiskTextDistinguishesAbsentFromZero: a priority with no recorded
// risk must not print as the number zero.
func TestAnchorsRiskTextDistinguishesAbsentFromZero(t *testing.T) {
	if got := anchorsRiskText(validation.VNull()); got != "—" {
		t.Errorf("absent risk = %q, want an em dash", got)
	}
	if got := anchorsRiskText(validation.VFloat(0)); got != "0.0" {
		t.Errorf("zero risk = %q, want 0.0", got)
	}
	if got := anchorsRiskText(validation.VFloat(0.8)); got != "0.8" {
		t.Errorf("0.8 = %q, want 0.8", got)
	}
}

// TestAnchorsRegistersAfterSchema pins the catalog position: ord 91 sits
// directly after B1's `schema` (ord 90), so no existing verb is renumbered.
func TestAnchorsRegistersAfterSchema(t *testing.T) {
	cat := usageText()
	si := strings.Index(cat, "schema [--list]")
	ai := strings.Index(cat, "anchors <campaign>")
	if si < 0 || ai < 0 {
		t.Fatalf("catalog missing a verb: schema at %d, anchors at %d\n%s",
			si, ai, cat)
	}
	if ai < si {
		t.Errorf("anchors must list after schema; got anchors at %d, schema at %d",
			ai, si)
	}
}
