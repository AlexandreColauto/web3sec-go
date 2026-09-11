package cli

// cmd_scorecard_test.go: the tests for `webv2 scorecard`.
//
// What is worth pinning here, in the order the sections print:
//
//   - the audit SURFACE is the pin's own file set, split by srcclass.Classify
//     with real line counts — the number the operator reads to decide whether
//     "153 files" means 153 files of product code;
//   - the six sections print in the locked order, --json emits the same keys in
//     the same order, and --no-surface OMITS the surface key rather than
//     emptying it;
//   - an unknown campaign is a handled error (exit 1), not a crash;
//   - missing/unknown arguments are usage errors (exit 2);
//   - the containment warning fires when the ACTIVE SNAPSHOT RECORDS
//     source.campaign_inside_target (the pin decided it while the absolute
//     target was still known); the section is presence-gated, so an ordinary
//     pin prints nothing at all.
//
// The eval section's own arithmetic is evalscore's, tested there; what this
// file pins is that scorecard reports "no gold case matches" in words instead
// of printing a zeroed score.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// scWrite writes one file of a fixture tree, creating parents.
func scWrite(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

// TestScorecardSurfaceCompositionFiveClasses is the acceptance tree read as a
// table: five files, one per class, including `other`. A headline count of
// these five would say "5 files" whether or not any of them is solidity to
// reason about; the composition row says which one is the code the audit act
// is about.
func TestScorecardSurfaceCompositionFiveClasses(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t.TempDir()
	scWrite(t, tgt, "src/Vault.sol", "contract Vault {}\n")
	scWrite(t, tgt, "test/Vault.t.sol", "a\n")
	scWrite(t, tgt, "lib/x.sol", "b\n")
	scWrite(t, tgt, "src/IThing.sol", "c\n")
	scWrite(t, tgt, "foundry.toml", "[profile.default]\nsolc = \"0.8.24\"\n")

	if code, _, errS := run(t, "--root", root, "snap", cid, tgt); code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}
	code, out, errS := run(t, "--root", root, "scorecard", cid)
	if code != 0 {
		t.Fatalf("scorecard exit %d: %q", code, errS)
	}
	for _, want := range []string{
		"implementation: 1 file, 1 line\n",
		"test-double: 1 file, 1 line\n",
		"library: 1 file, 1 line\n",
		"interface: 1 file, 1 line\n",
		"other: 1 file, 2 lines\n",
		"TOTAL: 5 files, 6 lines\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("composition missing %q:\n%s", want, out)
		}
	}
	// The JSON rows carry one entry per class, in reporting order.
	code, out, errS = run(t, "--root", root, "scorecard", cid, "--json")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("scorecard --json not JSON: %v\n%s", err, out)
	}
	rows, _ := doc["surface"].(map[string]any)["rows"].([]any)
	if len(rows) != 5 {
		t.Fatalf("surface rows = %d, want 5:\n%s", len(rows), out)
	}
	wantClasses := []string{"implementation", "test-double", "library",
		"interface", "other"}
	for i, r := range rows {
		row, _ := r.(map[string]any)
		if row["class"] != wantClasses[i] {
			t.Errorf("row %d class = %v, want %q", i, row["class"],
				wantClasses[i])
		}
	}
}

// TestScorecardSurfaceComposition is the surface contract: one pinned file per
// srcclass bucket, the count of FILES and the count of LINES, and a total that
// is the sum of the buckets (never a re-count of the tree).
func TestScorecardSurfaceComposition(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t.TempDir()
	// 3 lines, 2 lines, 4 lines, and one file with no trailing newline (a
	// file that ends mid-line is still one line long).
	scWrite(t, tgt, "src/Vault.sol", "contract Vault {\n  uint256 x;\n}\n")
	scWrite(t, tgt, "src/IVault.sol", "interface IVault {\n}\n")
	scWrite(t, tgt, "test/Vault.t.sol", "a\nb\nc\nd\n")
	scWrite(t, tgt, "lib/forge-std/src/Test.sol", "pragma solidity ^0.8.0;")

	if code, out, errS := run(t, "--root", root, "snap", cid, tgt); code != 0 {
		t.Fatalf("snap exit %d: out=%q err=%q", code, out, errS)
	}
	code, out, errS := run(t, "--root", root, "scorecard", cid)
	if code != 0 {
		t.Fatalf("scorecard exit %d: out=%q err=%q", code, out, errS)
	}
	for _, want := range []string{
		"campaign\n", "  id: " + cid + "\n", "  program: CLI Test\n",
		"surface\n", "findings\n", "process\n", "eval\n",
		"implementation: 1 file, 3 lines\n",
		"test-double: 1 file, 4 lines\n",
		"library: 1 file, 1 line\n",
		"interface: 1 file, 2 lines\n",
		"TOTAL: 4 files, 10 lines\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scorecard output missing %q:\n%s", want, out)
		}
	}
	// Order of the six headings is the contract.
	last := -1
	for _, h := range []string{"campaign\n", "surface\n", "findings\n",
		"process\n", "eval\n"} {
		i := strings.Index(out, h)
		if i <= last {
			t.Fatalf("section %q out of order:\n%s", h, out)
		}
		last = i
	}
}

// TestScorecardNoSnapshot drives the absent-data path: a campaign that has not
// pinned anything says so in words and prints no surface numbers (not a zeroed
// total, which would read as an empty target).
func TestScorecardNoSnapshot(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "scorecard", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "no pinned snapshot yet") {
		t.Errorf("missing absent-surface line:\n%s", out)
	}
	if strings.Contains(out, "TOTAL:") {
		t.Errorf("no snapshot must print no total:\n%s", out)
	}
	if !strings.Contains(out, "live findings: 0") ||
		!strings.Contains(out, "no live findings yet") {
		t.Errorf("findings section must say there are none:\n%s", out)
	}
}

// TestScorecardFindingsTallies pins the two tallies: by status, and by the
// evidence rung findings.FindingLevel reports (E0 for a bare hypothesis with no
// evidence). One finding, counted once in each.
func TestScorecardFindingsTallies(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.IngestHypothesis(c, validation.VObj(
		validation.KV{K: "title", V: validation.VStr("vault misprices")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("logic-error")},
			validation.KV{K: "description", V: validation.VStr("prices " +
				"from an attacker-movable source")})},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/Vault.sol")}))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()})},
		validation.KV{K: "capabilities", V: validation.VObj(
			validation.KV{K: "granted", V: validation.VArr()},
			validation.KV{K: "required", V: validation.VArr()})},
	), "code", "test", ""); err != nil {
		t.Fatalf("ingest hypothesis: %v", err)
	}
	code, out, errS := run(t, "--root", root, "scorecard", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	for _, want := range []string{
		"live findings: 1\n",
		"status HYPOTHESIS: 1\n",
		"evidence rung E0: 1\n",
		"blank attestations: 0\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no live findings yet") {
		t.Errorf("live finding present but section says otherwise:\n%s", out)
	}
}

// TestScorecardSurfaceFlagAndJSONOrder is the machine contract: --json carries
// the sections as an ordered object holding the same numbers, and --no-surface
// leaves the surface KEY out of both the object and the text.
func TestScorecardSurfaceFlagAndJSONOrder(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t.TempDir()
	scWrite(t, tgt, "src/Vault.sol", "contract Vault {}\n")
	if code, _, errS := run(t, "--root", root, "snap", cid, tgt); code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}

	code, out, errS := run(t, "--root", root, "scorecard", cid, "--json")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	got := keyOrder(t, out)
	want := []string{"campaign", "surface", "findings", "process", "eval"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("key order %v, want %v:\n%s", got, want, out)
	}
	if !strings.Contains(out, `"implementation"`) ||
		!strings.Contains(out, `"lines": 1`) {
		t.Errorf("surface numbers missing from JSON:\n%s", out)
	}

	code, out, errS = run(t, "--root", root, "scorecard", cid, "--json",
		"--no-surface")
	if code != 0 {
		t.Fatalf("json --no-surface exit %d: %q", code, errS)
	}
	got = keyOrder(t, out)
	want = []string{"campaign", "findings", "process", "eval"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("--no-surface key order %v, want %v:\n%s", got, want, out)
	}
	if strings.Contains(out, `"surface"`) {
		t.Errorf("--no-surface must omit the key entirely:\n%s", out)
	}

	code, out, errS = run(t, "--root", root, "scorecard", cid, "--no-surface")
	if code != 0 {
		t.Fatalf("text --no-surface exit %d: %q", code, errS)
	}
	if strings.Contains(out, "\nsurface\n") {
		t.Errorf("--no-surface must omit the section entirely:\n%s", out)
	}
}

// TestScorecardEvalNoMatch: when the campaign's program matches no suite case
// the section says so in words — it does not print a score computed over an
// empty denominator, which would read as a failing campaign.
func TestScorecardEvalNoMatch(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "scorecard", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "no gold case matches program CLI Test") {
		t.Errorf("missing no-gold-case line:\n%s", out)
	}
	if strings.Contains(out, "precision") {
		t.Errorf("no score may be printed without a matching case:\n%s", out)
	}
}

// TestScorecardUnknownCampaign: a handled error, exit 1, no stack, no panic.
func TestScorecardUnknownCampaign(t *testing.T) {
	root := mkroot(t)
	initOne(t, root)
	code, out, errS := run(t, "--root", root, "scorecard", "C-0000000000")
	if code != 1 {
		t.Fatalf("exit %d, want 1: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "no such campaign") {
		t.Fatalf("stderr %q", errS)
	}
}

// TestScorecardArgparse: argparse's exit 2 contract for a missing positional
// and for an unrecognized argument.
func TestScorecardArgparse(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)

	code, out, errS := run(t, "--root", root, "scorecard")
	if code != 2 {
		t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS,
		"the following arguments are required: campaign") {
		t.Fatalf("stderr %q", errS)
	}
	if !strings.Contains(errS, "usage: webv2 scorecard") {
		t.Fatalf("usage block missing:\n%s", errS)
	}

	code, out, errS = run(t, "--root", root, "scorecard", cid, "--bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "unrecognized arguments: --bogus") {
		t.Fatalf("stderr %q", errS)
	}
}

// TestScorecardHelp: -h is exit 0 and prints the verb's own usage block.
func TestScorecardHelp(t *testing.T) {
	code, out, errS := run(t, "scorecard", "-h")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "usage: webv2 scorecard [-h] [--json] "+
		"[--no-surface] [--gold FILE] campaign") {
		t.Fatalf("help missing usage:\n%s", out)
	}
	if !strings.Contains(out, "--no-surface") {
		t.Fatalf("help missing flag prose:\n%s", out)
	}
	if !strings.Contains(out, "--gold FILE") ||
		!strings.Contains(out, "not part of a campaign run") {
		t.Fatalf("help missing the --gold prose:\n%s", out)
	}
}

// TestScorecardContainmentWarning pins the containment section from the
// RECORDED fact, not from a path comparison.
//
// A real pin stages the walked tree as an immutable COPY under
// <campaign>/snapshots/<id>, so source.root is always a descendant of the
// campaign directory: comparing it against the campaign dir asks whether a
// directory is inside its own child, which is never true. The geometry the
// warning exists to catch (the campaign store living inside the target being
// audited) is therefore decided in the pin, where the absolute target is
// still known, and recorded as source.campaign_inside_target — written only
// when true.
//
// Positive: the campaign store IS inside the pinned target, pinned for real.
// Negative: an ordinary pin (store and target as siblings) records nothing,
// so the section prints nothing at all.
func TestScorecardContainmentWarning(t *testing.T) {
	// Negative first: siblings — no containment, and no section in text or
	// in --json, with or without the surface walk.
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t.TempDir()
	scWrite(t, tgt, "A.sol", "contract A {}\n")
	if code, _, errS := run(t, "--root", root, "snap", cid, tgt); code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}
	code, out, errS := run(t, "--root", root, "scorecard", cid, "--no-surface")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if strings.Contains(out, "containment") {
		t.Fatalf("containment section printed with no containment:\n%s", out)
	}
	code, out, errS = run(t, "--root", root, "scorecard", cid, "--json",
		"--no-surface")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	if got := keyOrder(t, out); fmt.Sprint(got) !=
		fmt.Sprint([]string{"campaign", "findings", "process", "eval"}) {
		t.Fatalf("containment key present without containment: %v\n%s", got, out)
	}

	// Positive: the campaign store is a CHILD of the pinned target.
	outer := t.TempDir()
	insideRoot := filepath.Join(outer, "store")
	cid2 := initOne(t, insideRoot)
	scWrite(t, outer, "B.sol", "contract B {}\n")
	if code, _, errS := run(t, "--root", insideRoot, "snap", cid2,
		outer); code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}
	code, out, errS = run(t, "--root", insideRoot, "scorecard", cid2,
		"--no-surface")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "containment\n") ||
		!strings.Contains(out, "WARNING: the campaign directory is inside "+
			"the pinned target tree; its own notes are part of what an agent "+
			"could read as target source") {
		t.Fatalf("containment warning missing:\n%s", out)
	}
	// Containment is reported even when the surface walk was skipped.
	if strings.Contains(out, "\nsurface\n") {
		t.Fatalf("--no-surface printed the surface section:\n%s", out)
	}

	code, out, errS = run(t, "--root", insideRoot, "scorecard", cid2, "--json",
		"--no-surface")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	got := keyOrder(t, out)
	want := []string{"campaign", "findings", "process", "eval",
		"containment"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("containment key order %v, want %v:\n%s", got, want, out)
	}
	if !strings.Contains(out, `"contained": true`) {
		t.Fatalf("containment object missing:\n%s", out)
	}
}

// scGoldWrite writes a one-row operator gold pack for program/class and
// returns the file path plus the sha256 of the exact bytes written. With
// withSidecar it also writes the store-convention sidecar
// (<stem>.sha256, the two-token `sha256sum` form `--gold` must accept).
func scGoldWrite(t *testing.T, dir, program, class string, withSidecar bool) (string, string) {
	t.Helper()
	row := map[string]any{
		"case_id":   "CASE-00000000000e",
		"source":    map[string]any{"dataset": "manual", "record_id": "MORPH-H-02"},
		"partition": "held-out",
		"program":   map[string]any{"program": program},
		"gold": map[string]any{
			"outcome":          "confirmed-exploitable",
			"bug_class":        class,
			"bug_class_accept": []string{"logic-error"},
			"root_cause":       "the previous state root is never checked before commit",
			"locations": []map[string]any{
				{"file": "contracts/contracts/l1/rollup/Rollup.sol", "line": 209}},
		},
		"code":           map[string]any{"repo": "https://github.com/morph-l2/morph"},
		"created_at":     "2026-09-01T00:00:00Z",
		"schema_version": 2,
	}
	data, err := json.MarshalIndent([]any{row}, "", "  ")
	if err != nil {
		t.Fatalf("marshal gold pack: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(dir, "gold-cases.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write gold pack: %v", err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if withSidecar {
		sc := strings.TrimSuffix(path, ".json") + ".sha256"
		if err := os.WriteFile(sc, []byte(digest+"  gold-cases.json\n"), 0o644); err != nil {
			t.Fatalf("write sidecar: %v", err)
		}
	}
	return path, digest
}

// TestScorecardGoldPack: --gold REPLACES the embedded suite (it is the
// answer key for a held-out target the shipped binary cannot carry), prints
// the verified provenance line, and scores the pack's case. Without the
// flag the section is exactly what it was: the embedded suite, which matches
// no Morph case, and no provenance key or line anywhere.
func TestScorecardGoldPack(t *testing.T) {
	c, root := adjudicateCampaign(t, "Morph")
	if fid := adjudicateFinding(t, c, "dos-griefing", "src/Rollup.sol"); fid == "" {
		t.Fatal("fixture finding has no id")
	}
	path, digest := scGoldWrite(t, t.TempDir(), "Morph", "dos-griefing", true)

	code, out, errS := run(t, "--root", root, "scorecard", c.CampaignID,
		"--gold", path)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	for _, want := range []string{
		"  gold pack: " + path + " (sha256 " + digest[:12] + ")\n",
		"  gold cases: 1\n",
		"  recall: 1/1 (95% CI 20.7–100.0%)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no gold case matches") {
		t.Errorf("the pack matched the program; no refusal may print:\n%s", out)
	}

	// No flag: the embedded suite, no provenance line.
	code, out, errS = run(t, "--root", root, "scorecard", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if strings.Contains(out, "gold pack") || strings.Contains(out, "sha256") {
		t.Errorf("provenance printed without --gold:\n%s", out)
	}
	if !strings.Contains(out, "no gold case matches program Morph") {
		t.Errorf("embedded suite must match no Morph case:\n%s", out)
	}

	// JSON: gold_pack is presence-gated on the flag, exactly like every
	// other optional key here.
	code, out, errS = run(t, "--root", root, "scorecard", c.CampaignID,
		"--json", "--gold", path)
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	eval, _ := doc["eval"].(map[string]any)
	gp, _ := eval["gold_pack"].(map[string]any)
	if gp == nil {
		t.Fatalf("gold_pack missing with --gold:\n%s", out)
	}
	if gp["path"] != path || gp["sha256"] != digest || gp["verified"] != true {
		t.Fatalf("gold_pack = %v", gp)
	}
	code, out, errS = run(t, "--root", root, "scorecard", c.CampaignID, "--json")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	if strings.Contains(out, "gold_pack") {
		t.Errorf("gold_pack present without --gold:\n%s", out)
	}
}

// TestScorecardGoldPackUnverifiedAndRefused: a pack with no sidecar loads
// and SAYS it is unverified; a drifted sidecar and a non-array file are
// refused, exit 1, with a message an operator can act on.
func TestScorecardGoldPackUnverifiedAndRefused(t *testing.T) {
	c, root := adjudicateCampaign(t, "Morph")

	dir := t.TempDir()
	path, _ := scGoldWrite(t, dir, "Morph", "dos-griefing", false)
	code, out, errS := run(t, "--root", root, "scorecard", c.CampaignID,
		"--gold", path)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "  gold pack: "+path+
		" (unverified - no sha256 sidecar found)\n") {
		t.Fatalf("missing unverified provenance:\n%s", out)
	}

	// A drifted sidecar prints BOTH hashes and refuses the score.
	dir2 := t.TempDir()
	p2, digest := scGoldWrite(t, dir2, "Morph", "dos-griefing", true)
	zeros := strings.Repeat("0", 64)
	sc := strings.TrimSuffix(p2, ".json") + ".sha256"
	if err := os.WriteFile(sc, []byte(zeros+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS = run(t, "--root", root, "scorecard", c.CampaignID,
		"--gold", p2)
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q, want a refusal", code, out)
	}
	for _, want := range []string{"does not match its sidecar", zeros, digest} {
		if !strings.Contains(errS, want) {
			t.Fatalf("stderr %q does not name %q", errS, want)
		}
	}

	// A pack that is not a JSON array of objects is refused too.
	notArray := filepath.Join(t.TempDir(), "pack.json")
	if err := os.WriteFile(notArray, []byte(`{"case_id":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS = run(t, "--root", root, "scorecard", c.CampaignID,
		"--gold", notArray)
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q, want a refusal", code, out)
	}
	if !strings.Contains(errS, "must be a JSON array of evaluation_case objects") {
		t.Fatalf("stderr %q", errS)
	}

	// A missing file names the path.
	missing := filepath.Join(t.TempDir(), "absent.json")
	code, out, errS = run(t, "--root", root, "scorecard", c.CampaignID,
		"--gold", missing)
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q, want a refusal", code, out)
	}
	if !strings.Contains(errS, missing) ||
		!strings.Contains(errS, "is not readable") {
		t.Fatalf("stderr %q", errS)
	}
}
