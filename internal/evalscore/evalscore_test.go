package evalscore

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// kvE is the package-local keyed KV constructor (the repo's per-package
// test convention: unkeyed cross-package literals are rejected by go vet).
func kvE(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// goldCase builds a synthetic eval gold case: only the join keys ScoreSuite
// reads (case_id, program.program, gold.outcome/bug_class/locations,
// partition) are populated.
func goldCase(id, program, outcome, class string, files ...string) validation.Value {
	locs := make([]validation.Value, 0, len(files))
	for _, f := range files {
		locs = append(locs, validation.VObj(kvE("file", validation.VStr(f))))
	}
	return validation.VObj(
		kvE("case_id", validation.VStr(id)),
		kvE("program", validation.VObj(kvE("program", validation.VStr(program)))),
		kvE("gold", validation.VObj(
			kvE("outcome", validation.VStr(outcome)),
			kvE("bug_class", validation.VStr(class)),
			kvE("locations", validation.VArr(locs...)),
		)),
		kvE("partition", validation.VStr("dev")),
	)
}

// finding builds a synthetic live finding: only the anchor keys ScoreSuite
// reads (root_cause.class, affected[0].path) are populated.
func finding(class, path string) validation.Value {
	return validation.VObj(
		kvE("root_cause", validation.VObj(kvE("class", validation.VStr(class)))),
		kvE("affected", validation.VArr(
			validation.VObj(kvE("path", validation.VStr(path))),
		)),
	)
}

// testSuite is two golds for p1 (one spelled "P1" to lock the
// case-insensitive join) plus one clean-control program.
func testSuite() []validation.Value {
	return []validation.Value{
		goldCase("CASE-A", "p1", "confirmed-exploitable", "access-control", "gold/Vault.sol"),
		goldCase("CASE-B", "P1", "confirmed-exploitable", "reentrancy", "gold/Bank.sol"),
		goldCase("CASE-C", "ctrl", "confirmed-not-exploitable", "reentrancy", "gold/Ctrl.sol"),
	}
}

func mustScore(t *testing.T, suite []validation.Value, liveByProgram map[string][]validation.Value) Report {
	t.Helper()
	return ScoreSuite([]string{"p1", "ctrl"}, liveByProgram, suite)
}

func TestHitMissAndControl(t *testing.T) {
	// findings: both classes found for P1 (file basename match), none for CTRL
	// => recall 2/2, hits on control = its zero-findings rule.
	r := mustScore(t, testSuite(), map[string][]validation.Value{
		"p1":   {finding("access-control", "src/Vault.sol"), finding("reentrancy", "src/Bank.sol")},
		"ctrl": {},
	})
	if r.GoldTotal != 3 || r.Hits != 3 || r.Misses != 0 || r.FP != 0 {
		t.Fatalf("%+v", r)
	}
	if r.RecallLine != "recall: 3/3 (95% CI 43.9–100.0%)" {
		t.Fatalf("recall line: %q", r.RecallLine)
	}
}

func TestMissAndFalsePositive(t *testing.T) {
	r := mustScore(t, testSuite(), map[string][]validation.Value{
		"p1":   {finding("oracle-manipulation", "src/Vault.sol")}, // wrong class => FP
		"ctrl": {finding("reentrancy", "src/Ctrl.sol")},           // control polluted => miss+FP
	})
	// gold: 2 p1 cases (miss,miss) + ctrl (miss) => recall 0/3
	if r.RecallLine != "recall: 0/3 (95% CI 0.0–56.1%)" {
		t.Fatalf("recall: %q", r.RecallLine)
	}
	if r.FP != 2 {
		t.Fatalf("FP: %d", r.FP)
	}
}

func TestPrecisionDenominator(t *testing.T) {
	// precision = hits-with-anchor / live-findings in matched programs;
	// 2 hits + 1 FP => "precision: 2/3 (95% CI 20.8–93.9%)"
	r := mustScore(t, testSuite(), map[string][]validation.Value{
		"p1": {
			finding("access-control", "src/Vault.sol"),
			finding("reentrancy", "src/Bank.sol"),
			finding("oracle-manipulation", "src/Vault.sol"), // FP
		},
		"ctrl": {},
	})
	if r.PrecisionLine != "precision: 2/3 (95% CI 20.8–93.9%)" {
		t.Fatalf("precision: %q", r.PrecisionLine)
	}
	if r.Hits != 3 || r.Misses != 0 || r.FP != 1 {
		t.Fatalf("%+v", r)
	}
}

// campaignFor opens a scratch campaign whose state doc carries the given
// program key.
func campaignFor(t *testing.T, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{CampaignID: "C-evalscoret1"})
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	return c
}

func TestNoMatchReturnsFalse(t *testing.T) {
	_, ok := Score(campaignFor(t, "unrelated-program"), testSuite())
	if ok {
		t.Fatal("no suite case matches the campaign's program — Score must refuse")
	}
}

func TestScoreEndToEnd(t *testing.T) {
	c := campaignFor(t, "e2escoreprogram")
	// One anchored live finding + one FP, written as raw finding docs
	// (LoadLiveFindings reads them without schema validation).
	for i, f := range []validation.Value{
		finding("access-control", "src/Vault.sol"),
		finding("oracle-manipulation", "src/Vault.sol"),
	} {
		// H12: strconv.Itoa, not string(rune('0'+i)) — the rune form is
		// only correct while the index stays below 10.
		p := filepath.Join(c.FindingsDir,
			"F-e2e00000000"+strconv.Itoa(i)+".json")
		if err := validation.WriteJson(p, f, ""); err != nil {
			t.Fatalf("WriteJson: %v", err)
		}
	}
	r, ok := Score(c, []validation.Value{
		goldCase("CASE-A", "E2EScoreProgram", "confirmed-exploitable", "access-control", "gold/Vault.sol"),
	})
	if !ok {
		t.Fatal("one suite case matches the campaign's program — Score must accept")
	}
	if r.GoldTotal != 1 || r.Hits != 1 || r.Misses != 0 || r.FP != 1 {
		t.Fatalf("%+v", r)
	}
	if r.RecallLine != "recall: 1/1 (95% CI 20.7–100.0%)" {
		t.Fatalf("recall: %q", r.RecallLine)
	}
	if r.PrecisionLine != "precision: 1/2 (95% CI 9.5–90.5%)" {
		t.Fatalf("precision: %q", r.PrecisionLine)
	}
}

// goldCaseAccept is goldCase plus the eval spec's bug_class_accept list.
// goldMechCase builds a goldCase with a match_mechanisms list injected into
// its gold object (the builders above predate the mechanism leg).
func goldMechCase(id, program, class, phrase string) validation.Value {
	c := goldCase(id, program, "confirmed-exploitable", class, "gold/Rollup.sol")
	g := obj(c, "gold")
	mech := validation.VObj(g.O...)
	// replace gold with gold + match_mechanisms
	mech.O = append(mech.O, kvE("match_mechanisms",
		validation.VArr(validation.VStr(phrase))))
	out := validation.VObj(c.O...)
	for i, kv := range out.O {
		if kv.K == "gold" {
			out.O[i] = kvE("gold", mech)
		}
	}
	return out
}

// findingMech builds a live finding with root_cause.mechanism populated.
// (Rebuilds the root_cause object rather than appending through obj()'s
// struct-copy view — appending there mutates a local copy only.)
func findingMech(class, path, mech string) validation.Value {
	return validation.VObj(
		kvE("root_cause", validation.VObj(
			kvE("class", validation.VStr(class)),
			kvE("mechanism", validation.VStr(mech)),
		)),
		kvE("affected", validation.VArr(
			validation.VObj(kvE("path", validation.VStr(path))),
		)),
	)
}

func TestAnchorMechanismGate(t *testing.T) {
	gold := goldMechCase("CASE-M", "p1", "denial-of-service",
		"fake prevStateRoot commit")
	g := obj(gold, "gold")

	// The gold mechanism, worded differently but containing the full phrase
	// vocabulary (fake, prevstateroot, commit): anchors. AUTHORING NOTE (the
	// real constraint this rule has): containment is exact-word after
	// identifier folding — inflections (commit/committed, finalize/finality)
	// do NOT match — so phrases must name the mechanism by its load-bearing
	// identifiers and nouns.
	if !anchor(findingMech("denial-of-service", "src/Rollup.sol",
		"a FAKE prevStateRoot commit never reaches finality"), g) {
		t.Fatal("same mechanism, different wording, must anchor")
	}
	// The G-01 vs F-5ba35 near-miss: same class, same file, DIFFERENT
	// mechanism (timeout latch, not fake root): must NOT anchor.
	if anchor(findingMech("denial-of-service", "src/Rollup.sol",
		"challenge window times out and latches nonReqRevert blocking commit"), g) {
		t.Fatal("a same-outcome-different-mechanism near-miss must NOT anchor")
	}
	// No mechanism sentence at all: gated out (the list exists).
	if anchor(finding("denial-of-service", "src/Rollup.sol"), g) {
		t.Fatal("missing root_cause.mechanism must not pass a mechanism gate")
	}
	// Single shared word is not enough ("commit" alone).
	if anchor(findingMech("denial-of-service", "src/Rollup.sol",
		"commit fee recursion drains treasury"), g) {
		t.Fatal("partial vocabulary must not anchor a multi-word phrase")
	}
	// Absent list: every finding above anchors exactly as before (the
	// pre-mechanism join).
	plain := obj(goldCase("CASE-P", "p1", "confirmed-exploitable",
		"denial-of-service", "gold/Rollup.sol"), "gold")
	if !anchor(findingMech("denial-of-service", "src/Rollup.sol",
		"challenge window times out and latches nonReqRevert blocking commit"), plain) {
		t.Fatal("a gold row without match_mechanisms must anchor as before")
	}
	// root:<class> control entry: passes iff the class leg passed — it
	// restates class equality as the mechanism, never weakens the join.
	rootGold := goldMechCase("CASE-R", "p1", "reentrancy", "root:reentrancy")
	if !anchor(findingMech("reentrancy", "src/Rollup.sol", "whatever sentence"),
		obj(rootGold, "gold")) {
		t.Fatal("root:<class> must anchor the matching class")
	}
	// Malformed lists fail CLOSED: wrong key type and empty array anchor
	// nothing, they never fall back to the historical pass.
	empty := goldMechCase("CASE-B", "p1", "reentrancy", "x")
	{
		c := goldCase("CASE-B", "p1", "confirmed-exploitable", "reentrancy", "gold/Rollup.sol")
		g := validation.VObj(obj(c, "gold").O...)
		g.O = append(g.O, kvE("match_mechanisms", validation.VArr()))
		empty = validation.VObj(kvE("case_id", validation.VStr("CASE-B")),
			kvE("program", validation.VObj(kvE("program", validation.VStr("p1")))),
			kvE("gold", g), kvE("partition", validation.VStr("dev")))
	}
	if anchor(findingMech("denial-of-service", "src/Rollup.sol", "anything"), obj(empty, "gold")) {
		t.Fatal("an empty match_mechanisms array must fail closed")
	}
	// Mixed well-formed + junk: per-entry fail-closed — the valid phrase
	// still anchors, the junk entry never creates one.
	mixed := goldCase("CASE-X", "p1", "confirmed-exploitable", "reentrancy", "gold/Rollup.sol")
	{
		g := validation.VObj(obj(mixed, "gold").O...)
		g.O = append(g.O, kvE("match_mechanisms", validation.VArr(
			validation.VStr("mint function unauthenticated"), validation.VStr("  "))))
		mixed = validation.VObj(kvE("case_id", validation.VStr("CASE-X")),
			kvE("program", validation.VObj(kvE("program", validation.VStr("p1")))),
			kvE("gold", g), kvE("partition", validation.VStr("dev")))
	}
	mg := obj(mixed, "gold")
	if !anchor(findingMech("reentrancy", "src/Rollup.sol",
		"the mint function is unauthenticated"), mg) {
		t.Fatal("the valid phrase in a mixed list must still anchor")
	}
	if anchor(findingMech("reentrancy", "src/Rollup.sol",
		"unauthenticated entirely"), mg) {
		t.Fatal("a junk whitespace entry must never create an anchor of its own")
	}

	// The gate moves HIT counts, not only the predicate: the near-miss
	// becomes an unanchored FP and the gold stays a MISS — exactly the
	// scoring honesty the distractor clause exists for.
	r := ScoreSuite([]string{"p1"}, map[string][]validation.Value{
		"p1": {findingMech("denial-of-service", "src/Rollup.sol",
			"challenge window times out and latches nonReqRevert blocking commit")},
	}, []validation.Value{gold})
	if r.Hits != 0 || r.Misses != 1 || r.FP != 1 {
		t.Fatalf("near-miss must score miss+FP, got %+v", r)
	}
}

func goldCaseAccept(id, program, outcome, class string, accept []string,
	files ...string) validation.Value {
	c := goldCase(id, program, outcome, class, files...)
	items := make([]validation.Value, 0, len(accept))
	for _, a := range accept {
		items = append(items, validation.VStr(a))
	}
	g := obj(c, "gold")
	g.O = append(g.O, kvE("bug_class_accept", validation.VArr(items...)))
	c.O = validation.SetOrAppend(c.O, "gold", g)
	return c
}

// TestAnchorBugClassAccept: the class leg of the anchor accepts the gold
// bug_class OR any class the eval spec listed in bug_class_accept, and
// nothing else moves — a class in neither list does not anchor, the
// location suffix rule is unchanged, and a row WITHOUT the list behaves
// exactly as before the key existed.
func TestAnchorBugClassAccept(t *testing.T) {
	caseDoc := goldCaseAccept("CASE-A", "p1", "confirmed-exploitable",
		"dos-griefing", []string{"logic-error", "economic-invariant"},
		"gold/Rollup.sol")
	gold := obj(caseDoc, "gold")
	if !anchor(finding("dos-griefing", "src/Rollup.sol"), gold) {
		t.Fatal("the gold bug_class must still anchor")
	}
	if !anchor(finding("logic-error", "src/Rollup.sol"), gold) {
		t.Fatal("a class ONLY in bug_class_accept must anchor")
	}
	if !anchor(finding("economic-invariant", "src/Rollup.sol"), gold) {
		t.Fatal("every class in bug_class_accept must anchor")
	}
	if anchor(finding("reentrancy", "src/Rollup.sol"), gold) {
		t.Fatal("a class in neither the gold class nor the accept list " +
			"must NOT anchor")
	}
	if anchor(finding("logic-error", "src/Other.sol"), gold) {
		t.Fatal("an accepted class at the wrong path must NOT anchor — the " +
			"accept list is not a weakening of the location rule")
	}
	// The accept leg moves the HIT count, not only the predicate.
	r := ScoreSuite([]string{"p1"}, map[string][]validation.Value{
		"p1": {finding("logic-error", "src/Rollup.sol")},
	}, []validation.Value{caseDoc})
	if r.Hits != 1 || r.RecallLine != "recall: 1/1 (95% CI 20.7–100.0%)" {
		t.Fatalf("accept-list hit not counted: %+v", r)
	}

	// Absent field: equality only, exactly as before.
	plain := obj(goldCase("CASE-B", "p1", "confirmed-exploitable",
		"access-control", "gold/Vault.sol"), "gold")
	if !anchor(finding("access-control", "src/Vault.sol"), plain) {
		t.Fatal("a gold row without bug_class_accept must still anchor its " +
			"own class")
	}
	if anchor(finding("logic-error", "src/Vault.sol"), plain) {
		t.Fatal("a gold row without bug_class_accept must anchor no other " +
			"class")
	}
	if anchor(finding("", "src/Vault.sol"), plain) {
		t.Fatal("a finding with no class must never anchor")
	}

	// Empty list: the key is present but says nothing, so it must behave
	// exactly like absence — equality only. Pinned because an empty list is
	// one schema-legal keystroke away from silently widening the anchor.
	empty := obj(goldCaseAccept("CASE-C", "p1", "confirmed-exploitable",
		"access-control", []string{}, "gold/Vault.sol"), "gold")
	if !anchor(finding("access-control", "src/Vault.sol"), empty) {
		t.Fatal("an empty accept list must still anchor the gold bug_class")
	}
	if anchor(finding("logic-error", "src/Vault.sol"), empty) {
		t.Fatal("an empty accept list must accept no other class")
	}
}

// goldPackRow is one schema-valid evaluation_case row for the loader tests:
// only the fields the schema requires, plus bug_class_accept when given.
func goldPackRow(id, program, class string, accept ...string) validation.Value {
	gold := []validation.KV{
		kvE("outcome", validation.VStr("confirmed-exploitable")),
		kvE("bug_class", validation.VStr(class)),
		kvE("root_cause", validation.VStr("the mechanism, at length")),
	}
	if accept != nil {
		items := make([]validation.Value, 0, len(accept))
		for _, a := range accept {
			items = append(items, validation.VStr(a))
		}
		gold = append(gold, kvE("bug_class_accept", validation.VArr(items...)))
	}
	return validation.VObj(
		kvE("case_id", validation.VStr(id)),
		kvE("source", validation.VObj(
			kvE("dataset", validation.VStr("manual")),
			kvE("record_id", validation.VStr("MORPH-"+id)))),
		kvE("partition", validation.VStr("held-out")),
		kvE("program", validation.VObj(kvE("program", validation.VStr(program)))),
		kvE("gold", validation.VObj(gold...)),
		kvE("code", validation.VObj(kvE("repo",
			validation.VStr("https://github.com/morph-l2/morph")))),
		kvE("created_at", validation.VStr("2026-09-01T00:00:00Z")),
		kvE("schema_version", validation.VInt(2)),
	)
}

// writeGoldPack writes rows as a JSON array and returns the path plus the
// sha256 of the exact bytes written.
func writeGoldPack(t *testing.T, dir, name string, rows ...validation.Value) (string, string) {
	t.Helper()
	p := filepath.Join(dir, name)
	data := []byte(validation.DumpIndentedASCII(validation.VArr(rows...)) + "\n")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	sum := sha256.Sum256(data)
	return p, hex.EncodeToString(sum[:])
}

func TestLoadGoldPackEmptyPathIsNoPack(t *testing.T) {
	cases, err := LoadGoldPack("")
	if err != nil || cases != nil {
		t.Fatalf("empty path: cases=%v err=%v, want nil,nil", cases, err)
	}
}

// TestLoadGoldPackAndSidecar: the two rows load, the rows keep their
// bug_class_accept key, and the stem-named sidecar (cases.json ->
// cases.sha256, the evalstore convention) verifies the pack.
func TestLoadGoldPackAndSidecar(t *testing.T) {
	dir := t.TempDir()
	p, digest := writeGoldPack(t, dir, "morph-gold-cases.json",
		goldPackRow("CASE-00000000000e", "Morph", "dos-griefing",
			"logic-error", "economic-invariant"),
		goldPackRow("CASE-00000000000f", "Morph", "logic-error"))
	if err := os.WriteFile(filepath.Join(dir, "morph-gold-cases.sha256"),
		[]byte(digest+"  morph-gold-cases.json\n"), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	pack, err := OpenGoldPack(p)
	if err != nil {
		t.Fatalf("OpenGoldPack: %v", err)
	}
	if len(pack.Cases) != 2 {
		t.Fatalf("cases = %d, want 2", len(pack.Cases))
	}
	if pack.Digest != digest {
		t.Fatalf("digest = %s, want %s", pack.Digest, digest)
	}
	if !pack.Verified {
		t.Fatal("a matching sidecar must verify the pack")
	}
	got := obj(obj(pack.Cases[0], "gold"), "bug_class_accept")
	if got.Kind != validation.Arr || len(got.A) != 2 {
		t.Fatalf("bug_class_accept not preserved: %v", got)
	}
	// LoadGoldPack is the thin wrapper every caller may use.
	rows, err := LoadGoldPack(p)
	if err != nil || len(rows) != 2 {
		t.Fatalf("LoadGoldPack: rows=%d err=%v", len(rows), err)
	}
}

// TestLoadGoldPackNoSidecarIsUnverified: no sidecar is not a failure — the
// pack loads, and Verified is false so the caller can say so.
func TestLoadGoldPackNoSidecarIsUnverified(t *testing.T) {
	dir := t.TempDir()
	p, digest := writeGoldPack(t, dir, "gold.json",
		goldPackRow("CASE-00000000000e", "Morph", "dos-griefing"))
	pack, err := OpenGoldPack(p)
	if err != nil {
		t.Fatalf("OpenGoldPack: %v", err)
	}
	if pack.Verified {
		t.Fatal("no sidecar: Verified must be false")
	}
	if pack.Digest != digest {
		t.Fatalf("digest = %s, want %s", pack.Digest, digest)
	}
}

// TestLoadGoldPackRefusals pins the fail-loud surface: a bad pack never
// shrinks the answer key silently.
func TestLoadGoldPackRefusals(t *testing.T) {
	dir := t.TempDir()
	good := goldPackRow("CASE-00000000000e", "Morph", "dos-griefing")
	_, goodDigest := writeGoldPack(t, dir, "good.json", good)

	notArray := filepath.Join(dir, "not-array.json")
	if err := os.WriteFile(notArray, []byte(`{"case_id": "x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	notObject := filepath.Join(dir, "not-object.json")
	if err := os.WriteFile(notObject, []byte(`["nope"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	badClass := filepath.Join(dir, "bad-class.json")
	data := []byte(validation.DumpIndentedASCII(validation.VArr(
		goldPackRow("CASE-00000000000e", "Morph", "NOT_A_CLASS"))) + "\n")
	if err := os.WriteFile(badClass, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dupPath, _ := writeGoldPack(t, dir, "dup.json", good, good)

	badSidecar := filepath.Join(dir, "bad-sidecar.json")
	badData := []byte(validation.DumpIndentedASCII(validation.VArr(good)) + "\n")
	if err := os.WriteFile(badSidecar, badData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badSidecar+".sha256",
		[]byte(strings.Repeat("0", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	vec := []struct {
		name string
		path string
		want []string
	}{
		{"missing file", filepath.Join(dir, "nope.json"),
			[]string{"is not readable"}},
		{"not an array", notArray,
			[]string{notArray, "must be a JSON array of evaluation_case " +
				"objects, found an object"}},
		{"element not an object", notObject,
			[]string{"row 0 must be a JSON object, found a string"}},
		{"row fails validation", badClass,
			[]string{"case CASE-00000000000e fails evaluation_case " +
				"validation", "bug_class"}},
		{"duplicate case_id", dupPath,
			[]string{"duplicate case_id CASE-00000000000e"}},
		{"corrupted sidecar", badSidecar,
			[]string{"does not match its sidecar",
				strings.Repeat("0", 64)}},
	}
	for _, tc := range vec {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := LoadGoldPack(tc.path)
			if err == nil {
				t.Fatalf("LoadGoldPack(%s) = %d rows, want an error",
					tc.path, len(rows))
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("error %q does not name %q", err.Error(), w)
				}
			}
		})
	}
	// The corrupted-sidecar message must print BOTH hashes.
	_, err := LoadGoldPack(badSidecar)
	if err == nil || !strings.Contains(err.Error(), goodDigest) {
		t.Fatalf("mismatch error must print the file's own hash: %v", err)
	}
}
