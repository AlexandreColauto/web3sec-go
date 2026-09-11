package evalscore

import (
	"path/filepath"
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
		p := filepath.Join(c.FindingsDir, "F-e2e00000000"+string(rune('0'+i))+".json")
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
