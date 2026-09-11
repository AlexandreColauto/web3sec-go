package risk

// calibration_test.go — G3 acceptance priors: failing-first tests for
// AcceptancePriors over a synthetic eval store (WEBV2_EVAL_DIR seam).

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/evalstore"
	ingestpkg "websec/internal/ingest"
	"websec/internal/validation"
	"websec/internal/wilson"
)

// seedCase writes one adjudicated row through evalstore.AddCase — the only
// production path into the store — with a minimal-valid doc shaped like
// assets/evalsuite/cases.json (source/program/code/created_at via
// defaults, gold{outcome,bug_class,root_cause} explicit).
func seedCase(t *testing.T, class, outcome, recordID string) {
	t.Helper()
	doc := validation.VObj(
		validation.KV{K: "source", V: validation.VObj(
			validation.KV{K: "dataset", V: validation.VStr("manual")},
			validation.KV{K: "record_id", V: validation.VStr(recordID)},
		)},
		validation.KV{K: "program", V: validation.VObj(
			validation.KV{K: "program", V: validation.VStr("PriorTestProgram")},
		)},
		validation.KV{K: "gold", V: validation.VObj(
			validation.KV{K: "outcome", V: validation.VStr(outcome)},
			validation.KV{K: "bug_class", V: validation.VStr(class)},
			validation.KV{K: "root_cause", V: validation.VStr(
				"synthetic root cause for prior calibration testing")},
		)},
		validation.KV{K: "code", V: validation.VObj(
			validation.KV{K: "repo", V: validation.VStr("internal://test")},
		)},
	)
	if _, err := evalstore.AddCase(doc); err != nil {
		t.Fatalf("seed %s/%s: %v", class, outcome, err)
	}
}

// appendUnadjudicated appends rows AddCase would (rightly) reject: the
// schema enums gold.outcome to the six adjudicated values, so a null,
// missing, or "unknown" outcome can only reach the store outside add_case
// (a hand edit the sidecar would flag in production; here a throwaway
// TempDir store). LoadCases reads them fine — and the prior must skip
// every one of them.
func appendUnadjudicated(t *testing.T, dir string, rows ...map[string]any) {
	t.Helper()
	p := filepath.Join(dir, evalstore.CasesName)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("decode cases: %v", err)
	}
	arr = append(arr, rows...)
	out, err := json.Marshal(arr)
	if err != nil {
		t.Fatalf("encode cases: %v", err)
	}
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatalf("write cases: %v", err)
	}
}

// TestOutcomeVocabularySync pins the prior's local vocabulary to its
// authority: a new outcome added to ingest.Outcomes without updating the
// prior fails here instead of silently changing every n. The import lives
// in the TEST only — calibration.go must never import ingest (test cycle:
// ingest -> sharedmem -> chainengine, whose test binaries import risk).
func TestOutcomeVocabularySync(t *testing.T) {
	if len(adjudicatedOutcomes) != len(ingestpkg.Outcomes) {
		t.Fatalf("vocab drift: risk %q vs ingest %q",
			adjudicatedOutcomes, ingestpkg.Outcomes)
	}
	seen := map[string]bool{}
	for _, o := range adjudicatedOutcomes {
		seen[o] = true
	}
	for _, o := range ingestpkg.Outcomes {
		if !seen[o] {
			t.Fatalf("vocab drift: ingest outcome %q missing from prior", o)
		}
	}
	if !seen[AcceptedOutcome] {
		t.Fatalf("accepted outcome %q not adjudicated", AcceptedOutcome)
	}
}

func TestPriorWilsonAndFallback(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WEBV2_EVAL_DIR", dir)
	// 12 oracle-manipulation: 6 accepted + 6 other-adjudicated.
	for i := 0; i < 6; i++ {
		seedCase(t, "oracle-manipulation", "confirmed-exploitable",
			"oracle-accept-"+string(rune('a'+i)))
	}
	negatives := []string{"disproved", "out-of-scope", "duplicate",
		"economic-no-go", "confirmed-not-exploitable", "disproved"}
	for i, o := range negatives {
		seedCase(t, "oracle-manipulation", o,
			"oracle-neg-"+string(rune('a'+i)))
	}
	// 3 reentrancy: 2 accepted (below DefaultMinN => fallback).
	seedCase(t, "reentrancy", "confirmed-exploitable", "reent-a")
	seedCase(t, "reentrancy", "confirmed-exploitable", "reent-b")
	seedCase(t, "reentrancy", "duplicate", "reent-c")
	// 1 unadjudicated case: outcome null => EXCLUDED from n.
	appendUnadjudicated(t, dir, map[string]any{
		"gold": map[string]any{"outcome": nil, "bug_class": "reentrancy"},
	})

	priors, global, err := AcceptancePriors(DefaultMinN)
	if err != nil {
		t.Fatal(err)
	}
	o := priors["oracle-manipulation"]
	if o.N != 12 || o.Fallback {
		t.Fatalf("oracle prior: %+v", o)
	}
	lo, hi := wilson.Interval(6, 12)
	if o.CILo != lo || o.CIHi != hi {
		t.Fatalf("CI must BE the wilson package's number: %+v", o)
	}
	if math.Abs(o.Rate-0.5) > 1e-12 {
		t.Fatalf("rate: %v", o.Rate)
	}
	if strings.Contains(o.Render(), "fallback") {
		t.Fatalf("exact class must not say fallback: %q", o.Render())
	}
	r := priors["reentrancy"]
	if !r.Fallback || r.N != 3 {
		t.Fatalf("n=3 must fall back: %+v", r)
	}
	if r.Rate != global.Rate {
		t.Fatal("fallback carries global numbers")
	}
	if r.CILo != global.CILo || r.CIHi != global.CIHi {
		t.Fatalf("fallback carries global numbers: %+v vs %+v", r, global)
	}
	if r.GlobalN != global.N || global.N != 15 {
		t.Fatalf("global n: %+v", global)
	}
	if global.Fallback {
		t.Fatalf("global is always exact: %+v", global)
	}
	if glo, ghi := wilson.Interval(8, 15); global.CILo != glo || global.CIHi != ghi {
		t.Fatalf("global CI must BE wilson's: %+v", global)
	}
	if !strings.Contains(r.Render(), "(fallback: global, n=3)") {
		t.Fatalf("fallback must SAY SO: %q", r.Render())
	}
	if n, skipped, err := AdjudicatedStats(); err != nil || n != 15 || skipped != 1 {
		t.Fatalf("stats: n=%d skipped=%d err=%v", n, skipped, err)
	}
}

func TestUnadjudicatedExcluded(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WEBV2_EVAL_DIR", dir)
	seedCase(t, "reentrancy", "confirmed-exploitable", "only-adjudicated")
	// Every outcome outside the Outcomes vocabulary contributes to NO n:
	// null, missing, and an unknown string, spread over two classes.
	appendUnadjudicated(t, dir,
		map[string]any{
			"gold": map[string]any{"outcome": nil, "bug_class": "reentrancy"},
		},
		map[string]any{
			"gold": map[string]any{"bug_class": "oracle-manipulation"},
		},
		map[string]any{
			"gold": map[string]any{
				"outcome": "unknown", "bug_class": "oracle-manipulation"},
		},
	)
	priors, global, err := AcceptancePriors(DefaultMinN)
	if err != nil {
		t.Fatal(err)
	}
	if len(priors) != 1 {
		t.Fatalf("unadjudicated rows must seed no class: %v", priors)
	}
	if global.N != 1 {
		t.Fatalf("global n: %+v", global)
	}
	if n, skipped, err := AdjudicatedStats(); err != nil || n != 1 || skipped != 3 {
		t.Fatalf("stats: n=%d skipped=%d err=%v", n, skipped, err)
	}
}
