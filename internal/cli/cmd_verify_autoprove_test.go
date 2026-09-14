package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/state"
	"websec/internal/validation"
)

// apReport writes a minimal-but-contractual reports/report.json.
var apSeq int

func apReport(t *testing.T, dir string, over string) string {
	t.Helper()
	apSeq++
	path := filepath.Join(dir, fmt.Sprintf("report-%d.json", apSeq))
	body := `{"schema_version": "1.0", "published": true, ` +
		`"publish_problems": [], "review_independent": true, ` +
		`"capabilities_missing": [], ` +
		`"flags": {"loop_bound": 4, "path_cap": 64, "timeout_ms": 30000}, ` +
		`"property_outcomes": {"total_never_wraps": {"outcome": "PROVEN", ` +
		`"per_rule": {"inv_1": "PROVEN", "inv_1_via_getter": "PROVEN"}}}, ` +
		`"review_findings": []` + over + `}`
	if err := os.WriteFile(path, []byte(body+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func apVerify(t *testing.T, root string, c *state.Campaign, extra ...string) (
	int, string, string) {
	t.Helper()
	base := []string{"--root", root, "verify", c.CampaignID,
		"--autoprove", "INV-1"}
	return run(t, append(base, extra...)...)
}

func TestAutoproveProvenBindsRung(t *testing.T) {
	c, root := mcCamp(t, "ap-proven")
	rep := apReport(t, t.TempDir(), "")
	code, out, errS := apVerify(t, root, c, "--property", "total_never_wraps",
		"--report", rep)
	if code != 0 {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	if !strings.Contains(out, "proved-bounded") ||
		!strings.Contains(out, "k=4") || !strings.Contains(out, "2 rules") {
		t.Fatalf("summary shape: %q", out)
	}
	hv := mcLinkField(t, c, "invariants", "INV-1", "verification", "harness")
	if objStr(hv, "kind") != string(harness.Kind("miniprover")) {
		t.Fatalf("kind: %s", validation.CanonCompact(hv))
	}
	if objStr(hv, "rung") != harness.RungProvedBounded {
		t.Fatalf("rung: %s", objStr(hv, "rung"))
	}
	if objStr(hv, "exec")[:7] != "REPORT-" {
		t.Fatalf("report-only provenance row expected: %q", objStr(hv, "exec"))
	}
	if p := objAt(hv, "proof"); p.Kind != validation.Null {
		t.Fatalf("proof sidecar is minicertora-only: %s",
			validation.CanonCompact(p))
	}
	// The event rode the ledger and the report is a registered artifact.
	if !strings.Contains(mcLinkFieldRaw(t, c), "harness_run") {
		t.Fatal("no harness_run event")
	}
}

func mcLinkFieldRaw(t *testing.T, c *state.Campaign) string {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAutoproveViolatedIsCounterexample(t *testing.T) {
	c, root := mcCamp(t, "ap-violated")
	rep := apReport(t, t.TempDir(), ``)
	// Rewrite the single property's rollup to VIOLATED (real prover
	// semantics: worst-first rollup over per_rule).
	body := strings.Replace(string(mustRead(t, rep)),
		`"outcome": "PROVEN"`, `"outcome": "VIOLATED"`, 1)
	body = strings.Replace(body, `"inv_1_via_getter": "PROVEN"`,
		`"inv_1_via_getter": "VIOLATED"`, 1)
	if err := os.WriteFile(rep, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := apVerify(t, root, c, "--property", "total_never_wraps",
		"--report", rep)
	if code != 0 {
		t.Fatalf("a counterexample MAPS (it is a real result): exit %d err %q",
			code, errS)
	}
	if !strings.Contains(out, "counterexample") ||
		!strings.Contains(out, "inv_1_via_getter") {
		t.Fatalf("must name the refuted rules: %q", out)
	}
	hv := mcLinkField(t, c, "invariants", "INV-1", "verification", "harness")
	if objStr(hv, "rung") != harness.RungCounterexample {
		t.Fatalf("rung: %s", objStr(hv, "rung"))
	}
	if bk := objAt(hv, "bounded_k"); bk.Kind != validation.Null {
		t.Fatal("counterexample carries no bound")
	}
}

func TestAutoproveRefusals(t *testing.T) {
	c, root := mcCamp(t, "ap-refusals")
	dir := t.TempDir()
	cases := []struct {
		name   string
		report string
		args   []string
		want   string
	}{
		{"no property", apReport(t, dir, ""),
			[]string{"--report", apReport(t, dir, "")},
			"attribution is exact-match"},
		{"unknown schema", func() string {
			p := filepath.Join(dir, "u.json")
			os.WriteFile(p, []byte(`{"schema_version": "9.0"}`), 0o644)
			return p
		}(), []string{"--property", "x", "--report", ""}, "not understood"},
		{"not published", func() string {
			p := apReport(t, dir, ``)
			b := strings.Replace(string(mustRead(t, p)),
				`"published": true`, `"published": false`, 1)
			b = strings.Replace(b, `"publish_problems": []`,
				`"publish_problems": ["rule inv_1 unverifiable"]`, 1)
			os.WriteFile(p, []byte(b), 0o644)
			return p
		}(), nil, "did NOT publish"},
		{"suspect review", func() string {
			p := apReport(t, dir, ``)
			b := strings.Replace(string(mustRead(t, p)),
				`"review_findings": []`,
				`"review_findings": [{"property": "total_never_wraps", `+
					`"verdict": "suspect", "reason": "circular body"}]`, 1)
			os.WriteFile(p, []byte(b), 0o644)
			return p
		}(), nil, "most expensive state"},
		{"title absent", apReport(t, dir, ""),
			nil, "is not in this run"}, // --property fixed below to a MISS
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{}, tc.args...)
			switch tc.name {
			case "unknown schema":
				args = []string{"--property", "x", "--report", tc.report}
			case "no property":
				// args already carry --report only
			case "title absent":
				args = []string{"--property", "no_such_property",
					"--report", tc.report}
			default:
				args = []string{"--property", "total_never_wraps",
					"--report", tc.report}
			}
			code, _, errS := apVerify(t, root, c, args...)
			if code != 2 || !strings.Contains(errS, tc.want) {
				t.Fatalf("want exit 2 naming %q, got exit %d err %q",
					tc.want, code, errS)
			}
		})
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
