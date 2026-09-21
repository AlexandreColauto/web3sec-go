package cli

// The cross-task wiring guard for the v16_coverage counters. A section unit
// test with a hand-built campaign cannot see the feed validating a drop's
// declaration and then discarding it — that is exactly how the counters read 0
// on every CLI-built campaign until 5630a900. So this drives the real verbs in
// sequence — init, `run <campaign> --feed <drop>`, `audit <campaign> --json` —
// and reads the counters out of the rendered JSON, plus the ledger event the
// counter is supposed to be counting.
//
// It is deliberately independent of the fix wave's own helper
// (requireCoverageDeclared, cmd_run_feed_test.go): it takes the positional form
// of `run`, checks the audit exit code itself, and holds each counter to the
// plan's floor (>= 1) rather than to a count a second accepted drop would move.

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRunFeedAcceptedDropMovesTheCoverageCountersEndToEnd: a drop the shipped
// transport accepts must move model_requests AND requests_declared off zero,
// and the campaign must really carry the model.request event behind them.
func TestRunFeedAcceptedDropMovesTheCoverageCountersEndToEnd(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	drop := inboxDrop(t, c, "discovery",
		discoveryDrop(t, []string{"ART-aaaa1111"}, []string{"ART-aaaa1111"}))
	code, out, errS := run(t, "--root", root, "run", c.CampaignID, "--feed", drop)
	if code != 0 || !strings.Contains(out, "ingested F-") {
		t.Fatalf("run %s --feed: exit %d out=%q err=%q", c.CampaignID, code, out, errS)
	}
	// The counter is not the only witness: the ledger itself carries the
	// declaration the drop made.
	requireOneDeclaredRequest(t, c, "ART-aaaa1111")
	cov := v16CoverageCounters(t, root, c.CampaignID)
	for _, key := range []string{"model_requests", "requests_declared"} {
		if got, ok := cov[key].(float64); !ok || got < 1 {
			t.Fatalf("v16_coverage.%s = %v, want >= 1 after an accepted drop "+
				"(coverage: %v)", key, cov[key], cov)
		}
	}
}

// v16CoverageCounters runs `audit <cid> --json` and returns the rendered
// v16_coverage coverage object, failing loudly if the section is missing.
func v16CoverageCounters(t *testing.T, root, cid string) map[string]any {
	t.Helper()
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if code != 0 {
		t.Fatalf("audit --json exit %d: %s", code, errS)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("audit --json is not JSON: %v\n%s", err, out)
	}
	secs, ok := rep["sections"].(map[string]any)
	if !ok {
		t.Fatalf("audit --json has no sections object: %s", out)
	}
	sec, ok := secs["v16_coverage"].(map[string]any)
	if !ok {
		t.Fatal("audit --json lacks the v16_coverage section")
	}
	cov, ok := sec["coverage"].(map[string]any)
	if !ok {
		t.Fatal("v16_coverage has no coverage object")
	}
	return cov
}
