package chainengine

// T36 testmap: tests/test_review_fixes.py::test_find_chains_is_capped — the
// enumeration guard (MAX_PROPOSALS unique member sets) and the dedup-by-
// member-set invariant it asserts.

import (
	"fmt"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// capFinding is one of the test's 13 capability-sharing hypotheses: F0 grants
// the capability everyone needs; F1..F12 each need it AND grant another.
func capFinding(t *testing.T, c *state.Campaign, i int) validation.Value {
	t.Helper()
	granted, required := []string{"grantA"}, []string{"grantB"}
	if i == 0 {
		granted, required = []string{"grantB"}, nil
	}
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(fmt.Sprintf("cap finding %d", i))),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("description", validation.VStr(
				"capability sharing used for the cap test")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr(fmt.Sprintf("src/F%d.sol", i))),
			kv("function", validation.VStr("f"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.StrArr(granted)),
			kv("required", validation.StrArr(required)))),
	), "code", "test", "")
	if err != nil {
		t.Fatalf("ingest hypothesis %d: %v", i, err)
	}
	return f
}

// TestFindChainsIsCapped is test_find_chains_is_capped: a cycle of
// capability-sharing findings produces combinatorially many simple paths;
// enumeration must stop at MAX_PROPOSALS (not overshoot), and the proposals
// it returns must be MAX_PROPOSALS DISTINCT member sets.
func TestFindChainsIsCapped(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	for i := 0; i < 13; i++ {
		capFinding(t, c, i)
	}
	props, err := FindChains(c, 2)
	if err != nil {
		t.Fatalf("FindChains: %v", err)
	}
	if len(props) != MaxProposals {
		t.Fatalf("proposals = %d, want MAX_PROPOSALS (%d)",
			len(props), MaxProposals)
	}
	keys := map[string]struct{}{}
	for _, p := range props {
		keys[memberKey(strList(listOf(p, "members")))] = struct{}{}
	}
	if len(keys) != MaxProposals {
		t.Fatalf("distinct member sets = %d, want %d", len(keys),
			MaxProposals)
	}
}
