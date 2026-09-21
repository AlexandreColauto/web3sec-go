package cli

// cmd_fork_dependence_test.go: the per-hypothesis fork-dependence verb (v1.6
// §2.2). The happy path is asserted on the exact stdout line and the refusals
// on exact stderr text and exit 2, because the refusal IS the output an
// operator reads. The re-set case proves the SECOND event carries the prior
// value: without it a re-set is indistinguishable from a first set, and the
// override rate ("how often was the class prior wrong?") is unmeasurable.

import (
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// forkDependenceFixture is the shared setup: a campaign with one ingested
// finding, plus the open campaign handle the ledger assertions read.
func forkDependenceFixture(t *testing.T) (*state.Campaign, string, string) {
	t.Helper()
	c, root := t15Campaign(t, "Acme")
	f := t15Finding(t, c, "an oracle read", "oracle-manipulation")
	return c, root, validation.ObjStr(f, "finding_id")
}

func TestForkDependenceRecordsAValue(t *testing.T) {
	c, root, fid := forkDependenceFixture(t)
	code, out, errS := run(t, "--root", root, "fork-dependence", c.CampaignID, fid,
		"--set", "none", "--reason", "the harness mocks the feed")
	if code != 0 {
		t.Fatalf("code = %d (stderr %q)", code, errS)
	}
	want := "fork_dependence " + fid + ": none (the harness mocks the feed)\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}

func TestForkDependenceRefusesAGuessAndAnUnknownValue(t *testing.T) {
	c, root, fid := forkDependenceFixture(t)
	code, _, errS := run(t, "--root", root, "fork-dependence", c.CampaignID, fid,
		"--set", "none", "--reason", "")
	want := "fork-dependence requires --reason: an override without a " +
		"recorded reason is a guess\n"
	if code != 2 || errS != want {
		t.Fatalf("reason: code = %d stderr = %q, want exit 2 and %q", code, errS, want)
	}
	code, _, errS = run(t, "--root", root, "fork-dependence", c.CampaignID, fid,
		"--set", "oracle-ish", "--reason", "because")
	want = "fork_dependence must be one of [external-protocol-state " +
		"real-price-feed real-balances-liquidity proxy-implementation none]\n"
	if code != 2 || errS != want {
		t.Fatalf("enum: code = %d stderr = %q, want exit 2 and %q", code, errS, want)
	}
}

func TestForkDependenceResetRecordsThePrior(t *testing.T) {
	c, root, fid := forkDependenceFixture(t)
	for _, v := range []string{"none", "real-price-feed"} {
		if code, _, errS := run(t, "--root", root, "fork-dependence",
			c.CampaignID, fid, "--set", v, "--reason", "because"); code != 0 {
			t.Fatalf("set %s: code = %d (stderr %q)", v, code, errS)
		}
	}
	evs := t17EventsOf(t, c, "finding.fork_dependence_set")
	if len(evs) != 2 {
		t.Fatalf("events = %d, want 2", len(evs))
	}
	data, _ := evs[1]["data"].(map[string]any)
	if got := data["prior_fork_dependence"]; got != "none" {
		t.Fatalf("prior_fork_dependence = %v, want none", got)
	}
}
