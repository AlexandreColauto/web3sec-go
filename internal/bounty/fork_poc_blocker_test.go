package bounty

// D8 — the gate blocker must carry the precise fork-PoC reason.
//
// check11 already asks fork_poc_status for the exact status, but the blocker
// discarded it for a constant string, so `gate` could not tell "no fork
// evidence at all" from "fork evidence exists but the sequence PoC never ran".
// The reproduction (C-21dd6a7642 / F-6791c9aee0b5) printed the constant while
// `prove` printed the sequence-coverage reason below.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// forkPocSequenceReason is the status prove prints for the D8 reproduction:
// fork-level evidence exists but no fork-runner exec verified coverage of the
// multi-step sequence.
const forkPocSequenceReason = "fork-level evidence exists but no fork-runner " +
	"exec has verified sequence coverage — run a T4 sequence PoC (webv2 " +
	"sequence run); a single-call fork PoC cannot prove this multi-step exploit"

// forkPocNoEvidenceReason is the status of a finding with no fork-level
// evidence at all — the other half of the distinction the blocker now keeps.
const forkPocNoEvidenceReason = "no fork-level evidence (E5/E6) — run the PoC " +
	"on the pinned mainnet fork (webv2 exec --profile fork-runner) and mint it"

// TestForkPocBlockerCarriesStatusReason: on failure the blocker repeats the
// status seam's reason verbatim (prefix + why), and falls back to the single
// constant only when the seam gave no reason. The check row itself keeps the
// raw reason either way.
func TestForkPocBlockerCarriesStatusReason(t *testing.T) {
	cases := []struct {
		name    string
		forkWhy string
		// wantPrecise: the seam gave a reason, so the blocker repeats it.
		wantPrecise bool
	}{
		{
			name:        "fork-level evidence, no verified sequence coverage",
			forkWhy:     forkPocSequenceReason,
			wantPrecise: true,
		},
		{
			name:        "no fork evidence at all",
			forkWhy:     forkPocNoEvidenceReason,
			wantPrecise: true,
		},
		{
			name:    "status fails without a reason of its own",
			forkWhy: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, fid := bountyFixture(t)
			stub := submissionReadySeamsFor("PRC-abc123")
			stub.forkOK = false
			stub.forkWhy = tc.forkWhy
			installSeams(t, stub)

			result, err := EvaluateBountyGate(c, fid, testPolicy(), true)
			if err != nil {
				t.Fatal(err)
			}
			row := checkRow(result, "mainnet-fork-poc")
			if row.Kind == validation.Null {
				t.Fatal("no mainnet-fork-poc row in policy_checks")
			}
			if got := validation.ObjStr(row, "result"); got != "fail" {
				t.Errorf("mainnet-fork-poc result = %s, want fail", got)
			}
			if got := validation.ObjStr(row, "detail"); got != tc.forkWhy {
				t.Errorf("check detail = %q, want the seam's reason %q",
					got, tc.forkWhy)
			}
			blocker, ok := forkPocBlocker(result)
			if !ok {
				t.Fatalf("no fork blocker in %s",
					validation.CanonCompact(validation.ObjAt(result, "blocking_reasons")))
			}
			if tc.wantPrecise {
				if !strings.HasPrefix(blocker, "no proven mainnet fork PoC: ") {
					t.Errorf("blocker = %q, want the precise prefix", blocker)
				}
				if !strings.Contains(blocker, tc.forkWhy) {
					t.Errorf("blocker %q does not carry the reason %q verbatim",
						blocker, tc.forkWhy)
				}
			} else if blocker != forkPocBlockerFallback {
				t.Errorf("blocker = %q, want the fallback constant", blocker)
			}
			if ready := validation.ObjAt(result, "submission_ready"); pyTruthyBigNonEmpty(ready) {
				t.Errorf("submission_ready = True with the fork PoC unproven")
			}
		})
	}
}

// forkPocBlocker is the one blocking reason about the fork PoC.
func forkPocBlocker(result validation.Value) (string, bool) {
	for _, r := range validation.ObjAt(result, "blocking_reasons").A {
		if r.Kind == validation.Str && strings.Contains(r.S, "mainnet fork PoC") {
			return r.S, true
		}
	}
	return "", false
}

// TestForkPocWaiverBlockerUnchanged: the waived path is untouched by D8 — the
// waiver passes the check and appends no blocker at all, precise reason or
// not.
func TestForkPocWaiverBlockerUnchanged(t *testing.T) {
	c, fid := bountyFixture(t)
	stub := submissionReadySeamsFor("PRC-abc123")
	stub.forkOK = false
	stub.forkWhy = forkPocSequenceReason
	stub.waivers = []validation.Value{validation.VObj(
		kv("stage", validation.VStr("mainnet-fork-poc")),
		kv("subject", validation.VStr(fid)),
		kv("reason", validation.VStr(
			"fork runner unavailable for this campaign's RPC")),
		kv("actor", validation.VStr("alice")),
	)}
	installSeams(t, stub)

	result, err := EvaluateBountyGate(c, fid, testPolicy(), true)
	if err != nil {
		t.Fatal(err)
	}
	row := checkRow(result, "mainnet-fork-poc")
	if row.Kind == validation.Null {
		t.Fatal("no mainnet-fork-poc row in policy_checks")
	}
	if got := validation.ObjStr(row, "result"); got != "pass" {
		t.Errorf("waived mainnet-fork-poc result = %s, want pass", got)
	}
	if got := validation.ObjStr(row, "detail"); !strings.HasPrefix(got, "waived by alice: ") {
		t.Errorf("waived detail = %q, want the waiver's provenance", got)
	}
	if blocker, ok := forkPocBlocker(result); ok {
		t.Errorf("waived check appended the blocker %q: %s", blocker,
			validation.CanonCompact(validation.ObjAt(result, "blocking_reasons")))
	}
	if ready := validation.ObjAt(result, "submission_ready"); !pyTruthyBigNonEmpty(ready) {
		t.Errorf("submission_ready = %s, want True (the waiver answered the "+
			"fork PoC)", validation.PyRepr(ready))
	}
}
