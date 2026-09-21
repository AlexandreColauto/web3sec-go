package cli

// cmd_fact_read_test.go: the deployment-fact record's CLI surface (v1.6 Part
// 8, non-negotiable 5). The happy path is asserted on the exact stdout line;
// both refusals are asserted on the exact stderr text and exit 2, because the
// refusal IS the output an operator reads.

import (
	"testing"

	"websec/internal/validation"
)

// factReadFixture is the shared setup: a campaign with one ingested finding.
func factReadFixture(t *testing.T) (root, cid, fid string) {
	t.Helper()
	c, root := t15Campaign(t, "Acme")
	f := t15Finding(t, c, "a capped vault", "logic-error")
	return root, c.CampaignID, validation.ObjStr(f, "finding_id")
}

func TestFactReadRecordsAPinnedRead(t *testing.T) {
	root, cid, fid := factReadFixture(t)
	code, out, errS := run(t, "--root", root, "fact-read", cid, fid,
		"--command", "cast call 0xC0FFEE 'cap()(uint256)' --block 21000000",
		"--value", "1000000000000000000000", "--block", "21000000")
	if code != 0 {
		t.Fatalf("code = %d (stderr %q)", code, errS)
	}
	want := "fact read on " + fid + " at block 21000000: 1000000000000000000000\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}

func TestFactReadRefusesAnUnpinnedRead(t *testing.T) {
	root, cid, fid := factReadFixture(t)
	code, _, errS := run(t, "--root", root, "fact-read", cid, fid,
		"--command", "cast call 0xC0FFEE 'cap()(uint256)'",
		"--value", "1", "--block", "0")
	want := "a fact read needs a pinned block (--block N): " +
		"an unpinned read is an assumption\n"
	if code != 2 || errS != want {
		t.Fatalf("code = %d stderr = %q, want exit 2 and %q", code, errS, want)
	}
}

func TestFactReadRefusesAMutatingCommand(t *testing.T) {
	root, cid, fid := factReadFixture(t)
	code, _, errS := run(t, "--root", root, "fact-read", cid, fid,
		"--command", "cast send 0xC0FFEE 'drain()'",
		"--value", "0x1", "--block", "21000000")
	want := "fact reads are read-only: \"cast send\" is a write\n"
	if code != 2 || errS != want {
		t.Fatalf("code = %d stderr = %q, want exit 2 and %q", code, errS, want)
	}
}

// TestFactReadAttestsANonEVMRead: an unrecognized command on another chain is
// recordable only with --read-only, and the attestation makes it so — the
// operator is never forced to skip (or fake) a read the framework cannot
// recognize.
func TestFactReadAttestsANonEVMRead(t *testing.T) {
	root, cid, fid := factReadFixture(t)
	cmd := "solana account 0xC0FFEE"
	code, _, errS := run(t, "--root", root, "fact-read", cid, fid,
		"--command", cmd, "--value", "1", "--block", "21000000")
	if code != 2 || errS == "" {
		t.Fatalf("unattested: code = %d stderr = %q, want the exit-2 refusal",
			code, errS)
	}
	code, out, errS := run(t, "--root", root, "fact-read", cid, fid,
		"--command", cmd, "--value", "1", "--block", "21000000", "--read-only")
	if code != 0 {
		t.Fatalf("attested: code = %d (stderr %q)", code, errS)
	}
	want := "fact read on " + fid + " at block 21000000: 1\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}
