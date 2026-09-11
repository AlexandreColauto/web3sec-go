package cli

// G15 PoC quality gate at mint (Task 23): --verify-reruns flag plumbing,
// the docker-absent warning line, and the default-OFF byte law at the CLI.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/reproduction"
	"websec/internal/state"
	"websec/internal/validation"
)

// g15Stub installs a stub rerun seam for one CLI mint; nil restores.
func g15Stub(t *testing.T,
	fn func(*state.Campaign, string, string) (string, int, []byte, error)) {
	t.Helper()
	reproduction.SetRerunExecutor(fn)
	t.Cleanup(func() { reproduction.SetRerunExecutor(nil) })
	if reproduction.TakeMintNotice() != "" {
		t.Fatal("stale mint notice leaked into the test")
	}
}

func g15MintItem(t *testing.T, f *t20Fixture, execID string) validation.Value {
	t.Helper()
	finding, err := findings.LoadFinding(f.c, f.fid)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range objAt(finding, "evidence").A {
		if objStr(e, "artifact_id") == execID {
			return e
		}
	}
	t.Fatalf("no evidence item for %s", execID)
	return validation.VNull()
}

// Flag ON with a deterministic stub: the minted line is unchanged and
// the item carries the rerun verdict with the rerun exec ids as the
// audit join.
func TestMintVerifyRerunsDeterministic(t *testing.T) {
	f := t20Setup(t)
	ids := []string{"EXEC-cli-rerun-1", "EXEC-cli-rerun-2",
		"EXEC-cli-rerun-3"}
	n := 0
	g15Stub(t,
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			id := ids[n]
			n++
			return id, 0, []byte("PASS: poc\n"), nil
		})
	code, out, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", f.pass, "--description", "unit PoC drains",
		"--tier", "T2", "--verify-reruns")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := f.fid + ": minted default evidence from " + f.pass +
		" — level E4\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want none", errS)
	}
	wantRuns := "3/3 (execs EXEC-cli-rerun-1,EXEC-cli-rerun-2," +
		"EXEC-cli-rerun-3)"
	if got := objStr(g15MintItem(t, f, f.pass), "reruns"); got != wantRuns {
		t.Fatalf("reruns = %q, want %q", got, wantRuns)
	}
}

// Flag ON with docker absent: mint succeeds (fail-open), the item reads
// not-applicable, and the brief warning line hits stderr.
func TestMintVerifyRerunsNotApplicable(t *testing.T) {
	f := t20Setup(t)
	g15Stub(t,
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			return "", 0, nil, reproduction.ErrRerunUnavailable
		})
	code, out, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", f.pass, "--description", "unit PoC drains",
		"--tier", "T2", "--verify-reruns")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := f.fid + ": minted default evidence from " + f.pass +
		" — level E4\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
	wantErr := "warning: reruns not-applicable (container runtime " +
		"unavailable) \u2014 evidence minted without variance data\n"
	if errS != wantErr {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, wantErr)
	}
	if got := objStr(g15MintItem(t, f, f.pass), "reruns"); got !=
		"not-applicable" {
		t.Fatalf("reruns = %q, want not-applicable", got)
	}
}

// Flag OFF (the default): no reruns key is gained and the t20 fixture
// (no snapshot pin) gains no fork_stale key either — the mint path is
// byte-identical to today.
func TestMintDefaultOffGainsNoKeys(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", f.pass, "--description", "unit PoC drains",
		"--tier", "T2")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	item := g15MintItem(t, f, f.pass)
	for _, kv := range item.O {
		if kv.K == "reruns" || kv.K == "fork_stale" {
			t.Fatalf("flag OFF gained %q: %q", kv.K, kv.V.S)
		}
	}
}

// The flag must not leak between in-process commands: ON then OFF mints
// a second type with no reruns key.
func TestMintVerifyRerunsDoesNotLeak(t *testing.T) {
	f := t20Setup(t)
	g15Stub(t,
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			return "EXEC-cli-rerun-1", 0, []byte("PASS: poc\n"), nil
		})
	if code, _, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", f.pass, "--description", "unit PoC drains",
		"--tier", "T2", "--verify-reruns"); code != 0 {
		t.Fatalf("first mint exit %d: %q", code, errS)
	}
	if code, _, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", f.pass, "--description", "differential pass",
		"--tier", "T2", "--type", "unit-test"); code != 0 {
		t.Fatalf("second mint exit %d: %q", code, errS)
	}
	finding, err := findings.LoadFinding(f.c, f.fid)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range objAt(finding, "evidence").A {
		if objStr(e, "type") != "unit-test" {
			continue
		}
		for _, kv := range e.O {
			if kv.K == "reruns" {
				t.Fatalf("flag leaked into the second mint: %q", kv.V.S)
			}
		}
	}
}

// Help advertises the flag.
func TestMintHelpVerifyReruns(t *testing.T) {
	code, out, errS := run(t, "mint", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out, "--verify-reruns") {
		t.Fatalf("help lacks --verify-reruns:\n%s", out)
	}
}
