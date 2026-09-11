package reproduction

// G15 PoC quality gate at mint (Task 23): 3x-rerun variance + fork-age
// advisories, fail-open by construction. The rerun seam is stubbed here
// (flaky/deterministic/unavailable); the snapshot clock is pinned with
// explicit fork_timestamp/started_at strings, never the wall clock.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

const g15Stdout = "Suite result: ok. 1 passed; 0 failed\n"
const g15Command = "forge test --match-test test_poc"

// g15Pin pins a source snapshot and returns its id + created_at.
func g15Pin(t *testing.T, c *state.Campaign) (string, string) {
	t.Helper()
	target := filepath.Join(t.TempDir(), "t")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V { function f() external {} }"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.PinSourceSnapshot(c, target, nil, nil)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	return objStr(snap, "snapshot_id"), objStr(snap, "created_at")
}

// g15Chain attaches a chain pin carrying fork_block + fork_timestamp.
// Empty forkTS attaches a chain WITHOUT fork_timestamp (null-timestamp
// case); attach=false leaves the snapshot chainless (null-chain case).
func g15Chain(t *testing.T, c *state.Campaign, sid, forkTS string,
	attach bool) {
	t.Helper()
	if !attach {
		return
	}
	chain := validation.VObj(
		kv("network", validation.VStr("ethereum-mainnet")),
		kv("chain_id", validation.VInt(1)),
		kv("fork_block", validation.VInt(23456789)),
	)
	if forkTS != "" {
		chain = setKey(chain, "fork_timestamp", validation.VStr(forkTS))
	}
	if _, err := snapshot.AttachChainPin(c, sid, chain); err != nil {
		t.Fatalf("chain pin: %v", err)
	}
}

// g15Mint ingests, registers a passing exec with an explicit started_at,
// records the T2 attempt and mints. It returns the minted evidence item.
func g15Mint(t *testing.T, c *state.Campaign, startedAt string) validation.Value {
	t.Helper()
	fid := integrityHypo(t, c, "reentrancy")
	opts := sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: g15Command,
		ReportedBy: "operator", ExitStatus: 0, FindingID: optStr(fid),
		StdoutText: g15Stdout,
	}
	if startedAt != "" {
		opts.StartedAt = &startedAt
	}
	rec, err := sandbox.RegisterExec(c, opts)
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	execID := objStr(rec, "exec_id")
	tier := "T2"
	if _, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: &execID, Tier: &tier}); err != nil {
		t.Fatal(err)
	}
	out, err := MintReproEvidence(c, fid, execID, "drains via reentry",
		&tier, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range objAt(out, "evidence").A {
		if objStr(e, "artifact_id") == execID {
			return e
		}
	}
	t.Fatal("minted item missing")
	return validation.VNull()
}

// g15Seam installs a stub rerunExecutor; the restore runs on cleanup.
func g15Seam(t *testing.T,
	fn func(*state.Campaign, string, string) (int, []byte, error)) *int {
	t.Helper()
	prev := rerunExecutor
	calls := 0
	rerunExecutor = func(c *state.Campaign, profile,
		command string) (int, []byte, error) {
		calls++
		return fn(c, profile, command)
	}
	t.Cleanup(func() { rerunExecutor = prev })
	return &calls
}

// g15Flag sets VerifyReruns for the test; the restore runs on cleanup.
func g15Flag(t *testing.T, on bool) {
	t.Helper()
	prev := VerifyReruns
	VerifyReruns = on
	t.Cleanup(func() { VerifyReruns = prev })
}

func g15ItemKeys(e validation.Value) []string {
	keys := make([]string, 0, len(e.O))
	for _, kv := range e.O {
		keys = append(keys, kv.K)
	}
	return keys
}

func g15KeysEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The deterministic half: stubbed 3/3 exit-vector equality mints
// reruns:"3/3" and calls the seam exactly rerunAttempts times.
func TestG15RerunsDeterministic(t *testing.T) {
	c := newCampaign(t, "g15")
	g15Pin(t, c)
	g15Flag(t, true)
	calls := g15Seam(t,
		func(c *state.Campaign, profile, command string) (int, []byte, error) {
			if profile != "docker-networkless" {
				t.Errorf("seam profile = %q", profile)
			}
			if command != g15Command {
				t.Errorf("seam command = %q", command)
			}
			return 0, []byte(g15Stdout), nil
		})
	item := g15Mint(t, c, "")
	if got := objStr(item, "reruns"); got != "3/3" {
		t.Fatalf("reruns = %q, want 3/3", got)
	}
	if *calls != rerunAttempts {
		t.Fatalf("seam calls = %d, want %d", *calls, rerunAttempts)
	}
	if n := TakeMintNotice(); n != "" {
		t.Fatalf("notice = %q, want none", n)
	}
}

// The flaky half: 2/3 exit-vector equality mints reruns:"flaky 2/3".
// The mint still succeeds (fail-open law).
func TestG15RerunsFlaky(t *testing.T) {
	c := newCampaign(t, "g15")
	g15Pin(t, c)
	g15Flag(t, true)
	n := 0
	g15Seam(t,
		func(*state.Campaign, string, string) (int, []byte, error) {
			n++
			if n == 3 {
				return 0, []byte("Suite result: ok. 1 passed; 0 failed\nEXTRA\n"), nil
			}
			return 0, []byte(g15Stdout), nil
		})
	item := g15Mint(t, c, "")
	if got := objStr(item, "reruns"); got != "flaky 2/3" {
		t.Fatalf("reruns = %q, want flaky 2/3", got)
	}
	if n != rerunAttempts {
		t.Fatalf("seam calls = %d, want %d", n, rerunAttempts)
	}
}

// Docker-absent: the seam's sentinel resolves to not-applicable, the mint
// succeeds, and a warning notice is owed to the CLI.
func TestG15RerunsNotApplicable(t *testing.T) {
	c := newCampaign(t, "g15")
	g15Pin(t, c)
	g15Flag(t, true)
	g15Seam(t,
		func(*state.Campaign, string, string) (int, []byte, error) {
			return 0, nil, ErrRerunUnavailable
		})
	item := g15Mint(t, c, "")
	if got := objStr(item, "reruns"); got != "not-applicable" {
		t.Fatalf("reruns = %q, want not-applicable", got)
	}
	if n := TakeMintNotice(); n == "" {
		t.Fatal("docker-absent mint owes the CLI a warning notice")
	}
}

// A wrapped docker-absent error (errors.Is through %w) is the same law.
func TestG15RerunsUnavailableWrapped(t *testing.T) {
	c := newCampaign(t, "g15")
	g15Pin(t, c)
	g15Flag(t, true)
	g15Seam(t,
		func(*state.Campaign, string, string) (int, []byte, error) {
			return 0, nil,
				errors.Join(errors.New("docker info failed"),
					ErrRerunUnavailable)
		})
	item := g15Mint(t, c, "")
	if got := objStr(item, "reruns"); got != "not-applicable" {
		t.Fatalf("reruns = %q, want not-applicable", got)
	}
	_ = TakeMintNotice()
}

// Flag OFF (the default): the seam is never consulted and the item gains
// no reruns key. Fresh pin here so fork_stale stays silent too.
func TestG15RerunsFlagOffSilent(t *testing.T) {
	c := newCampaign(t, "g15")
	sid, _ := g15Pin(t, c)
	execAt := "2026-09-08T12:00:05.000000+00:00"
	g15Chain(t, c, sid, execAt, true) // fork == exec clock: fresh
	g15Flag(t, false)
	consulted := false
	g15Seam(t,
		func(*state.Campaign, string, string) (int, []byte, error) {
			consulted = true
			return 0, []byte(g15Stdout), nil
		})
	item := g15Mint(t, c, execAt)
	if consulted {
		t.Fatal("flag OFF must never consult the rerun seam")
	}
	for _, kv := range item.O {
		if kv.K == "reruns" {
			t.Fatalf("flag OFF gained a reruns key: %q", kv.V.S)
		}
	}
}

// THE byte law: flag OFF on a fresh pin mints the exact pre-G15 key set
// in the exact pre-G15 order — the path is byte-identical.
func TestG15DefaultOffByteIdentity(t *testing.T) {
	c := newCampaign(t, "g15")
	sid, _ := g15Pin(t, c)
	execAt := "2026-09-08T12:00:05.000000+00:00"
	g15Chain(t, c, sid, execAt, true)
	g15Flag(t, false)
	item := g15Mint(t, c, execAt)
	want := []string{"evidence_id", "level", "type", "artifact_id",
		"description", "command", "produced_at", "sandbox_profile",
		"snapshot_id"}
	if got := g15ItemKeys(item); !g15KeysEqual(got, want) {
		t.Fatalf("item keys\n%q\nwant\n%q", got, want)
	}
	if got := objStr(item, "level"); got != "E4" {
		t.Fatalf("level = %q", got)
	}
	if got := objStr(item, "type"); got != "foundry-test" {
		t.Fatalf("type = %q", got)
	}
}

// Stale fork: age beyond forkStaleDays gains the exact brief message.
func TestG15ForkStale(t *testing.T) {
	c := newCampaign(t, "g15")
	sid, _ := g15Pin(t, c)
	forkTS := "2026-08-31T12:00:00.000000+00:00"
	g15Chain(t, c, sid, forkTS, true)
	g15Flag(t, false)
	item := g15Mint(t, c, "2026-09-08T12:00:05.000000+00:00") // 8d later
	want := "snapshot pinned 2026-08-31T12:00:00.000000+00:00 fork_block " +
		"23456789 \u2014 re-pin with snap + re-mint"
	if got := objStr(item, "fork_stale"); got != want {
		t.Fatalf("fork_stale\n%q\nwant\n%q", got, want)
	}
}

// Fresh fork: age within the window gains no key.
func TestG15ForkFreshSilent(t *testing.T) {
	c := newCampaign(t, "g15")
	sid, _ := g15Pin(t, c)
	g15Chain(t, c, sid, "2026-09-08T11:00:00.000000+00:00", true)
	g15Flag(t, false)
	item := g15Mint(t, c, "2026-09-08T12:00:05.000000+00:00")
	for _, kv := range item.O {
		if kv.K == "fork_stale" {
			t.Fatalf("fresh pin gained fork_stale: %q", kv.V.S)
		}
	}
}

// Boundary: exactly forkStaleDays is NOT stale (the law is age > 7 days).
func TestG15ForkBoundaryFresh(t *testing.T) {
	c := newCampaign(t, "g15")
	sid, _ := g15Pin(t, c)
	g15Chain(t, c, sid, "2026-09-01T12:00:05.000000+00:00", true)
	g15Flag(t, false)
	item := g15Mint(t, c, "2026-09-08T12:00:05.000000+00:00")
	for _, kv := range item.O {
		if kv.K == "fork_stale" {
			t.Fatalf("7d-exact pin gained fork_stale: %q", kv.V.S)
		}
	}
}

// Null fork_timestamp on a pinned chain: stale, dated by created_at.
func TestG15ForkNullTimestampStale(t *testing.T) {
	c := newCampaign(t, "g15")
	sid, created := g15Pin(t, c)
	g15Chain(t, c, sid, "", true) // chain pin, no fork_timestamp
	g15Flag(t, false)
	item := g15Mint(t, c, "2026-09-08T12:00:05.000000+00:00")
	want := "snapshot pinned " + created + " fork_block 23456789 \u2014 " +
		"re-pin with snap + re-mint"
	if got := objStr(item, "fork_stale"); got != want {
		t.Fatalf("fork_stale\n%q\nwant\n%q", got, want)
	}
}

// Null chain (source-only pin, the golden shape): stale with the fields
// that DO exist + "unknown" placeholders.
func TestG15ForkNullChainStale(t *testing.T) {
	c := newCampaign(t, "g15")
	_, created := g15Pin(t, c)
	g15Flag(t, false)
	item := g15Mint(t, c, "2026-09-08T12:00:05.000000+00:00")
	want := "snapshot pinned " + created + " fork_block unknown \u2014 " +
		"re-pin with snap + re-mint"
	if got := objStr(item, "fork_stale"); got != want {
		t.Fatalf("fork_stale\n%q\nwant\n%q", got, want)
	}
}

// No source pin at all: nothing to judge freshness against — silent,
// and the mint still succeeds (fail-open).
func TestG15ForkNoPinSilent(t *testing.T) {
	c := newCampaign(t, "g15")
	g15Flag(t, false)
	item := g15Mint(t, c, "2026-09-08T12:00:05.000000+00:00")
	for _, kv := range item.O {
		if kv.K == "fork_stale" {
			t.Fatalf("pinless mint gained fork_stale: %q", kv.V.S)
		}
	}
}

// Schema round-trip: both new optional keys validate against the
// evidence_item definition, and their absence still validates.
func TestG15SchemaRoundTrip(t *testing.T) {
	withBoth := validation.VObj(
		kv("evidence_id", validation.VStr("EV-abc123")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("drains via reentry path")),
		kv("reruns", validation.VStr("flaky 2/3")),
		kv("fork_stale", validation.VStr(
			"snapshot pinned x fork_block unknown \u2014 re-pin with snap + re-mint")),
	)
	if bad, err := validation.ValidateDefinition(withBoth, "finding",
		"evidence_item"); err != nil || bad != nil {
		t.Fatalf("both keys: bad=%v err=%v", bad, err)
	}
	without := validation.VObj(
		kv("evidence_id", validation.VStr("EV-abc123")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("drains via reentry path")),
	)
	if bad, err := validation.ValidateDefinition(without, "finding",
		"evidence_item"); err != nil || bad != nil {
		t.Fatalf("no keys: bad=%v err=%v", bad, err)
	}
	// A live-minted item carrying both advisories validates end to end.
	c := newCampaign(t, "g15")
	sid, _ := g15Pin(t, c)
	g15Chain(t, c, sid, "2026-08-31T12:00:00.000000+00:00", true)
	g15Flag(t, true)
	g15Seam(t,
		func(*state.Campaign, string, string) (int, []byte, error) {
			return 0, []byte(g15Stdout), nil
		})
	live := g15Mint(t, c, "2026-09-08T12:00:05.000000+00:00")
	if objStr(live, "reruns") != "3/3" {
		t.Fatalf("live reruns = %q", objStr(live, "reruns"))
	}
	if !strings.Contains(objStr(live, "fork_stale"), "fork_block 23456789") {
		t.Fatalf("live fork_stale = %q", objStr(live, "fork_stale"))
	}
	if bad, err := validation.ValidateDefinition(live, "finding",
		"evidence_item"); err != nil || bad != nil {
		t.Fatalf("live item: bad=%v err=%v", bad, err)
	}
}

// The stdout hash is the ledger's hash: a stub returning the exact cited
// bytes matches, a stub returning anything else does not.
func TestG15HashIsLedgerHash(t *testing.T) {
	c := newCampaign(t, "g15")
	g15Pin(t, c)
	g15Flag(t, true)
	g15Seam(t,
		func(*state.Campaign, string, string) (int, []byte, error) {
			return 0, []byte(g15Stdout), nil
		})
	item := g15Mint(t, c, "")
	if got := objStr(item, "reruns"); got != "3/3" {
		t.Fatalf("identical bytes must match the ledger hash: %q", got)
	}
	_ = TakeMintNotice()
}

var _ = sandbox.E4_PROFILES // keep the seam-package import honest
