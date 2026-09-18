package reproduction

// G15 PoC quality gate at mint (Task 23): 3x-rerun variance + fork-age
// advisories, fail-open by construction. The rerun seam is stubbed here
// (flaky/deterministic/unavailable); the snapshot clock is pinned with
// explicit fork_timestamp/started_at strings, never the wall clock.

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
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
	return validation.ObjStr(snap, "snapshot_id"), validation.ObjStr(snap, "created_at")
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
	execID := validation.ObjStr(rec, "exec_id")
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
	for _, e := range validation.ObjAt(out, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == execID {
			return e
		}
	}
	t.Fatal("minted item missing")
	return validation.VNull()
}

// g15Seam installs a stub rerunExecutor; the restore runs on cleanup.
// The stub reports its own synthetic rerun exec ids (rerun-1..3 in run
// order) so the evidence join is exercised end to end.
func g15Seam(t *testing.T,
	fn func(*state.Campaign, string, string) (string, int, []byte, error)) *int {
	t.Helper()
	prev := rerunExecutor
	calls := 0
	rerunExecutor = func(c *state.Campaign, profile,
		command string) (string, int, []byte, error) {
		calls++
		return fn(c, profile, command)
	}
	t.Cleanup(func() { rerunExecutor = prev })
	return &calls
}

// g15IDs returns distinct synthetic rerun exec ids keyed by call count.
func g15IDs(n *int) string {
	return "EXEC-rerun-" + strconv.Itoa(*n)
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
// reruns:"3/3 (execs ...)" with the rerun exec ids as the audit join,
// and calls the seam exactly rerunAttempts times.
func TestG15RerunsDeterministic(t *testing.T) {
	c := newCampaign(t, "g15")
	g15Pin(t, c)
	g15Flag(t, true)
	n := 0
	calls := g15Seam(t,
		func(c *state.Campaign, profile, command string) (string, int, []byte, error) {
			n++
			if profile != "docker-networkless" {
				t.Errorf("seam profile = %q", profile)
			}
			if command != g15Command {
				t.Errorf("seam command = %q", command)
			}
			return g15IDs(&n), 0, []byte(g15Stdout), nil
		})
	item := g15Mint(t, c, "")
	want := "3/3 (execs EXEC-rerun-1,EXEC-rerun-2,EXEC-rerun-3)"
	if got := validation.ObjStr(item, "reruns"); got != want {
		t.Fatalf("reruns = %q, want %q", got, want)
	}
	if *calls != rerunAttempts {
		t.Fatalf("seam calls = %d, want %d", *calls, rerunAttempts)
	}
	if n := TakeMintNotice(); n != "" {
		t.Fatalf("notice = %q, want none", n)
	}
}

// The flaky half: 2/3 exit-vector equality mints reruns:"flaky 2/3
// (execs ...)" — the join lists every successful rerun exec even when
// one disagrees. The mint still succeeds (fail-open law).
func TestG15RerunsFlaky(t *testing.T) {
	c := newCampaign(t, "g15")
	g15Pin(t, c)
	g15Flag(t, true)
	n := 0
	g15Seam(t,
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			n++
			id := g15IDs(&n)
			if n == 3 {
				return id, 0, []byte("Suite result: ok. 1 passed; 0 failed\nEXTRA\n"), nil
			}
			return id, 0, []byte(g15Stdout), nil
		})
	item := g15Mint(t, c, "")
	want := "flaky 2/3 (execs EXEC-rerun-1,EXEC-rerun-2,EXEC-rerun-3)"
	if got := validation.ObjStr(item, "reruns"); got != want {
		t.Fatalf("reruns = %q, want %q", got, want)
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
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			return "", 0, nil, ErrRerunUnavailable
		})
	item := g15Mint(t, c, "")
	if got := validation.ObjStr(item, "reruns"); got != "not-applicable" {
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
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			return "", 0, nil,
				errors.Join(errors.New("docker info failed"),
					ErrRerunUnavailable)
		})
	item := g15Mint(t, c, "")
	if got := validation.ObjStr(item, "reruns"); got != "not-applicable" {
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
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			consulted = true
			return "EXEC-rerun-1", 0, []byte(g15Stdout), nil
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
	if got := validation.ObjStr(item, "level"); got != "E4" {
		t.Fatalf("level = %q", got)
	}
	if got := validation.ObjStr(item, "type"); got != "foundry-test" {
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
	want := "stale: pinned 8 days ago \u2014 snapshot pinned " +
		"2026-08-31T12:00:00.000000+00:00 fork_block 23456789 \u2014 " +
		"re-pin with snap + re-mint"
	if got := validation.ObjStr(item, "fork_stale"); got != want {
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
	want := "stale: fork timestamp missing \u2014 snapshot pinned " +
		created + " fork_block 23456789 \u2014 re-pin with snap + re-mint"
	if got := validation.ObjStr(item, "fork_stale"); got != want {
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
	want := "stale: no snapshot data recorded \u2014 snapshot pinned " +
		created + " fork_block unknown \u2014 re-pin with snap + re-mint"
	if got := validation.ObjStr(item, "fork_stale"); got != want {
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
		kv("reruns", validation.VStr(
			"3/3 (execs EXEC-rerun-1,EXEC-rerun-2,EXEC-rerun-3)")),
		kv("fork_stale", validation.VStr(
			"stale: pinned 8 days ago \u2014 snapshot pinned x fork_block "+
				"unknown \u2014 re-pin with snap + re-mint")),
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
	n := 0
	g15Seam(t,
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			n++
			return g15IDs(&n), 0, []byte(g15Stdout), nil
		})
	live := g15Mint(t, c, "2026-09-08T12:00:05.000000+00:00")
	wantLive := "3/3 (execs EXEC-rerun-1,EXEC-rerun-2,EXEC-rerun-3)"
	if validation.ObjStr(live, "reruns") != wantLive {
		t.Fatalf("live reruns = %q, want %q", validation.ObjStr(live, "reruns"),
			wantLive)
	}
	if !strings.Contains(validation.ObjStr(live, "fork_stale"), "fork_block 23456789") {
		t.Fatalf("live fork_stale = %q", validation.ObjStr(live, "fork_stale"))
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
	n := 0
	g15Seam(t,
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			n++
			return g15IDs(&n), 0, []byte(g15Stdout), nil
		})
	item := g15Mint(t, c, "")
	want := "3/3 (execs EXEC-rerun-1,EXEC-rerun-2,EXEC-rerun-3)"
	if got := validation.ObjStr(item, "reruns"); got != want {
		t.Fatalf("identical bytes must match the ledger hash: %q", got)
	}
	_ = TakeMintNotice()
}

var _ = sandbox.E4_PROFILES // keep the seam-package import honest

// Fix round 1, IMPORTANT-1: null-chain, null-fork_timestamp and genuine
// age>7d render mutually distinguishable reason markers FIRST, with the
// detail text preserved after the marker.
func TestG15ForkStaleReasonsDistinct(t *testing.T) {
	staleOf := func(attach bool, forkTS string) string {
		c := newCampaign(t, "g15")
		sid, _ := g15Pin(t, c)
		g15Chain(t, c, sid, forkTS, attach)
		g15Flag(t, false)
		return validation.ObjStr(g15Mint(t, c,
			"2026-09-08T12:00:05.000000+00:00"), "fork_stale")
	}
	noData := staleOf(false, "") // null chain
	noTS := staleOf(true, "")    // chain pin, no fork_timestamp
	aged := staleOf(true,
		"2026-08-31T12:00:00.000000+00:00") // 8d before the exec
	if !strings.HasPrefix(noData,
		"stale: no snapshot data recorded \u2014 ") {
		t.Fatalf("null chain marker\n%q", noData)
	}
	if !strings.HasPrefix(noTS,
		"stale: fork timestamp missing \u2014 ") {
		t.Fatalf("null timestamp marker\n%q", noTS)
	}
	if !strings.HasPrefix(aged, "stale: pinned 8 days ago \u2014 ") {
		t.Fatalf("aged marker\n%q", aged)
	}
	if noData == noTS || noData == aged || noTS == aged {
		t.Fatalf("stale reasons indistinguishable:\n%q\n%q\n%q",
			noData, noTS, aged)
	}
	for _, m := range []string{noData, noTS, aged} {
		for _, want := range []string{"snapshot pinned ", "fork_block ",
			"re-pin with snap + re-mint"} {
			if !strings.Contains(m, want) {
				t.Fatalf("detail text lost %q in\n%q", want, m)
			}
		}
	}
}

// Fix round 1, IMPORTANT-2 (rail B): the evidence item carries the rerun
// exec ids as the audit join, and the cited original exec record is
// byte-identical before and after the mint (the mint path never rewrites
// exec records).
func TestG15RerunJoinLeavesOriginalUntouched(t *testing.T) {
	c := newCampaign(t, "g15")
	g15Pin(t, c)
	g15Flag(t, true)
	n := 0
	g15Seam(t,
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			n++
			return g15IDs(&n), 0, []byte(g15Stdout), nil
		})
	fid := integrityHypo(t, c, "reentrancy")
	started := "2026-09-08T12:00:05.000000+00:00"
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: g15Command,
		ReportedBy: "operator", ExitStatus: 0, FindingID: optStr(fid),
		StdoutText: g15Stdout, StartedAt: &started,
	})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	execID := validation.ObjStr(rec, "exec_id")
	recPath := filepath.Join(c.ExecsDir, execID, "exec_record.json")
	before, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatalf("read original record: %v", err)
	}
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
	after, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatalf("re-read original record: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("original exec record changed by a flag-ON mint")
	}
	var item validation.Value
	for _, e := range validation.ObjAt(out, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == execID {
			item = e
		}
	}
	want := "3/3 (execs EXEC-rerun-1,EXEC-rerun-2,EXEC-rerun-3)"
	if got := validation.ObjStr(item, "reruns"); got != want {
		t.Fatalf("reruns = %q, want %q", got, want)
	}
	entries, err := os.ReadDir(c.ExecsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("mint wrote %d exec dirs, want 1 (the original)",
			len(entries))
	}
}

// A rerun that errors before producing an exec contributes no id to the
// join: all-error reruns mint bare "flaky 0/3" and still succeed.
func TestG15RerunsErrorOmitsJoin(t *testing.T) {
	c := newCampaign(t, "g15")
	g15Pin(t, c)
	g15Flag(t, true)
	g15Seam(t,
		func(*state.Campaign, string, string) (string, int, []byte, error) {
			return "", 0, nil, errors.New("container died mid-run")
		})
	item := g15Mint(t, c, "")
	if got := validation.ObjStr(item, "reruns"); got != "flaky 0/3" {
		t.Fatalf("reruns = %q, want flaky 0/3", got)
	}
	_ = TakeMintNotice()
}
