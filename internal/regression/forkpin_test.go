package regression

import (
	"strings"
	"testing"
)

// The fork-pin tests use REAL forge output, not a hand-written string: the
// regex exists to read what the harness actually prints, and a fixture invented
// here would prove only that the regex matches the fixture. This is the exact
// line shape the control target's pre-patch run emitted (2026-09-22,
// docs/gates/v16-P0-control-target.md §3.1) — including the parenthesised gas
// suffix that follows it, which a lazier pattern would swallow.
const forgeReportedLine = "[FAIL: call reverted as expected, but without data] " +
	"testFakeMarketLeverage() (block: 99811375) (gas: 1388949)"

func TestDeriveForkBlockReadsTheHeightTheHarnessReported(t *testing.T) {
	got, err := DeriveForkBlock(forgeReportedLine)
	if err != nil {
		t.Fatalf("DeriveForkBlock(%q) = %v, want the reported height", forgeReportedLine, err)
	}
	if got != 99811375 {
		t.Fatalf("DeriveForkBlock = %d, want 99811375", got)
	}
	// The same height repeated on every test line is the normal shape: five
	// tests, one fork. It must not read as a disagreement.
	repeated := strings.Join([]string{forgeReportedLine, forgeReportedLine, forgeReportedLine}, "\n")
	if got, err := DeriveForkBlock(repeated); err != nil || got != 99811375 {
		t.Fatalf("repeated height: got %d, err %v; want 99811375 and no error", got, err)
	}
}

// TestDeriveForkBlockRefusesWhatItCannotKnow is the point of the type. The
// failure this guards against is not a crash — it is a record that quietly
// carries the height someone *passed* when the harness ran at a different one,
// which is what the control target actually did (three months apart).
func TestDeriveForkBlockRefusesWhatItCannotKnow(t *testing.T) {
	if _, err := DeriveForkBlock("Ran 5 tests for test/DebtManager.t.sol:DebtManagerTest\n" +
		"Suite result: ok. 5 passed; 0 failed; 0 skipped"); err == nil {
		t.Fatal("output mentioning no height was accepted — the caller would then fall back " +
			"to the requested height, which is the defect this exists to forbid")
	} else if !strings.Contains(err.Error(), "no reported fork height") {
		t.Fatalf("err = %v, want the no-height refusal", err)
	}
	two := "[PASS] a() (block: 99811375) (gas: 1)\n[PASS] b() (block: 108375558) (gas: 1)"
	if _, err := DeriveForkBlock(two); err == nil {
		t.Fatal("a run that forked two states was accepted as one height")
	} else if !strings.Contains(err.Error(), "two fork heights") {
		t.Fatalf("err = %v, want the two-heights refusal", err)
	}
}

// legalForkObserved is the accept side: one shape per source, plus a run that
// named no endpoint (the host is optional).
func legalForkObserved() []ForkObservedSpec {
	return []ForkObservedSpec{
		{Block: 108375557, Source: ForkDerived, ReportedBy: "EXEC-0001",
			EndpointHost: "mainnet.optimism.io"},
		{Block: 108375557, Source: ForkDeclared, Reason: "harness prints no height",
			EndpointHost: "optimism.drpc.org:443"},
		{Source: ForkAbsent, Reason: "no fork run recorded for this target"},
		{Block: 1, Source: ForkDerived, ReportedBy: "EXEC-0002"},
	}
}

// refusedForkObserved is the refuse side: each entry is one branch of the
// pairing rule, including the two that are the silent fallback in disguise.
func refusedForkObserved() []struct {
	name string
	spec ForkObservedSpec
	want string
} {
	return []struct {
		name string
		spec ForkObservedSpec
		want string
	}{
		{"derived with no height", ForkObservedSpec{Source: ForkDerived, ReportedBy: "EXEC-1"},
			"needs the height the harness reported"},
		{"derived with no provenance",
			ForkObservedSpec{Block: 1, Source: ForkDerived}, "needs --fork-reported-by"},
		{"declared with no reason",
			ForkObservedSpec{Block: 1, Source: ForkDeclared}, "needs a reason"},
		{"absent carrying a number",
			ForkObservedSpec{Block: 99811375, Source: ForkAbsent, Reason: "x"},
			"a number with no provenance is the fallback this record forbids"},
		{"absent with no reason", ForkObservedSpec{Source: ForkAbsent}, "needs the reason"},
		{"unknown source", ForkObservedSpec{Block: 1, Source: "guessed"},
			"unknown fork_observed source"},
		{"a full URL as the endpoint",
			ForkObservedSpec{Block: 1, Source: ForkDerived, ReportedBy: "EXEC-1",
				EndpointHost: "https://mainnet.optimism.io/v1/?key=abc"},
			"a full URL is a credential leak with extra steps"},
	}
}

// TestCheckForkObservedRefusesTheSilentFallback walks the three sources. Each
// branch has one shape that is legal and one that is the fallback in disguise.
func TestCheckForkObservedRefusesTheSilentFallback(t *testing.T) {
	for _, s := range legalForkObserved() {
		if err := checkForkObserved(s); err != nil {
			t.Errorf("checkForkObserved(%+v) = %v, want nil", s, err)
		}
	}
	for _, tc := range refusedForkObserved() {
		err := checkForkObserved(tc.spec)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want a refusal containing %q", tc.name, err, tc.want)
		}
	}
}

// TestForkObservedDocOmitsWhatIsAbsent pins the shape the ledger sees: an absent
// height is absent from the document, not rendered as 0. A zero in a
// hash-chained record is a claim that a block was forked.
func TestForkObservedDocOmitsWhatIsAbsent(t *testing.T) {
	absent := ForkObservedDoc(ForkObservedSpec{Source: ForkAbsent, Reason: "no fork run"})
	if got := absent.O; len(got) != 2 {
		t.Fatalf("absent doc has %d keys, want source and reason only: %v", len(got), got)
	}
	derived := ForkObservedDoc(ForkObservedSpec{Block: 108375557, Source: ForkDerived,
		ReportedBy: "EXEC-0001", EndpointHost: "mainnet.optimism.io"})
	if got := derived.O; len(got) != 4 {
		t.Fatalf("derived doc has %d keys, want source/block/reported_by/endpoint_host: %v",
			len(got), got)
	}
}
