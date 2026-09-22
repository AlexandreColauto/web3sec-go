package regression

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"websec/internal/validation"
)

// The chain-side half of a fork run's pin.
//
// roadmap §4: "a fork run carries a resolved block". Its mirror image is the
// snapshot's resolved SHA, and the pair exists because P0's control target
// proved they can disagree: a commit says nothing about which chain state was
// forked, and forge's createSelectFork silently beats --fork-block-number, so
// the height a run *asked for* is not the height it *got*
// (docs/gates/v16-P0-control-target.md §3.1 — three months apart).
//
// Which is why the observed height is DERIVED from what the harness reported
// and never taken from the flag that was passed: an asserted height is exactly
// the thing that just failed.

// ForkObservedSource names how fork_observed.block came to be known.
type ForkObservedSource = string

const (
	// ForkDerived: the height was read out of the harness's own output, which
	// is the only kind that says what actually ran.
	ForkDerived ForkObservedSource = "derived"
	// ForkDeclared: the height could not be recovered, and the operator
	// asserts it. Always carries a reason for not being derived.
	ForkDeclared ForkObservedSource = "declared"
	// ForkAbsent: nothing is known about the height. The record says so, with
	// a reason, instead of quietly falling back to the requested value.
	ForkAbsent ForkObservedSource = "absent"
)

// ForkObservedSpec is one run's chain-side observation.
type ForkObservedSpec struct {
	Block        int64
	Source       ForkObservedSource
	ReportedBy   string // derived: where the height was read from (an exec id)
	Reason       string // declared/absent: why it is not derived
	EndpointHost string // host only — see checkForkObserved for why
}

// forkBlockReported is how forge prints the height a forked test actually ran
// at: "(block: 99811375)" on every test line.
var forkBlockReported = regexp.MustCompile(`\(block: ([0-9]{1,20})\)`)

// DeriveForkBlock reads the height the fork REPORTED out of a harness's own
// output. It refuses output that mentions no height, and output that mentions
// more than one: a harness that selects several forks has not run at a single
// height, and recording the first one it printed would be the fallback this
// type exists to forbid.
func DeriveForkBlock(output string) (int64, error) {
	ms := forkBlockReported.FindAllStringSubmatch(output, -1)
	if len(ms) == 0 {
		return 0, fmt.Errorf("no reported fork height in %d bytes of harness output — "+
			"record fork_observed with source %q and a reason; the height passed on the "+
			"command line is not evidence of the height that ran",
			len(output), ForkAbsent)
	}
	want := ms[0][1]
	for _, m := range ms[1:] {
		if m[1] != want {
			return 0, fmt.Errorf("the harness reported two fork heights (%s and %s) — "+
				"a run that forked more than one state carries one block, not a choice",
				want, m[1])
		}
	}
	n, err := parseUint(want)
	if err != nil {
		return 0, fmt.Errorf("reported fork height %q: %w", want, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("reported fork height %q is not a block", want)
	}
	return n, nil
}

// parseUint reads a decimal height out of harness output. It is deliberately
// strict: the digits came from a regex, but a height that does not fit an int64
// is not a height, and silently wrapping one would put a number in a hash-chained
// record that no chain ever had.
func parseUint(s string) (int64, error) {
	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil {
		return 0, fmt.Errorf("not a block height: %w", err)
	}
	return int64(n), nil
}

// checkForkObserved is the pairing rule: a height and the way it was learned
// travel together, or neither is present and the absence is explained. Every
// branch refuses the silent fallback.
func checkForkObserved(s ForkObservedSpec) error {
	if err := checkForkSource(s); err != nil {
		return err
	}
	return checkEndpointHost(s.EndpointHost)
}

// checkForkSource dispatches on how the height came to be known. The three
// sources are genuinely different claims, so they are three functions rather
// than one long switch: a branch per claim is what makes "which one is this?"
// answerable at the call site.
func checkForkSource(s ForkObservedSpec) error {
	switch s.Source {
	case ForkDerived:
		return checkDerivedFork(s)
	case ForkDeclared:
		return checkDeclaredFork(s)
	case ForkAbsent:
		return checkAbsentFork(s)
	default:
		return fmt.Errorf("unknown fork_observed source %q (known: %s, %s, %s)", s.Source,
			ForkDerived, ForkDeclared, ForkAbsent)
	}
}

func checkDerivedFork(s ForkObservedSpec) error {
	if s.Block <= 0 {
		return fmt.Errorf("source %q needs the height the harness reported, not a positive "+
			"number someone believed", ForkDerived)
	}
	if strings.TrimSpace(s.ReportedBy) == "" {
		return fmt.Errorf("source %q needs --fork-reported-by naming where the height was "+
			"read from (an EXEC id), so a reader can re-derive it", ForkDerived)
	}
	return nil
}

func checkDeclaredFork(s ForkObservedSpec) error {
	if s.Block <= 0 {
		return fmt.Errorf("source %q needs the asserted height — if no height is known, "+
			"record source %q", ForkDeclared, ForkAbsent)
	}
	if strings.TrimSpace(s.Reason) == "" {
		return fmt.Errorf("source %q needs a reason (--fork-reason): why the height could not "+
			"be derived from the harness's own output", ForkDeclared)
	}
	return nil
}

func checkAbsentFork(s ForkObservedSpec) error {
	if s.Block != 0 {
		return fmt.Errorf("source %q carries no height, but %d was given — a number with no "+
			"provenance is the fallback this record forbids", ForkAbsent, s.Block)
	}
	if strings.TrimSpace(s.Reason) == "" {
		return fmt.Errorf("source %q needs the reason the height is unknown (--fork-reason)",
			ForkAbsent)
	}
	return nil
}

// hostRe allows a bare host (with optional port) and nothing else: no scheme,
// no path, no query, and above all no userinfo.
var hostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?$`)

// checkEndpointHost refuses anything that is not a bare host, because a public
// archive endpoint's URL is a credential in the wild (publicnode wants a token;
// operators paste URLs that carry keys) and this document lands in a
// hash-chained ledger that is copied, diffed and pasted into reports. The
// identity that matters for reproducibility is the host; the path and query are
// either noise or secrets.
func checkEndpointHost(h string) error {
	if h == "" {
		return nil // optional: a run may not have named its endpoint
	}
	if !hostRe.MatchString(h) {
		return fmt.Errorf("fork_endpoint must be a HOST (optionally host:port), got %q — "+
			"a full URL is a credential leak with extra steps: keys ride in paths and query "+
			"strings, and this record is hash-chained and copy-pasted", h)
	}
	return nil
}

// ForkObservedDoc builds the run record's fork_observed block. Callers check
// the spec first; this function only shapes it.
func ForkObservedDoc(s ForkObservedSpec) validation.Value {
	o := []validation.KV{kv("source", validation.VStr(s.Source))}
	if s.Block > 0 {
		o = append(o, kv("block", validation.VInt(s.Block)))
	}
	for _, p := range []struct {
		key, val string
	}{
		{"reported_by", s.ReportedBy},
		{"reason", s.Reason},
		{"endpoint_host", s.EndpointHost},
	} {
		if strings.TrimSpace(p.val) != "" {
			o = append(o, kv(p.key, validation.VStr(p.val)))
		}
	}
	return validation.VObj(o...)
}
