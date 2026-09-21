package cli

// spike_driver_test.go: the Phase 2 maximization spike driver
// (scripts/v16-spike.sh) is operator-run — it needs Docker, a fork RPC and an
// already-CONFIRMED finding — so its command surface is asserted offline
// instead. `bash -n` proves the script parses and nothing else, and this
// driver is the only place `exec --profile fork-runner`, `mint --poc-tier` and
// `impact --replayable` are driven together: a typo in a flag name would
// otherwise surface mid-spike, with Docker up and a fork pinned.
//
// The driver routes EVERY webv2 call through its run() helper, written as a
// `run <verb> ...` line, which is what makes this check possible: the test
// reads the script's SOURCE and pulls those invocation lines out, rather than
// guessing shell style (a driver that invoked through a variable would match
// nothing and fail for the wrong reason). The flag scan is scoped to the
// invocation lines because the forge command handed to `exec --command`
// carries foundry's own flags (--fork-url, --match-test) that no webv2 command
// declares.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// spikeRunRE matches the head of one driver invocation; the driver indents it
// inside `$( ... )` capture blocks and wraps it with backslashes.
var spikeRunRE = regexp.MustCompile(`^\s*run\s+([a-z][a-z0-9-]*)`)

// spikeFlagRE matches a long option token.
var spikeFlagRE = regexp.MustCompile(`--[a-z][a-z0-9-]+`)

// spikeDirectRE matches a line that invokes webv2 without going through run().
var spikeDirectRE = regexp.MustCompile(`^\s*webv2\s`)

func TestSpikeDriverEmitsOnlyKnownFlags(t *testing.T) {
	src := readSpikeDriver(t)
	invocations := spikeInvocations(src)
	if len(invocations) == 0 {
		t.Fatal("no `run <verb>` invocations found — the driver must route " +
			"every webv2 call through run(), or this test cannot check anything")
	}
	assertSpikeVerbsRegistered(t, invocations)
	assertSpikeLoopIsCovered(t, invocations)
	assertSpikeFlagsDeclared(t, invocations, readCLISources(t))
	assertRunOwnsEveryCall(t, src)
}

// readSpikeDriver returns the driver's source.
func readSpikeDriver(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "v16-spike.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// spikeInvocations returns each `run <verb> ...` invocation as one logical
// line, joining backslash continuations so a wrapped flag list is still
// checked.
func spikeInvocations(src string) []string {
	lines := strings.Split(src, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		if !spikeRunRE.MatchString(lines[i]) {
			continue
		}
		logical := lines[i]
		for strings.HasSuffix(strings.TrimRight(logical, " \t"), "\\") &&
			i+1 < len(lines) {
			i++
			logical += " " + lines[i]
		}
		out = append(out, logical)
	}
	return out
}

// assertSpikeVerbsRegistered checks every invoked verb against the dispatch
// registry itself — the read side of register(), which the other cli tests
// use — so a renamed verb breaks this test rather than the spike.
func assertSpikeVerbsRegistered(t *testing.T, invocations []string) {
	t.Helper()
	registered := map[string]bool{}
	for _, name := range CommandNames() {
		registered[name] = true
	}
	if len(registered) == 0 {
		t.Fatal("CommandNames() is empty — this guard would pass vacuously")
	}
	for _, line := range invocations {
		m := spikeRunRE.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("invocation %q does not name a verb", line)
			continue
		}
		if !registered[m[1]] {
			t.Errorf("driver invokes unregistered verb %q", m[1])
		}
	}
}

// assertSpikeLoopIsCovered pins the plan's steps by verb: a driver that
// silently dropped `impact --replayable` would still pass the flag check,
// because every flag it kept is declared.
func assertSpikeLoopIsCovered(t *testing.T, invocations []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, line := range invocations {
		if m := spikeRunRE.FindStringSubmatch(line); m != nil {
			seen[m[1]] = true
		}
	}
	for _, want := range []string{"exec", "mint", "ladder", "impact", "audit"} {
		if !seen[want] {
			t.Errorf("driver never invokes %q — the Phase 2 loop is incomplete",
				want)
		}
	}
}

// assertSpikeFlagsDeclared checks every flag on an invocation line against the
// package's own sources, so a renamed CLI flag breaks this test instead of the
// spike. A hand-copied list could not notice that.
func assertSpikeFlagsDeclared(t *testing.T, invocations []string, cliSrc string) {
	t.Helper()
	global := map[string]bool{"--root": true, "--json": true,
		"--help": true, "--dry-run": true}
	checked := 0
	for _, line := range invocations {
		for _, f := range spikeFlagRE.FindAllString(line, -1) {
			checked++
			if global[f] || strings.Contains(cliSrc, `"`+f+`"`) {
				continue
			}
			t.Errorf("driver emits flag %q that no command declares", f)
		}
	}
	if checked == 0 {
		t.Fatal("no flags found on any invocation — the driver emits nothing?")
	}
}

// readCLISources concatenates this package's non-test sources: the flag
// declarations a driver flag has to appear in.
func readCLISources(t *testing.T) string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		t.Fatal("no CLI sources read — this guard would pass vacuously")
	}
	return b.String()
}

// assertRunOwnsEveryCall is the teeth behind the scan above: a bare
// `webv2 audit ...` line would never match `run <verb>`, so its flags would go
// unchecked. Every line that invokes webv2 directly must therefore sit inside
// the run() helper, and that helper must honour DRY_RUN.
func assertRunOwnsEveryCall(t *testing.T, src string) {
	t.Helper()
	lines := strings.Split(src, "\n")
	start, end, ok := runHelperRange(lines)
	if !ok {
		t.Fatal("no run() helper found in the driver")
	}
	for i, line := range lines {
		if spikeDirectRE.MatchString(line) && (i < start || i > end) {
			t.Errorf("bare webv2 call outside run() at line %d: %q",
				i+1, strings.TrimSpace(line))
		}
	}
	if !strings.Contains(strings.Join(lines[start:end+1], "\n"), "DRY_RUN") {
		t.Error("run() does not honour DRY_RUN — the driver cannot be walked " +
			"offline, which is the whole point of the test")
	}
}

// runHelperRange returns the line range of the run() helper: its definition
// line through the first line that closes it at column 0.
func runHelperRange(lines []string) (int, int, bool) {
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "run()") {
			start = i
			break
		}
	}
	if start < 0 {
		return 0, 0, false
	}
	for i := start; i < len(lines); i++ {
		if lines[i] == "}" {
			return start, i, true
		}
	}
	return start, len(lines) - 1, true
}
