package briefing

// task14_reachability_test.go: plan §Task 3 (gold-findings closure, defect 5)
// — the brief renders evidence reachability per open bug class: the class's
// CONFIRMED floor against the box's local E-cap. Advisory only: no gate,
// proof or phase transition reads the line.

import (
	"strings"
	"testing"
)

// TestReachabilityLine pins the rendering contract: reachable classes first,
// fork-required classes second, each group alphabetized, one class per clause
// carrying its own floor value.
func TestReachabilityLine(t *testing.T) {
	got := ReachabilityLine([]string{"economic-invariant", "dos-griefing"}, "E4")
	want := "evidence reachability: CONFIRMED locally reachable for dos-griefing " +
		"(floor E4); fork required for economic-invariant (floor E6 > E4)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// reachable-first alphabetized, fork-required alphabetized, one clause each
	got = ReachabilityLine([]string{"token-integration", "economic-invariant",
		"dos-griefing", "bridge-message"}, "E4")
	want = "evidence reachability: CONFIRMED locally reachable for dos-griefing " +
		"(floor E4); CONFIRMED locally reachable for token-integration " +
		"(floor E4); fork required for bridge-message (floor E6 > E4); " +
		"fork required for economic-invariant (floor E6 > E4)"
	if got != want {
		t.Fatalf("multi-class got %q, want %q", got, want)
	}
	if all := ReachabilityLine([]string{"dos-griefing", "logic-error"}, "E4"); strings.Contains(all, "fork required") {
		t.Fatalf("all-reachable line must omit the fork clause: %q", all)
	}
	if forkOnly := ReachabilityLine([]string{"economic-invariant"}, "E4"); strings.Contains(forkOnly, "locally reachable") {
		t.Fatalf("all-fork line must omit the reachable clause: %q", forkOnly)
	}
	if forkOnly := ReachabilityLine([]string{"economic-invariant"}, "E4"); !strings.HasPrefix(forkOnly, "evidence reachability: fork required for ") {
		t.Fatalf("all-fork line must start with the fork clause: %q", forkOnly)
	}
	// an unknown class floors at the CONFIRMED default (E5)
	if got := ReachabilityLine([]string{"nonexistent-class"}, "E4"); got !=
		"evidence reachability: fork required for nonexistent-class (floor E5 > E4)" {
		t.Fatalf("unknown-class got %q", got)
	}
	// empty class list renders nothing at all
	if got := ReachabilityLine(nil, "E4"); got != "" {
		t.Fatalf("empty class list rendered %q, want the empty string", got)
	}
	if got := ReachabilityLine([]string{}, "E4"); got != "" {
		t.Fatalf("empty class list rendered %q, want the empty string", got)
	}
}

// TestReachabilityLineFollowsColdProbeWarning is the ordering pin: the line
// sits at exactly one index past the Task 11 cold-probe warning in a fixture
// that carries both.
func TestReachabilityLineFollowsColdProbeWarning(t *testing.T) {
	c := newCamp(t, "Reachability Program")
	if err := c.SetPhase("DISCOVERY", "task 14 fixture"); err != nil {
		t.Fatalf("set phase: %v", err)
	}
	t35WorkHypo(t, c, "griefing hypothesis", "subset-of-users",
		"dos-griefing", nil)
	actions := objStringList(t, build(t, c, false), "next_actions")

	coldIdx, reachIdx := -1, -1
	for i, a := range actions {
		if task11HasColdLine(c.CampaignID, []string{a}) {
			coldIdx = i
		}
		if strings.HasPrefix(a, "evidence reachability: ") {
			reachIdx = i
		}
	}
	if coldIdx < 0 {
		t.Fatalf("fixture rendered no cold-probe warning: %v", actions)
	}
	if reachIdx < 0 {
		t.Fatalf("fixture rendered no reachability line: %v", actions)
	}
	if reachIdx != coldIdx+1 {
		t.Fatalf("reachability line at index %d, want %d — immediately "+
			"after the cold-probe warning: %v", reachIdx, coldIdx+1, actions)
	}
	want := "evidence reachability: CONFIRMED locally reachable for " +
		"dos-griefing (floor E4)"
	if actions[reachIdx] != want {
		t.Fatalf("rendered line %q, want %q", actions[reachIdx], want)
	}
	t.Logf("cold-probe warning index %d, reachability line index %d: %s",
		coldIdx, reachIdx, actions[reachIdx])
}

// TestReachabilityLineNeedsAnOpenClass pins the render condition: no open
// finding carries a class → no line, and a terminal finding is not open work.
func TestReachabilityLineNeedsAnOpenClass(t *testing.T) {
	c := newCamp(t, "Empty Program")
	actions := objStringList(t, build(t, c, false), "next_actions")
	for _, a := range actions {
		if strings.HasPrefix(a, "evidence reachability: ") {
			t.Fatalf("class-less campaign rendered %q", a)
		}
	}
}
