package findings

// levels_reachability_test.go: plan §Task 3 (gold-findings closure) — the
// class-floor accessors the brief's reachability line renders from.
//
// Step 0 floor-map facts (read from levels.go, never assumed):
// CLASS_CONFIRM_FLOOR carries E6 keys — share-price-inflation, economic-
// invariant, bridge-message, cross-chain-replay, frontend-injection,
// infra-boundary. share-price-inflation = "E6" is the real pinned value
// below (the plan's placeholder was correct for this map).
import "testing"

func TestClassConfirmFloor(t *testing.T) {
	if got := ClassConfirmFloor("dos-griefing"); got != "E4" {
		t.Fatalf("dos-griefing floor = %q, want E4", got)
	}
	// the real E6 key/value from the Step 0 read of levels.go
	if got := ClassConfirmFloor("share-price-inflation"); got != "E6" {
		t.Fatalf("share-price-inflation floor = %q, want E6", got)
	}
	if got := ClassConfirmFloor("nonexistent-class"); got != "E5" {
		t.Fatalf("unknown class floor = %q, want E5 (CONFIRMED default)", got)
	}
}

func TestReachableLocally(t *testing.T) {
	if !ReachableLocally("dos-griefing", "E4") {
		t.Errorf("dos-griefing at cap E4 = false, want true")
	}
	if ReachableLocally("economic-invariant", "E4") {
		t.Errorf("economic-invariant at cap E4 = true, want false (floor E6)")
	}
	if !ReachableLocally("economic-invariant", "E6") {
		t.Errorf("economic-invariant at cap E6 = false, want true")
	}
	// unknown class defaults to the CONFIRMED floor (E5)
	if ReachableLocally("nonexistent-class", "E4") {
		t.Errorf("unknown class at cap E4 = true, want false (default E5)")
	}
	if !ReachableLocally("nonexistent-class", "E5") {
		t.Errorf("unknown class at cap E5 = false, want true")
	}
	// an unknown cap has no ladder position: not reachable
	if ReachableLocally("dos-griefing", "E9") {
		t.Errorf("unknown cap E9 = true, want false")
	}
}
