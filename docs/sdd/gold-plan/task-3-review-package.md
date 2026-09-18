# Gold Task 3 review package
## commits (3c095827..280e348d)
280e348d feat(briefing): evidence reachability line (class confirm floor vs box cap) (defect 5)
## diffstat
 internal/briefing/briefing.go                 |  87 +++++++++++++++++++++
 internal/briefing/task14_reachability_test.go | 106 ++++++++++++++++++++++++++
 internal/findings/levels.go                   |  27 +++++++
 internal/findings/levels_reachability_test.go |  47 ++++++++++++
 4 files changed, 267 insertions(+)
## full diff (-U10)
diff --git a/internal/briefing/briefing.go b/internal/briefing/briefing.go
index 150ff947..4fb3a6a6 100644
--- a/internal/briefing/briefing.go
+++ b/internal/briefing/briefing.go
@@ -2060,20 +2060,91 @@ func webv2Action(command, reason string) string {
 	return command + "  # " + noParens(reason)
 }
 
 // noParens keeps interpolated prose inside a `# reason` comment from
 // tripping the no-parenthesis law — the plan's own test regex is `\(` and
 // it reads the whole line; brackets carry the same meaning to an operator.
 func noParens(s string) string {
 	return strings.NewReplacer("(", "[", ")", "]").Replace(s)
 }
 
+// boxLocalCap is the box's E-cap for the reachability line: E4 — the local
+// execution ceiling the environment records. envgo's profileMaxLevel gives
+// every isolated container profile E4 and the doctor's e4_capable list names
+// exactly those profiles; E5+ is a fork run, which is what the line's "fork
+// required" clause names. Read, not probed: `docker info` inside a pure view
+// would turn the cockpit host-dependent and hang it for up to the probe's
+// 20s timeout on a wedged daemon — `webv2 env doctor` is the probe.
+//
+// ponytail: constant, not a live probe; wire envgo's e4_capable in when the
+// brief gains a cached environment block (the value only moves on a box that
+// cannot run containers at all, which `env doctor` already reports).
+const boxLocalCap = "E4"
+
+// openFindingClasses is the set of bug classes the campaign's open findings
+// carry: the classes a CONFIRMED move could still target. findings.IsTerminal
+// is the shared dead-row predicate, so a disproved or superseded row is not
+// open work. The read is not fail-soft — the brief already fails on the same
+// store (Reachability).
+func openFindingClasses(campaign *state.Campaign) ([]string, error) {
+	all, err := findings.LoadAllFindings(campaign)
+	if err != nil {
+		return nil, err
+	}
+	seen := map[string]bool{}
+	classes := []string{}
+	for _, f := range all {
+		if findings.IsTerminal(objStr(f, "status")) {
+			continue
+		}
+		cls := objStr(objAt(f, "root_cause"), "class")
+		if cls == "" || seen[cls] {
+			continue
+		}
+		seen[cls] = true
+		classes = append(classes, cls)
+	}
+	return classes, nil
+}
+
+// ReachabilityLine renders the evidence-reachability advisory: which of the
+// campaign's open bug classes can reach CONFIRMED on this box (floor at or
+// below cap) and which need a fork. Reachable classes lead, fork-required
+// classes follow, each group alphabetized, one class per clause with its own
+// floor. An empty class list renders nothing. Pure prose, advisory only: no
+// gate, proof or phase transition reads it.
+func ReachabilityLine(classes []string, cap string) string {
+	reachable, forked := []string{}, []string{}
+	for _, c := range classes {
+		if findings.ReachableLocally(c, cap) {
+			reachable = append(reachable, c)
+		} else {
+			forked = append(forked, c)
+		}
+	}
+	sort.Strings(reachable)
+	sort.Strings(forked)
+	clauses := make([]string, 0, len(classes))
+	for _, c := range reachable {
+		clauses = append(clauses, "CONFIRMED locally reachable for "+c+
+			" (floor "+findings.ClassConfirmFloor(c)+")")
+	}
+	for _, c := range forked {
+		clauses = append(clauses, "fork required for "+c+
+			" (floor "+findings.ClassConfirmFloor(c)+" > "+cap+")")
+	}
+	if len(clauses) == 0 {
+		return ""
+	}
+	return "evidence reachability: " + strings.Join(clauses, "; ")
+}
+
 // NextActions is _next_actions: the prioritized, concrete work list.
 func NextActions(brief validation.Value, campaign *state.Campaign) ([]string, error) {
 	actions := []string{}
 	cb := asObj(objAt(brief, "campaign"))
 	integ := asObj(objAt(brief, "integrity"))
 	if objBool(cb, "closed") {
 		cid := campaign.CampaignID
 		if objAt(integ, "ok").Kind == validation.Bool && !objAt(integ, "ok").B {
 			actions = append(actions, webv2Action("webv2 doctor "+cid,
 				"FIX INTEGRITY FIRST — trust issue, fix even though the "+
@@ -2135,20 +2206,36 @@ func NextActions(brief validation.Value, campaign *state.Campaign) ([]string, er
 	// the moment the emit is on record. It gates nothing.
 	if campaign != nil && objStr(cb, "phase") == "DISCOVERY" {
 		if emitted, err := probes.Emitted(campaign); err == nil && !emitted {
 			actions = append(actions, webv2Action(
 				"webv2 probes "+cid+" run --emit",
 				"cold probe surface — DISCOVERY is running with no probe "+
 					"emit on record, so the mechanical surface is unprobed"))
 		}
 	}
 
+	// Task 3 (defect 5): evidence reachability. G-01's accepted classes floor
+	// at E4 (dos-griefing, logic-error) and this box reaches E4 locally — the
+	// cockpit never said so, so CONFIRMED read as out of reach when it was
+	// not. Rendered immediately after the cold-probe warning; advisory only
+	// (no gate, proof or phase transition reads it) and silent when no open
+	// finding carries a class.
+	if campaign != nil {
+		classes, err := openFindingClasses(campaign)
+		if err != nil {
+			return nil, err
+		}
+		if line := ReachabilityLine(classes, boxLocalCap); line != "" {
+			actions = append(actions, line)
+		}
+	}
+
 	// probe surface: the ranked open rows lead
 	if ps := objAt(brief, "probe_surface"); ps.Kind == validation.Obj {
 		rows := listAt(ps, "open_rows")
 		sorted := append([]validation.Value{}, rows...)
 		sort.SliceStable(sorted, func(i, j int) bool {
 			return probes.RankKeyOf(sorted[i]).Less(probes.RankKeyOf(sorted[j]))
 		})
 		for _, r := range sorted {
 			rid := objStr(r, "row_id")
 			where := orQuestion(objStr(r, "lens")) + " " +
diff --git a/internal/briefing/task14_reachability_test.go b/internal/briefing/task14_reachability_test.go
new file mode 100644
index 00000000..702c8601
--- /dev/null
+++ b/internal/briefing/task14_reachability_test.go
@@ -0,0 +1,106 @@
+package briefing
+
+// task14_reachability_test.go: plan §Task 3 (gold-findings closure, defect 5)
+// — the brief renders evidence reachability per open bug class: the class's
+// CONFIRMED floor against the box's local E-cap. Advisory only: no gate,
+// proof or phase transition reads the line.
+
+import (
+	"strings"
+	"testing"
+)
+
+// TestReachabilityLine pins the rendering contract: reachable classes first,
+// fork-required classes second, each group alphabetized, one class per clause
+// carrying its own floor value.
+func TestReachabilityLine(t *testing.T) {
+	got := ReachabilityLine([]string{"economic-invariant", "dos-griefing"}, "E4")
+	want := "evidence reachability: CONFIRMED locally reachable for dos-griefing " +
+		"(floor E4); fork required for economic-invariant (floor E6 > E4)"
+	if got != want {
+		t.Fatalf("got %q, want %q", got, want)
+	}
+	// reachable-first alphabetized, fork-required alphabetized, one clause each
+	got = ReachabilityLine([]string{"token-integration", "economic-invariant",
+		"dos-griefing", "bridge-message"}, "E4")
+	want = "evidence reachability: CONFIRMED locally reachable for dos-griefing " +
+		"(floor E4); CONFIRMED locally reachable for token-integration " +
+		"(floor E4); fork required for bridge-message (floor E6 > E4); " +
+		"fork required for economic-invariant (floor E6 > E4)"
+	if got != want {
+		t.Fatalf("multi-class got %q, want %q", got, want)
+	}
+	if all := ReachabilityLine([]string{"dos-griefing", "logic-error"}, "E4"); strings.Contains(all, "fork required") {
+		t.Fatalf("all-reachable line must omit the fork clause: %q", all)
+	}
+	if forkOnly := ReachabilityLine([]string{"economic-invariant"}, "E4"); strings.Contains(forkOnly, "locally reachable") {
+		t.Fatalf("all-fork line must omit the reachable clause: %q", forkOnly)
+	}
+	if forkOnly := ReachabilityLine([]string{"economic-invariant"}, "E4"); !strings.HasPrefix(forkOnly, "evidence reachability: fork required for ") {
+		t.Fatalf("all-fork line must start with the fork clause: %q", forkOnly)
+	}
+	// an unknown class floors at the CONFIRMED default (E5)
+	if got := ReachabilityLine([]string{"nonexistent-class"}, "E4"); got !=
+		"evidence reachability: fork required for nonexistent-class (floor E5 > E4)" {
+		t.Fatalf("unknown-class got %q", got)
+	}
+	// empty class list renders nothing at all
+	if got := ReachabilityLine(nil, "E4"); got != "" {
+		t.Fatalf("empty class list rendered %q, want the empty string", got)
+	}
+	if got := ReachabilityLine([]string{}, "E4"); got != "" {
+		t.Fatalf("empty class list rendered %q, want the empty string", got)
+	}
+}
+
+// TestReachabilityLineFollowsColdProbeWarning is the ordering pin: the line
+// sits at exactly one index past the Task 11 cold-probe warning in a fixture
+// that carries both.
+func TestReachabilityLineFollowsColdProbeWarning(t *testing.T) {
+	c := newCamp(t, "Reachability Program")
+	if err := c.SetPhase("DISCOVERY", "task 14 fixture"); err != nil {
+		t.Fatalf("set phase: %v", err)
+	}
+	t35WorkHypo(t, c, "griefing hypothesis", "subset-of-users",
+		"dos-griefing", nil)
+	actions := objStringList(t, build(t, c, false), "next_actions")
+
+	coldIdx, reachIdx := -1, -1
+	for i, a := range actions {
+		if task11HasColdLine(c.CampaignID, []string{a}) {
+			coldIdx = i
+		}
+		if strings.HasPrefix(a, "evidence reachability: ") {
+			reachIdx = i
+		}
+	}
+	if coldIdx < 0 {
+		t.Fatalf("fixture rendered no cold-probe warning: %v", actions)
+	}
+	if reachIdx < 0 {
+		t.Fatalf("fixture rendered no reachability line: %v", actions)
+	}
+	if reachIdx != coldIdx+1 {
+		t.Fatalf("reachability line at index %d, want %d — immediately "+
+			"after the cold-probe warning: %v", reachIdx, coldIdx+1, actions)
+	}
+	want := "evidence reachability: CONFIRMED locally reachable for " +
+		"dos-griefing (floor E4)"
+	if actions[reachIdx] != want {
+		t.Fatalf("rendered line %q, want %q", actions[reachIdx], want)
+	}
+	t.Logf("cold-probe warning index %d, reachability line index %d: %s",
+		coldIdx, reachIdx, actions[reachIdx])
+}
+
+// TestReachabilityLineNeedsAnOpenClass pins the render condition: no open
+// finding carries a class → no line, and a terminal finding is not open work.
+func TestReachabilityLineNeedsAnOpenClass(t *testing.T) {
+	c := newCamp(t, "Empty Program")
+	actions := objStringList(t, build(t, c, false), "next_actions")
+	for _, a := range actions {
+		if strings.HasPrefix(a, "evidence reachability: ") {
+			t.Fatalf("class-less campaign rendered %q", a)
+		}
+	}
+}
diff --git a/internal/findings/levels.go b/internal/findings/levels.go
index 61ff2cd5..fa6da668 100644
--- a/internal/findings/levels.go
+++ b/internal/findings/levels.go
@@ -169,20 +169,47 @@ func RequiredLevelFor(status, bugClass string) string {
 			return f
 		}
 		return STATUS_FLOOR["CONFIRMED"]
 	}
 	if f, ok := STATUS_FLOOR[status]; ok {
 		return f
 	}
 	return "E0"
 }
 
+// ClassConfirmFloor is class_confirm_floor: the class's CONFIRMED floor from
+// CLASS_CONFIRM_FLOOR, or the CONFIRMED default (E5) for a class the map does
+// not carry — the same conservative default RequiredLevelFor applies. A pure
+// read: it gates nothing.
+func ClassConfirmFloor(class string) string {
+	if f, ok := CLASS_CONFIRM_FLOOR[class]; ok {
+		return f
+	}
+	return STATUS_FLOOR["CONFIRMED"]
+}
+
+// ReachableLocally reports whether CONFIRMED for *class* can be reached in a
+// local harness: its floor sits at or below *cap* on the E0-E7 ladder. An
+// unknown cap has no ladder position, so nothing is reachable against it —
+// the same refusal LevelIndex makes instead of guessing an index.
+func ReachableLocally(class, cap string) bool {
+	floor, err := LevelIndex(ClassConfirmFloor(class))
+	if err != nil {
+		return false
+	}
+	limit, err := LevelIndex(cap)
+	if err != nil {
+		return false
+	}
+	return floor <= limit
+}
+
 // RequiredLevelForCampaign is required_level_for_campaign: the evidence
 // floor that applies IN THIS CAMPAIGN — the instance-level override when
 // the operator set one (floors.set_floor_policy: data, actor, written
 // reason, logged event), else the built-in CLASS_CONFIRM_FLOOR /
 // STATUS_FLOOR default. Without a campaign, the built-in default.
 func RequiredLevelForCampaign(campaign *state.Campaign, status, bugClass string) string {
 	if campaign == nil {
 		return RequiredLevelFor(status, bugClass)
 	}
 	return effectiveFloorFunc(campaign, status, bugClass)
diff --git a/internal/findings/levels_reachability_test.go b/internal/findings/levels_reachability_test.go
new file mode 100644
index 00000000..eca00087
--- /dev/null
+++ b/internal/findings/levels_reachability_test.go
@@ -0,0 +1,47 @@
+package findings
+
+// levels_reachability_test.go: plan §Task 3 (gold-findings closure) — the
+// class-floor accessors the brief's reachability line renders from.
+//
+// Step 0 floor-map facts (read from levels.go, never assumed):
+// CLASS_CONFIRM_FLOOR carries E6 keys — share-price-inflation, economic-
+// invariant, bridge-message, cross-chain-replay, frontend-injection,
+// infra-boundary. share-price-inflation = "E6" is the real pinned value
+// below (the plan's placeholder was correct for this map).
+import "testing"
+
+func TestClassConfirmFloor(t *testing.T) {
+	if got := ClassConfirmFloor("dos-griefing"); got != "E4" {
+		t.Fatalf("dos-griefing floor = %q, want E4", got)
+	}
+	// the real E6 key/value from the Step 0 read of levels.go
+	if got := ClassConfirmFloor("share-price-inflation"); got != "E6" {
+		t.Fatalf("share-price-inflation floor = %q, want E6", got)
+	}
+	if got := ClassConfirmFloor("nonexistent-class"); got != "E5" {
+		t.Fatalf("unknown class floor = %q, want E5 (CONFIRMED default)", got)
+	}
+}
+
+func TestReachableLocally(t *testing.T) {
+	if !ReachableLocally("dos-griefing", "E4") {
+		t.Errorf("dos-griefing at cap E4 = false, want true")
+	}
+	if ReachableLocally("economic-invariant", "E4") {
+		t.Errorf("economic-invariant at cap E4 = true, want false (floor E6)")
+	}
+	if !ReachableLocally("economic-invariant", "E6") {
+		t.Errorf("economic-invariant at cap E6 = false, want true")
+	}
+	// unknown class defaults to the CONFIRMED floor (E5)
+	if ReachableLocally("nonexistent-class", "E4") {
+		t.Errorf("unknown class at cap E4 = true, want false (default E5)")
+	}
+	if !ReachableLocally("nonexistent-class", "E5") {
+		t.Errorf("unknown class at cap E5 = false, want true")
+	}
+	// an unknown cap has no ladder position: not reachable
+	if ReachableLocally("dos-griefing", "E9") {
+		t.Errorf("unknown cap E9 = true, want false")
+	}
+}
