// proofs2.go: the CONFIRMED-finding proofs (maximal exploitation through
// learning). Same contract as proofs.go: deterministic, read-only, total.
package completion

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// confirmedStatuses is the pair every post-confirmation proof tracks.
var confirmedStatuses = []string{"CONFIRMED", "CHAIN"}

// proofMaximalExploitation is _proof_maximal_exploitation: every CONFIRMED
// finding must have a variant ladder whose disposition is complete — or a
// recorded waiver. This is the stage that turns 'E6 luck' into a requirement.
func proofMaximalExploitation(c *state.Campaign) (validation.Value, error) {
	wmap, err := waiverMap(c, "maximal-exploitation")
	if err != nil {
		return validation.VNull(), err
	}
	found, err := findingsWith(c, confirmedStatuses)
	if err != nil {
		return validation.VNull(), err
	}
	items := []proofItem{}
	for _, f := range found {
		fid := objStr(f, "finding_id")
		lad, err := maximizationImpl.LoadLadder(c, fid)
		if err != nil {
			return validation.VNull(), err
		}
		if lad.Kind != validation.Obj {
			items = append(items, proofItem{fid,
				"no variant ladder — webv2 ladder start " + fid})
			continue
		}
		disp := objAt(orEmpty(objAt(lad, "disposition")), "state")
		if disp.Kind == validation.Str && disp.S == "complete" {
			continue
		}
		explored := listAt(lad, "axes_explored")
		unexplored := []string{}
		for _, axis := range AllAxes {
			if !containsStr(explored, axis) {
				unexplored = append(unexplored, axis)
			}
		}
		detail := "ladder disposition is " + validation.PyRepr(disp)
		if len(unexplored) > 0 {
			detail += "; unexplored axes: " + strings.Join(unexplored, ", ")
		}
		items = append(items, proofItem{fid, detail})
	}
	missing := unwaived(items, wmap, func(s, m string) string { return s + ": " + m })
	note := "every CONFIRMED finding maximized or waived"
	if len(missing) > 0 {
		note = "CONFIRMED findings lacking a completed variant ladder"
	}
	return proofResult(len(missing) == 0, missing, note), nil
}

// containsStr is Python's `x in list` over string values.
func containsStr(list []validation.Value, want string) bool {
	for _, v := range list {
		if v.Kind == validation.Str && v.S == want {
			return true
		}
	}
	return false
}

// proofIndependentVerification is _proof_independent_verification.
func proofIndependentVerification(c *state.Campaign) (validation.Value, error) {
	wmap, err := waiverMap(c, "independent-verification")
	if err != nil {
		return validation.VNull(), err
	}
	found, err := findingsWith(c, confirmedStatuses)
	if err != nil {
		return validation.VNull(), err
	}
	items := []proofItem{}
	for _, f := range found {
		iv := orEmpty(objAt(orEmpty(objAt(f, "verification")),
			"independent_reproduction"))
		if objStr(iv, "status") == "matches" && pyTruthy(objAt(iv, "verifier")) {
			continue
		}
		items = append(items, proofItem{objStr(f, "finding_id"),
			"no E6 independent reproduction (run the " +
				"independent-verification stage; mint with " +
				"webv2 verify --exec ...)"})
	}
	missing := unwaived(items, wmap, func(s, m string) string { return s + ": " + m })
	note := "every CONFIRMED finding independently verified"
	if len(missing) > 0 {
		note = "CONFIRMED findings lacking E6"
	}
	return proofResult(len(missing) == 0, missing, note), nil
}

// proofRiskCalibration is _proof_risk_calibration.
func proofRiskCalibration(c *state.Campaign) (validation.Value, error) {
	wmap, err := waiverMap(c, "risk-calibration")
	if err != nil {
		return validation.VNull(), err
	}
	found, err := findingsWith(c, confirmedStatuses)
	if err != nil {
		return validation.VNull(), err
	}
	items := []proofItem{}
	for _, f := range found {
		band := objAt(orEmpty(objAt(orEmpty(objAt(f, "risk")), "validated")), "band")
		if pyTruthy(band) {
			continue
		}
		items = append(items, proofItem{objStr(f, "finding_id"),
			"not calibrated (no risk.validated.band)"})
	}
	missing := unwaived(items, wmap, func(s, m string) string { return s + ": " + m })
	note := "findings await calibration"
	if len(missing) == 0 {
		note = "calibrated"
	}
	return proofResult(len(missing) == 0, missing, note), nil
}

// proofMainnetForkPoc is _proof_mainnet_fork_poc: every CONFIRMED finding
// must carry a PROVEN mainnet fork PoC — E5/E6 evidence tracing to a
// succeeded fork-runner exec in the ledger.
func proofMainnetForkPoc(c *state.Campaign) (validation.Value, error) {
	wmap, err := waiverMap(c, "mainnet-fork-poc")
	if err != nil {
		return validation.VNull(), err
	}
	found, err := findingsWith(c, confirmedStatuses)
	if err != nil {
		return validation.VNull(), err
	}
	items := []proofItem{}
	for _, f := range found {
		item, reason, err := forkPocImpl.ForkPocEvidence(c, f)
		if err != nil {
			return validation.VNull(), err
		}
		if item.Kind == validation.Null {
			text := "no fork PoC proven"
			if reason != nil && *reason != "" {
				text = *reason
			}
			items = append(items, proofItem{objStr(f, "finding_id"), text})
		}
	}
	missing := unwaived(items, wmap, func(s, m string) string { return s + ": " + m })
	note := "CONFIRMED findings lack a mainnet fork PoC"
	if len(found) == 0 {
		note = "no CONFIRMED findings yet (vacuously done)"
	} else if len(missing) == 0 {
		note = "every CONFIRMED finding has a proven fork PoC"
	}
	return proofResult(len(missing) == 0, missing, note), nil
}

// proofBountyGate is _proof_bounty_gate.
func proofBountyGate(c *state.Campaign) (validation.Value, error) {
	wmap, err := waiverMap(c, "bounty-gate")
	if err != nil {
		return validation.VNull(), err
	}
	found, err := findingsWith(c, confirmedStatuses)
	if err != nil {
		return validation.VNull(), err
	}
	items := []proofItem{}
	for _, f := range found {
		if pyTruthy(objAt(orEmpty(objAt(f, "bounty")), "policy_checks")) {
			continue
		}
		items = append(items, proofItem{objStr(f, "finding_id"),
			"bounty gate never evaluated"})
	}
	missing := unwaived(items, wmap, func(s, m string) string { return s + ": " + m })
	note := "findings await the bounty gate"
	if len(missing) == 0 {
		note = "gate evaluated for every CONFIRMED finding"
	}
	return proofResult(len(missing) == 0, missing, note), nil
}

// proofReport is the report-freshness proof (Go is the source of truth —
// feedback-triage A8). The reference compared the report's state-head stamp
// against the ABSOLUTE log head with strict equality; but generate() stamps
// the head it read and THEN logs its own events (artifact refresh +
// report.generated), so that equality could never pass for a real report and
// the proof sat permanently red. The Go rule: the report is fresh iff the
// LAST event in the log IS the report's own report.generated — i.e. nothing
// has been logged since its generation. Fail-closed: an empty log, or a log
// that was never generated (a hand-written report), is stale.
func proofReport(c *state.Campaign) (validation.Value, error) {
	p := filepath.Join(campaignDir(c), "report.md")
	if !fileExists(p) {
		return proofResult(false, []string{"report.md — report.generate()"},
			"no report"), nil
	}
	events, err := c.Events()
	if err != nil {
		return validation.VNull(), err
	}
	headHash := ""
	fresh := false
	if len(events) > 0 {
		head := events[len(events)-1]
		if h := objAt(head, "event_hash"); h.Kind == validation.Str {
			headHash = h.S
		}
		fresh = objStr(head, "type") == "report.generated"
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return validation.VNull(), err
	}
	// The stamp is informational only under the Go rule (it names the head
	// the report was generated from, for the stale message).
	// read_text(errors="replace") semantics: invalid UTF-8 becomes U+FFFD.
	text := strings.ToValidUTF8(string(raw), "\uFFFD")
	stamped, found := stampOf(text)
	if fresh {
		return proofResult(true, []string{}, "report fresh"), nil
	}
	repr := "None"
	if found {
		repr = validation.PyReprStr(stamped)
	}
	msg := fmt.Sprintf("report.md is stale (generated at log head %s, "+
		"head is %s) — regenerate", repr, validation.PyReprStr(headHash))
	return proofResult(false, []string{msg}, "stale report"), nil
}

// stampOf is the `<!-- state-head: <hash> -->` scan: the first matching line
// wins, and the hash is line.split(":", 1)[1].strip().rstrip("->").strip().
func stampOf(text string) (string, bool) {
	for _, line := range pySplitLines(text) {
		if !strings.HasPrefix(line, "<!-- state-head:") {
			continue
		}
		rest := strings.SplitN(line, ":", 2)[1]
		rest = pyStrip(rest)
		rest = strings.TrimRight(rest, "->")
		return pyStrip(rest), true
	}
	return "", false
}

// proofLearning is _proof_learning: every terminal finding needs a memory
// entry, and the campaign needs a reflection entry.
func proofLearning(c *state.Campaign) (validation.Value, error) {
	wmap, err := waiverMap(c, "learning")
	if err != nil {
		return validation.VNull(), err
	}
	mems := []validation.Value{}
	if dirExists(c.MemoryDir) {
		matches := validation.ListPrefixed(c.MemoryDir, "MEM-", ".json")
		if err != nil {
			return validation.VNull(), err
		}
		sort.Strings(matches)
		for _, p := range matches {
			m, err := validation.ReadJson(p)
			if err != nil {
				return validation.VNull(), err
			}
			mems = append(mems, m)
		}
	}
	linked := map[string]bool{}
	for _, m := range mems {
		if fid := objStr(m, "finding_id"); fid != "" {
			linked[fid] = true
		}
	}
	items := []proofItem{}
	terminal, err := findingsWith(c, TerminalStatuses)
	if err != nil {
		return validation.VNull(), err
	}
	for _, f := range terminal {
		fid := objStr(f, "finding_id")
		if linked[fid] {
			continue
		}
		items = append(items, proofItem{fid,
			"no memory entry for this terminal finding (learning.queue_memory)"})
	}
	lp := filepath.Join(campaignDir(c), "learnings.jsonl")
	reflected := false
	if raw, err := os.ReadFile(lp); err == nil {
		reflected = pyStrip(string(raw)) != ""
	}
	if !reflected {
		items = append(items, proofItem{"*",
			"no reflection entry (learning.reflection_entry)"})
	}
	missing := unwaived(items, wmap, func(s, m string) string { return s + ": " + m })
	note := "learning artifacts missing"
	if len(missing) == 0 {
		note = "memory + reflection complete"
	}
	return proofResult(len(missing) == 0, missing, note), nil
}
