package cli

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestWaiveVocabularyIsReadByProofs pins critic r3: every accepted waive
// stage must be READ by a completion proof or a bounty gate — and every
// waiverMap consumer name must be accepted here. The pairing is checked
// against the proof source itself, so neither list can drift silently.
func TestWaiveVocabularyIsReadByProofs(t *testing.T) {
	read := map[string]bool{}
	for _, f := range []string{
		"../completion/proofs.go", "../completion/proofs2.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range regexp.MustCompile(`waiverMap\(c, "([a-z-]+)"\)`).
			FindAllStringSubmatch(string(raw), -1) {
			read[m[1]] = true
		}
	}
	if len(read) == 0 {
		t.Fatal("no waiverMap consumers found — this guard is vacuous")
	}
	accepted := map[string]bool{}
	for _, s := range waiveStages() {
		accepted[s] = true
	}
	for s := range read {
		if !accepted[s] {
			t.Errorf("proofs read waiver stage %s but waive refuses it", s)
		}
	}
	// The rails are read by bounty.go (gate checks), not the proof files.
	for _, rail := range waiveCheckStages {
		raw, err := os.ReadFile("../bounty/bounty.go")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "\""+rail+"\"") {
			t.Errorf("rail %s is accepted but bounty.go never names it", rail)
		}
	}
	// Stage-shaped names that satisfy NOTHING stay out (the critic's probe):
	for _, bad := range []string{"protocol-model", "scope", "snapshot",
		"structural-index", "campaign-planning", "chaining", "report"} {
		if accepted[bad] {
			t.Errorf("waive still accepts %s, which no proof reads", bad)
		}
	}
	names := waiveStages()
	if !sort.StringsAreSorted(names) {
		t.Error("waive vocabulary must be sorted for deterministic help text")
	}
}
