package cli

// runbook_test.go: the operator runbook is part of the CLI surface, so it gets
// a test. The runbook fell nine verbs behind (every command the improvement
// programme added) because nothing compared the registry to the document; these
// two tests are that comparison.
//
// They check the two mechanical failure modes only:
//
//   - a capability no operator can discover (registered, undocumented);
//   - a documented command that no longer exists (documented, unregistered).
//
// Whether the *prose* is true is the reviewer's job, not the suite's.

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"

	"websec/assets"
)

// runbookText reads the embedded runbook — the exact bytes `init` drops into a
// campaign, so a doc that ships broken fails here rather than in the field.
func runbookText(t *testing.T) string {
	t.Helper()
	b, err := fs.ReadFile(assets.RunbookFS, "runbook/RUNBOOK.md")
	if err != nil {
		t.Fatalf("read embedded runbook: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("embedded runbook is empty")
	}
	return string(b)
}

// runbookDocExempt names registered commands allowed to go undocumented. It is
// empty on purpose: every capability must be discoverable from the runbook.
// Adding an entry is a deliberate, reviewable statement that a command is
// internal — not an escape hatch for forgetting.
var runbookDocExempt = map[string]string{}

// runbookDocOnly names tokens the runbook may use that are not registered
// commands. `help` is rendered by usageText, not registered.
var runbookDocOnly = map[string]bool{"help": true}

// runbookVerbRe matches a command only where the runbook writes commands: at
// the start of a line (inside a fenced block or the cheat sheet). Prose such as
// "the webv2 operator runbook" must not read as a command named `operator`.
var runbookVerbRe = regexp.MustCompile(`(?m)^[ \t]*webv2 ([a-z][a-z0-9-]*)`)

// TestRunbookDocumentsEveryRegisteredVerb is the guard the runbook lacked: add
// a command without documenting it and this fails, naming it.
func TestRunbookDocumentsEveryRegisteredVerb(t *testing.T) {
	text := runbookText(t)
	var missing []string
	for _, c := range registered {
		if _, exempt := runbookDocExempt[c.name]; exempt {
			continue
		}
		// Word boundary on both sides: `webv2 chain` must not be satisfied by
		// `webv2 chains`.
		re := regexp.MustCompile(`webv2 ` + regexp.QuoteMeta(c.name) + `\b`)
		if !re.MatchString(text) {
			missing = append(missing, c.name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("embedded runbook does not document %d registered "+
			"command(s): %s\nAdd each to assets/runbook/RUNBOOK.md (the "+
			"cheat sheet at minimum, and the section that owns it) or, if "+
			"the command is deliberately internal, to runbookDocExempt.",
			len(missing), strings.Join(missing, ", "))
	}
}

// TestRunbookCommandsAreRegistered catches the other direction: the doc naming
// a command the binary does not have (a rename that forgot the runbook).
func TestRunbookCommandsAreRegistered(t *testing.T) {
	text := runbookText(t)
	known := map[string]bool{}
	for _, c := range registered {
		known[c.name] = true
	}
	var stale []string
	seen := map[string]bool{}
	for _, m := range runbookVerbRe.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if seen[name] || known[name] || runbookDocOnly[name] {
			continue
		}
		seen[name] = true
		stale = append(stale, name)
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("embedded runbook names %d command(s) that are not "+
			"registered: %s\nEither register the command or fix the runbook.",
			len(stale), strings.Join(stale, ", "))
	}
}
