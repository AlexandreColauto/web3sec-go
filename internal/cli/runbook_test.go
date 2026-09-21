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
	"os"
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

// ---------------------------------------------------------------------------
// The walkthrough's citations
// ---------------------------------------------------------------------------

// walkthroughCheck is one `check <name> <expect> <marker> <anchor> -- argv`
// row of scripts/runbook-walkthrough.sh.
type walkthroughCheck struct {
	line   int
	name   string
	anchor string
	verb   string
}

var walkthroughCheckRe = regexp.MustCompile(
	`^\s*check (\S+) (\S+) (?:'[^']*'|"[^"]*"|\S+) (\S+) -- (.*)$`)

// sectionAnchorOf maps a runbook heading to the anchor the walkthrough cites.
// Numbered headings derive their own anchor ("## 4a. ..." is §4a); the
// unnumbered ones are named here, and that table IS the contract: rename a
// heading and this test fails rather than letting a label rot.
var sectionAnchorOf = map[string]string{
	"Evidence levels, floors, and the gate":                    "§floors",
	"CLI cheat sheet":                                          "§cheat",
	"Environment variables":                                    "§env",
	"Hard rules for the operator":                              "§rules",
	"Who pays, and why the bug makes them pay (check14)":       "§7i",
	"The patch clause: what `immunize` records (check12)":      "§7p",
	"When no dollar figure is defensible (unpriceable impact)": "§7u",
	"webv2 operator runbook (Go)":                              "§top",
}

var headingRe = regexp.MustCompile(`^(#{1,3}) (.+?)\s*$`)
var numberedHeadingRe = regexp.MustCompile(`^(\d+[a-z]?)\.`)

// runbookSections splits the runbook into anchor -> body.
func runbookSections(t *testing.T, text string) map[string]string {
	t.Helper()
	lines := strings.Split(text, "\n")
	type head struct {
		anchor string
		start  int
	}
	heads := []head{}
	for i, l := range lines {
		m := headingRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		title := m[2]
		anchor := sectionAnchorOf[title]
		if anchor == "" {
			if n := numberedHeadingRe.FindStringSubmatch(title); n != nil {
				anchor = "§" + n[1]
			}
		}
		if anchor == "" {
			t.Fatalf("runbook heading %q has no anchor: add it to "+
				"sectionAnchorOf and cite it from the walkthrough", title)
		}
		heads = append(heads, head{anchor, i})
	}
	out := map[string]string{}
	for n, h := range heads {
		end := len(lines)
		if n+1 < len(heads) {
			end = heads[n+1].start
		}
		out[h.anchor] = strings.Join(lines[h.start:end], "\n")
	}
	return out
}

// walkthroughChecks parses every check row (top-level and nested) of the
// walkthrough.
func walkthroughChecks(t *testing.T, text string) []walkthroughCheck {
	t.Helper()
	out := []walkthroughCheck{}
	for i, l := range strings.Split(text, "\n") {
		m := walkthroughCheckRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		argv := strings.ReplaceAll(m[4], `"$WEBV2"`, " ")
		argv = strings.ReplaceAll(argv, "--root .", " ")
		verb := ""
		for _, tok := range strings.Fields(argv) {
			if strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, `"`) {
				continue
			}
			verb = strings.Trim(tok, `"'`)
			break
		}
		out = append(out, walkthroughCheck{i + 1, m[1], m[3], verb})
	}
	return out
}

// TestWalkthroughAnchorsPointAtTheRunbook is the label contract. The
// walkthrough once cited runbook LINE NUMBERS: every edit above a citation
// silently moved it, and the labels were wrong for months. Section anchors
// cannot rot that way, but they can still be pointed at the wrong section, so
// each row must cite a real section — and that section has to mention the
// command the row exercises.
func TestWalkthroughAnchorsPointAtTheRunbook(t *testing.T) {
	wt, err := os.ReadFile("../../scripts/runbook-walkthrough.sh")
	if err != nil {
		t.Fatalf("read walkthrough: %v", err)
	}
	sections := runbookSections(t, runbookText(t))
	checks := walkthroughChecks(t, string(wt))
	if len(checks) < 100 {
		t.Fatalf("only %d checks parsed — the walkthrough format changed "+
			"and this test stopped seeing it", len(checks))
	}
	seen := map[string]int{}
	for _, c := range checks {
		if !strings.HasPrefix(c.anchor, "§") {
			t.Errorf("line %d (%s): label %q is not a section anchor — line "+
				"numbers rot; cite the section that documents the command",
				c.line, c.name, c.anchor)
			continue
		}
		body, ok := sections[c.anchor]
		if !ok {
			t.Errorf("line %d (%s): %s is not a runbook section", c.line,
				c.name, c.anchor)
			continue
		}
		if c.verb == "" {
			t.Errorf("line %d (%s): no verb parsed from the argv", c.line,
				c.name)
			continue
		}
		if !strings.Contains(body, c.verb) {
			t.Errorf("line %d (%s): %s does not mention %q — point the row "+
				"at the section that documents it, or document the command "+
				"there", c.line, c.name, c.anchor, c.verb)
		}
		seen[c.anchor]++
	}
	// The anchors are meant to spread across the runbook: one anchor taking
	// most of the table means the mapping collapsed to a fallback.
	if seen["§cheat"] == len(checks) {
		t.Errorf("every check cites §cheat — the anchors carry no information")
	}
}

// TestRunbookDocumentsTheReplayFamily is the critic I-1 guard on the runbook
// half of the finding: `impact` was already documented, so the verb-level
// checks above passed while the §2.4 flag family appeared nowhere in the
// operator's one-page reference. The cheat-sheet line is the surface an
// operator reads before a run, so it must name every accepted flag.
func TestRunbookDocumentsTheReplayFamily(t *testing.T) {
	text := runbookText(t)
	// The cheat sheet's canonical line uses the `<C>` placeholder form; the
	// walkthrough examples spell a real campaign id (`<C-xxx>`) and are not
	// the flag reference.
	line := ""
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "webv2 impact <C> ") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("the runbook has no `webv2 impact <C>` cheat-sheet line")
	}
	for _, flag := range impactReplayFlags {
		if !strings.Contains(line, flag) {
			t.Errorf("the runbook's impact line omits %s:\n%s", flag, line)
		}
	}
}
