// Invariant exec matching — the exec-relevance gate: command-token matching against applies_to (split from invariants.go; pure structural move).

package invariants

import (
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// ExecTouchesInvariant is the exec-relevance gate: a cited exec only counts as
// a check of this invariant when the command it RAN targeted one of the
// entry's applies_to contracts. The captured output cannot decide this — a
// Foundry full-suite run names every contract in its log, so an exec can cite
// an invariant it never touched — hence the gate reads the recorded command
// line, never the log.
//
// An invariant bound to nothing cannot be exec-verified: empty applies_to is
// unbound, never a wildcard (the same law Task 4 pins for artifact
// references). The token set comes from applies_to ALONE — the invariant id is
// deliberately out of scope, because `--match-contract INV-3` names the
// bookkeeping id, not a contract.
//
// Reasons: "no-exec-record" (no such exec, or an exec store that cannot be
// read), "no-command-record" (the record carries no command line), and
// "no-target-match" (no applies_to token occurs at a left boundary).
func ExecTouchesInvariant(c *state.Campaign, invID, execID string) (bool, string) {
	execs, err := state.AllExecs(c)
	if err != nil {
		// A store that cannot be read names no exec: fail closed.
		return false, "no-exec-record"
	}
	var rec validation.Value
	found := false
	for _, e := range execs {
		if validation.ObjStr(e, "exec_id") == execID {
			rec, found = e, true
			break
		}
	}
	if !found {
		return false, "no-exec-record"
	}
	command := stripShellQuotes(validation.ObjStr(rec, "command"))
	if command == "" {
		return false, "no-command-record"
	}
	links, err := LoadLinks(c)
	if err != nil {
		// No readable registry, no applies_to targets: fail closed.
		return false, "no-target-match"
	}
	for _, tok := range appliesToTokens(validation.ObjAt(regOf(links), invID)) {
		if tokenOccursLeftBound(command, tok) {
			return true, ""
		}
	}
	return false, "no-target-match"
}

// appliesToTokens is the exec-relevance token set: every applies_to string in
// its recorded spelling and in NormalizeInvID's canonical one, deduplicated,
// empties dropped. Unlike referenceTokens it excludes the invariant id — see
// ExecTouchesInvariant.
func appliesToTokens(entry validation.Value) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range validation.ObjAt(entry, "applies_to").A {
		if t.Kind != validation.Str {
			continue
		}
		for _, tok := range []string{t.S, NormalizeInvID(t.S)} {
			if tok == "" || seen[tok] {
				continue
			}
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out
}

// tokenOccursLeftBound reports whether command contains token starting at a
// left boundary: the match begins the string, or the character before it is
// outside [0-9a-z_]. Matching is case-insensitive and there is deliberately NO
// trailing boundary.
//
// This intentionally differs from the Task 4 artifact matcher
// (artifactReferencesInvariant), which requires a full \b...\b word match.
// Foundry's --match-contract is a regex/prefix filter, so \bStaking\b would
// reject `--match-contract StakingTest` — exactly the targeted command this
// gate must accept — while the left boundary is what keeps `Unstaking` out.
// The Task 4 matcher stays byte-identical: its refusals are pinned.
func tokenOccursLeftBound(command, token string) bool {
	if token == "" {
		return false
	}
	cmd := strings.ToLower(command)
	tok := strings.ToLower(token)
	for from := 0; from < len(cmd); {
		i := strings.Index(cmd[from:], tok)
		if i < 0 {
			return false
		}
		at := from + i
		if at == 0 || !isLowerWordByte(cmd[at-1]) {
			return true
		}
		from = at + 1
	}
	return false
}

// isLowerWordByte is the left-boundary alphabet on the lowered command:
// [0-9a-z_] — the characters a contract name can be glued to.
func isLowerWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z')
}

// stripShellQuotes removes one layer of matching surrounding quotes from a
// recorded command line.
func stripShellQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
