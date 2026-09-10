package cli

// help_test.go: every registered command must answer -h/--help the way
// argparse does — the command's usage block on stdout, exit 0 — because the
// runbook and the notes both promise `webv2 <cmd> --help`, and 23 verbs used to
// either reject the flag or exit 2 on a missing required argument (recorded in
// docs/runbook-go-notes.md 3a).
//
// The flag has to short-circuit BEFORE any argument validation and before any
// state access: this test runs against a workspace that has no campaign at all,
// which is exactly how an operator asks for help.

import (
	"bytes"
	"strings"
	"testing"
)

func TestEveryCommandAnswersHelp(t *testing.T) {
	for _, c := range registered {
		for _, flag := range []string{"-h", "--help"} {
			var out, errOut bytes.Buffer
			code := Run([]string{c.name, flag}, &out, &errOut)
			if code != 0 {
				t.Errorf("%s %s: exit %d, want 0 (stderr: %q)",
					c.name, flag, code, errOut.String())
			}
			if !strings.Contains(out.String(), "usage: webv2 "+c.name) {
				t.Errorf("%s %s: stdout does not name the command's usage; "+
					"got %q", c.name, flag, firstLine(out.String()))
			}
		}
	}
}

// TestHelpPrecedesArgumentValidation pins the ordering rule: argparse answers
// help before it complains about anything missing, so a bare `-h` with no
// campaign/positional must still exit 0 rather than 2.
func TestHelpPrecedesArgumentValidation(t *testing.T) {
	for _, c := range registered {
		var out, errOut bytes.Buffer
		code := Run([]string{c.name, "-h"}, &out, &errOut)
		if code != 0 {
			t.Errorf("%s -h with no arguments: exit %d, want 0", c.name, code)
		}
		if strings.Contains(errOut.String(), "error:") {
			t.Errorf("%s -h: wrote an error to stderr: %q", c.name,
				firstLine(errOut.String()))
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
