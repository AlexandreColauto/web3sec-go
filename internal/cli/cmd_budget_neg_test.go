// T26: argparse's negative-number rule, shared by the T26 parsers.
package cli

import "testing"

func TestIsNegNumberCLI(t *testing.T) {
	cases := map[string]bool{
		"-1":     true,
		"-0":     true,
		"-1.5":   true,
		"-.5":    true,
		"-":      false,
		"":       false,
		"1":      false,
		"--json": false,
		"-x":     false,
		"-1x":    false,
		"-1.2.3": false,
		"-.":     false,
		"-1-":    false,
	}
	for in, want := range cases {
		if got := isNegNumberCLI(in); got != want {
			t.Errorf("isNegNumberCLI(%q) = %v, want %v", in, got, want)
		}
	}
}
