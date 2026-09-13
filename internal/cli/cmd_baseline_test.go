package cli

import "testing"

// TestBaselineRemoveGhostIsQuietlyIdempotent pins r7's ruling: the twin
// argparse golden captured the twin law — remove is rm-rf-idempotent with
// EMPTY stderr; the critic's "should it be a refusal" dies at the byte
// surface. This test exists so nobody re-adds a note and breaks the
// golden twice.
func TestBaselineRemoveGhostIsQuietlyIdempotent(t *testing.T) {
	root := t.TempDir()
	code, out, errS := run(t, "--root", root, "baseline", "remove",
		"never-registered")
	if code != 0 || out != "baseline never-registered removed\n" ||
		errS != "" {
		t.Fatalf("idempotent-quiet law broken: exit %d out %q err %q",
			code, out, errS)
	}
}
