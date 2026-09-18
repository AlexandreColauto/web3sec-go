package state

// B6a — the unknown-artifact refusal is TYPED.
//
// The three producers (Artifact, PruneArtifact, refreshArtCtx.findRow) used to
// build the KeyError with a bare fmt.Errorf; they now return
// *UnknownArtifactError. The contract this test pins is twofold: the message
// stays byte-identical to the copy the Python-parity tests pin EXACT
// (artifacts_test.go:339/:497/:612 — a reword here breaks three other tests,
// which is the point), and the failure is now identifiable structurally, so an
// operator-facing caller can decide what to print without re-matching that
// copy.

import (
	"errors"
	"testing"
)

func TestUnknownArtifactErrorIsTypedAndBytePinned(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	const id = "ART-nope1234"

	_, artErr := c.Artifact(id)
	_, pruneErr := c.PruneArtifact(id, "")
	_, refreshErr := c.RefreshArtifact(id, "r", "op")

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"Artifact", artErr},
		{"PruneArtifact", pruneErr},
		{"RefreshArtifact", refreshErr},
	} {
		if tc.err == nil {
			t.Fatalf("%s: expected the unknown-artifact refusal", tc.name)
		}
		if got := tc.err.Error(); got != "unknown artifact 'ART-nope1234'" {
			t.Errorf("%s: message %q, want the pinned KeyError copy",
				tc.name, got)
		}
		var uae *UnknownArtifactError
		if !errors.As(tc.err, &uae) {
			t.Errorf("%s: %T is not *UnknownArtifactError — the CLI's heal "+
				"pointer would stop firing", tc.name, tc.err)
			continue
		}
		if uae.ID != id {
			t.Errorf("%s: typed ID %q, want %q", tc.name, uae.ID, id)
		}
	}
}

// TestUnknownArtifactErrorQuotesLikeTheReference: Error() must repr-quote, not
// interpolate: an id holding a quote is rendered the way Python's KeyError is.
func TestUnknownArtifactErrorQuotesLikeTheReference(t *testing.T) {
	err := error(&UnknownArtifactError{ID: "ART-o'brien"})
	if got, want := err.Error(), `unknown artifact "ART-o'brien"`; got != want {
		t.Fatalf("message %q, want %q", got, want)
	}
}
