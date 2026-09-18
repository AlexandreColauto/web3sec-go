package state

import "websec/internal/validation"

// UnknownArtifactError is the registry's "unknown artifact '<id>'" refusal:
// the KeyError the reference Python raises for an id no row in
// campaign_state.artifacts names. Its producers are Artifact
// (artifacts.go:124), PruneArtifact (artifacts.go:170) and
// refreshArtCtx.findRow (artifacts_refresh.go:99).
//
// The message is byte-identical to the fmt.Errorf those sites used to return
// — internal/state/artifacts_test.go pins err.Error() EXACT at all three
// ("unknown artifact 'ART-nope1234'", :339/:497/:612) and the CLI renders the
// same string through validation.PyReprStr — but carrying a TYPE lets an
// operator-facing caller answer "is this failure the unknown-artifact
// reason?" structurally, with errors.As, instead of re-matching a copy whose
// exact spelling is owned by those Python-parity pins.
// cmd_invariant_verify.go (B6a) is the first such caller: it appends a
// register-it-first heal line to this reason only.
type UnknownArtifactError struct {
	// ID is the id (or path-shaped token) the caller asked for, verbatim:
	// Error repr-quotes it exactly as the reference does.
	ID string
}

// Error is the pinned reference text, repr quoting included.
func (e *UnknownArtifactError) Error() string {
	return "unknown artifact " + validation.PyReprStr(e.ID)
}
