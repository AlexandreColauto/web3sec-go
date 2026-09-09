package findings

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// ResolveEvidenceRef is _resolve_evidence_ref: resolve one evidence reference
// against a finding's own store, returning the Python ValueError text on a
// miss. Exported for the model boundary's critic pre-validation.
func ResolveEvidenceRef(campaign *state.Campaign, finding validation.Value,
	ref string) error {
	_, err := resolveEvidenceRef(campaign, finding, ref)
	return err
}
