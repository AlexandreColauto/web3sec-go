package findings

import "websec/internal/validation"

// InvariantIDs is _invariant_ids: every invariant id a finding hangs off
// (singular + structured list), in canonical form. Exported for roles'
// invariant-verification block (the one cross-package consumer).
func InvariantIDs(finding validation.Value) []string { return invariantIDs(finding) }
