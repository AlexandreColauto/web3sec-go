// Trust-boundary concern: _boundary_matrix(), the compact matrix the
// boundary stages get in their context bundle.
package adapter

import (
	"fmt"
	"strings"
)

// boundaryStages are the stages that get the boundary matrix.
var boundaryStages = map[string]bool{
	"discovery": true, "reproduction": true, "hostile-review": true,
	"independent-verification": true,
}

// BoundaryMatrix is _boundary_matrix(): the trust boundary between the model
// and the deterministic core as a compact matrix.
func BoundaryMatrix() string {
	rows := [][3]string{
		{"evidence E0-E3", "may claim, with written reasoning",
			"stored after schema validation"},
		{"evidence E4+", "CANNOT claim — must name a real EXEC id from THIS campaign",
			"add_evidence() verifies profile, exit 0, captured output"},
		{"independent repro", "must be a DIFFERENT verifier + different exec",
			"mint_independent_evidence enforces it"},
		{"status transitions", "may propose via the API",
			"code enforces the state machine; illegal moves raise"},
		{"CONFIRMED floor", "no authority — floors are data, not opinion",
			"the gate uses the campaign effective floor (override or default)"},
		{"floor overrides", "CANNOT set",
			"operator-only: floors.set_floor_policy, actor+reason, logged"},
		{"bug classes", "use taxonomy.known_classes()",
			"unknown classes raise an intake advisory + default E5 floor"},
		{"discovery budget", "each ingest consumes a slot",
			"code enforces max_discovery_findings"},
		{"repro evidence mint", "propose tier + evidence_type",
			"mint validates the type and is idempotent (same exec -> same finding)"},
	}
	out := []string{"BOUNDARY MATRIX — trust boundary between you and the deterministic core.",
		"You may produce the left column; ONLY code performs the right column:"}
	for _, r := range rows {
		out = append(out, fmt.Sprintf("  %-22s | %-52s | %s", r[0], r[1], r[2]))
	}
	out = append(out, "An evidence claim that names no real EXEC id, or a status jump the")
	out = append(out, "state machine forbids, is rejected — never assumed true.")
	return strings.Join(out, "\n")
}
