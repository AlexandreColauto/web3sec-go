package findings

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestIngestRefusesEscapingAffectedPaths pins r6 issue 6: affected.path is a
// claim about the pinned tree; ..-escapes and absolute paths die at intake.
func TestIngestRefusesEscapingAffectedPaths(t *testing.T) {
	for _, bad := range []string{"../../../../etc/passwd", "/etc/passwd",
		"src/../secrets/key.pem", "weird//double", "trailing/"} {
		c := ingestCamp(t)
		p := hypoPayload()
		aff := objAt(p, "affected")
		aff.A[0].O = validation.SetOrAppend(aff.A[0].O, "path",
			validation.VStr(bad))
		_, err := IngestHypothesis(c, p, "code", "", "")
		if err == nil || !strings.Contains(err.Error(),
			"the pinned tree") {
			t.Fatalf("path %q must be refused, got %v", bad, err)
		}
	}
	// In-tree oddities stay legal (dot-names included — they are real).
	c := ingestCamp(t)
	p := hypoPayload()
	aff := objAt(p, "affected")
	aff.A[0].O = validation.SetOrAppend(aff.A[0].O, "path",
		validation.VStr(".github/workflows/ci.yml"))
	if _, err := IngestHypothesis(c, p, "code", "", ""); err != nil {
		t.Fatalf("legit dot-path refused: %v", err)
	}
}
