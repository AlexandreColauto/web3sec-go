package invariants

import "websec/internal/validation"

import "testing"

// Port of tests/test_review_fixes.py::test_link_test_requires_registered_artifact:
// link_test must reject an artifact id that was never registered, and the
// honest path lands test_status "held".
func TestLinkTestRequiresRegisteredArtifact(t *testing.T) {
	c := invCamp(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	_, err := LinkTest(c, "INV-1", "POC-doesnotexist")
	wantErr(t, err, "unknown artifact")

	artID := registeredArtifact(t, c, "t_test.sol", "test")
	e, err := LinkTest(c, "INV-1", artID)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(e, "test_status"); got != "held" {
		t.Errorf("test_status = %q, want held", got)
	}
}
