package evalstore

// I1a (Wave I, Task 1): deployed_at rides an evaluation case beside
// created_at.
//
// The two dates answer different questions and must never be conflated:
//
//   - created_at — the INGESTION stamp. AddCase owns it (SetDefault), it is
//     always present, and it says when this row entered the store.
//   - deployed_at — when the underlying bug actually lived on-chain (or the
//     advisory's publication date). It is OPERATOR-SUPPLIED provenance: it
//     may be absent, and the store must never invent it, default it, or
//     overwrite a supplied value with the ingestion stamp.
//
// Validation is presence+string only. A date PARSER is deliberately absent:
// Task 2 (temporal gate) owns the ordering rule and the parse-failure
// posture, so a format gate here would be a second, conflicting rule. The
// backfill in assets/evalsuite/cases.json uses YYYY-MM-DD uniformly and the
// suite test below pins that shape at the test level, not in the schema.

import (
	"regexp"
	"strings"
	"testing"

	"websec/assets"
	"websec/internal/validation"
)

// ymd is the backfill date shape pinned by the suite test (test-level, not a
// schema gate): uniform YYYY-MM-DD.
var ymd = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// TestAddCaseKeepsSuppliedDeployedAt: a case that carries deployed_at keeps
// the EXACT supplied string through AddCase and the on-disk round-trip —
// the store never overwrites it with created_at.
func TestAddCaseKeepsSuppliedDeployedAt(t *testing.T) {
	store(t)
	id := "CASE-" + strings.Repeat("b", 12)
	stored, err := AddCase(caseVal(id,
		kv("deployed_at", validation.VStr("2024-03-14"))))
	if err != nil {
		t.Fatalf("AddCase: %v", err)
	}
	if got := objAt(stored, "deployed_at"); got.Kind != validation.Str || got.S != "2024-03-14" {
		t.Fatalf("supplied deployed_at not preserved: %s", validation.CanonCompact(got))
	}
	// The ingestion stamp is still AddCase's own, distinct from deployed_at.
	if got := objAt(stored, "created_at"); got.Kind != validation.Str || got.S == "2024-03-14" {
		t.Fatalf("created_at overwritten by deployed_at: %s", validation.CanonCompact(got))
	}
	loaded, err := LoadCase(id)
	if err != nil {
		t.Fatalf("LoadCase: %v", err)
	}
	if got := objAt(loaded, "deployed_at"); got.Kind != validation.Str || got.S != "2024-03-14" {
		t.Fatalf("deployed_at lost on the on-disk round-trip: %s", validation.CanonCompact(got))
	}
	if got := VerifyEvalStore(); !got.OK {
		t.Fatalf("verify after deployed_at add: %+v", got)
	}
}

// TestAddCaseWithoutDeployedAtStaysAbsent: no deployed_at in, no deployed_at
// out. AddCase must not default the key (a defaulted date would counterfeit
// provenance) and the row must still validate.
func TestAddCaseWithoutDeployedAtStaysAbsent(t *testing.T) {
	store(t)
	id := "CASE-" + strings.Repeat("c", 12)
	stored, err := AddCase(caseVal(id))
	if err != nil {
		t.Fatalf("AddCase without deployed_at: %v", err)
	}
	if got := objAt(stored, "deployed_at"); got.Kind != validation.Null {
		t.Fatalf("absent deployed_at was defaulted: %s", validation.CanonCompact(got))
	}
	loaded, err := LoadCase(id)
	if err != nil {
		t.Fatalf("LoadCase: %v", err)
	}
	if got := objAt(loaded, "deployed_at"); got.Kind != validation.Null {
		t.Fatalf("absent deployed_at appeared on disk: %s", validation.CanonCompact(got))
	}
}

// TestEvalSuiteRowsCarryDeployedAt: every checked-in suite row validates
// under the amended evaluation_case schema AND carries a backfilled
// YYYY-MM-DD deployed_at. 19 rows is the whole suite (Task 1's 17-row
// backfill scope + Wave J Task 3's two compiler-diversity fixtures); a new
// row without a deployed_at fails here on purpose.
func TestEvalSuiteRowsCarryDeployedAt(t *testing.T) {
	cases, err := assets.LoadEvalCases()
	if err != nil {
		t.Fatalf("LoadEvalCases: %v", err)
	}
	if len(cases) != 19 {
		t.Fatalf("suite has %d rows, want 19 — Task 1 backfills 17, J-diversity adds 2", len(cases))
	}
	for i := range cases {
		c := cases[i]
		if err := validation.Validate(c, "evaluation_case", 1); err != nil {
			t.Fatalf("suite row %d invalid under the amended schema: %v", i, err)
		}
		dep := objAt(c, "deployed_at")
		if dep.Kind != validation.Str {
			t.Fatalf("suite row %d (%s) has no deployed_at", i, objAt(c, "case_id").S)
		}
		if !ymd.MatchString(dep.S) {
			t.Fatalf("suite row %d deployed_at %q is not YYYY-MM-DD",
				i, dep.S)
		}
	}
}
