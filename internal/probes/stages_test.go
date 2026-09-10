package probes

// stages_test.go pins the C1 surface enrichment and, just as importantly, that
// it is opt-in: the zero ProbeOpts reproduces the reference surface exactly
// (the parity goldens own that byte-for-byte claim), while the shipped
// ProdProbeOpts adds the enforcement stage pairs to the assertion-strength
// rows and still validates against probe_surface.schema.json.

import (
	"testing"

	"websec/internal/validation"
)

// enrichedSurface builds the fixture surface with the shipped options.
func enrichedSurface(t *testing.T, fixture string) validation.Value {
	t.Helper()
	surface, err := BuildSurfaceOpts(parityLoad(t, "index_"+fixture),
		parityLoad(t, "model"), 12, 40, 3, "2026-01-01T00:00:00Z", ProdProbeOpts())
	if err != nil {
		t.Fatalf("build %s: %v", fixture, err)
	}
	return surface
}

// assertionRows are the assertion-strength rows of a surface.
func assertionRows(surface validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, r := range vList(surface, "rows") {
		if vStr(r, "probe") == "assertion-strength" {
			out = append(out, r)
		}
	}
	return out
}

// TestStageTablesEnrichment: the shipped surface carries the deterministic
// (write, read) stage pairs of an assertion row's concept keys, scoped to the
// row's contract, and the schema accepts them.
func TestStageTablesEnrichment(t *testing.T) {
	surface := enrichedSurface(t, "assertion_buggy")
	rows := assertionRows(surface)
	if len(rows) == 0 {
		t.Fatal("fixture has no assertion-strength row to enrich")
	}
	enriched := 0
	for _, row := range rows {
		stages := vGet(row, "stages_unguarded")
		if stages.Kind != validation.Arr {
			continue
		}
		enriched++
		total := vGet(row, "stages_unguarded_total")
		if total.Kind != validation.Int || total.I != int64(len(stages.A)) {
			t.Errorf("stages_unguarded_total %v != %d pairs", total, len(stages.A))
		}
		keys := vStrList(row, "concept_keys")
		for _, p := range stages.A {
			if got := vStr(p, "contract"); got != vStr(row, "contract") {
				t.Errorf("pair contract %q outside the row's contract %q",
					got, vStr(row, "contract"))
			}
			if !containsString(keys, vStr(p, "concept")) {
				t.Errorf("pair concept %q is not one of the row's keys %v",
					vStr(p, "concept"), keys)
			}
			for _, kind := range []string{"write", "read"} {
				site := vGet(p, kind)
				if got := vStr(site, "kind"); got != kind {
					t.Errorf("pair %s site kind = %q", kind, got)
				}
				if vStr(site, "function") == "" {
					t.Errorf("pair %s site has no function", kind)
				}
				if vGet(site, "line").Kind != validation.Int {
					t.Errorf("pair %s site has no line", kind)
				}
			}
			// A carried pair is a gap: its write side is unguarded.
			if b := vGet(p, "write_guarded"); b.Kind != validation.Bool || b.B {
				t.Errorf("carried pair should have an unguarded write side")
			}
		}
	}
	if enriched == 0 {
		t.Fatal("no assertion row was enriched: the stage table went missing")
	}
	if err := validation.Validate(surface, "probe_surface", 1); err != nil {
		t.Fatalf("enriched surface fails its own schema: %v", err)
	}
}

// TestStageTablesOptIn: the zero ProbeOpts is the reference surface — no row
// carries the enrichment — so the parity goldens keep pinning the port.
func TestStageTablesOptIn(t *testing.T) {
	plain, err := BuildSurface(parityLoad(t, "index_assertion_buggy"),
		parityLoad(t, "model"), 12, 40, 3, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, row := range vList(plain, "rows") {
		if _, ok := vGetPresent(row, "stages_unguarded"); ok {
			t.Fatalf("row %s carries the C1 enrichment without opting in",
				vStr(row, "row_id"))
		}
		if _, ok := vGetPresent(row, "stages_unguarded_total"); ok {
			t.Fatalf("row %s carries stages_unguarded_total without opting in",
				vStr(row, "row_id"))
		}
	}
	parityEqual(t, "surface_assertion_buggy", plain,
		parityLoad(t, "surface_assertion_buggy"))
}

// TestStageTablesSurviveQuota: enrichment happens before the quota slice, so
// an emitted row still carries its pairs.
func TestStageTablesSurviveQuota(t *testing.T) {
	surface := enrichedSurface(t, "siblings")
	carried := 0
	for _, row := range assertionRows(surface) {
		if vGet(row, "stages_unguarded").Kind == validation.Arr {
			carried++
		}
	}
	if carried == 0 {
		t.Fatalf("siblings assertion rows lost their pair data under the quota")
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
