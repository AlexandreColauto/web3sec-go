package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r40d — unwind-on-refusal pin for the risk package's finding writers. The
// honest refusal an operator can always hit: grow the ledger, then cut
// events.jsonl to a shorter PREFIX so the state mirror is LONGER than the
// log — the next Log refuses with "events.jsonl holds N event(s) but the
// state projection mirrors M ... run webv2 doctor".
//
// Before r40 RecordEconomicImpact / RecordUnpriceable / Calibrate /
// RecordReversibility saved the finding file and then logged with no
// restore: a refused event left economic numbers, a priceable:false NAMED
// DECISION (the exact shape findings.UnpriceableDecision reads back
// state-only and audit red-lines when hand-edited), or a gate-read risk
// band on disk that the ledger never recorded. The pin: the finding file's
// sha256 is byte-identical across the refusal (clock pinned so a half-land
// WOULD have moved the updated_at stamp), no event of any kind in the chain
// lands, and the honest path still works.
// ---------------------------------------------------------------------------

// r40dSha is the sha256 of one file (or "absent"), the byte-identity pin.
func r40dSha(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// r40dEventCount counts the ledger's anchors of one event type.
func r40dEventCount(t *testing.T, c *state.Campaign, eventType string) int {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return strings.Count(string(raw), `"`+eventType+`"`)
}

// r40dCutLedger grows the ledger a few events, then cuts events.jsonl to a
// shorter prefix so the state mirror is LONGER than the log. Returns the
// full bytes (the sanctioned out-of-band repair: restore the cut tail).
func r40dCutLedger(t *testing.T, c *state.Campaign) []byte {
	t.Helper()
	for i := 0; i < 3; i++ {
		data := validation.VObj(validation.KV{K: "note",
			V: validation.VStr("r40d ledger growth")})
		if _, err := c.Log("note.added", nil, &data); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("ledger too short to cut: %d line(s)", len(lines))
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return raw
}

// r40dRefuse runs one verb on a cut ledger and pins the unwind: the finding
// file's bytes are identical, no event of the named types landed. Returns
// the cut ledger bytes so the caller can repair.
func r40dRefuse(t *testing.T, c *state.Campaign, fid string,
	eventTypes []string, call func() error) []byte {
	t.Helper()
	path := findingsPathFor(t, c, fid)
	before := r40dSha(t, path)
	baselines := map[string]int{}
	for _, ev := range eventTypes {
		baselines[ev] = r40dEventCount(t, c, ev)
	}
	cut := r40dCutLedger(t, c)
	err := call()
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("err = %v (want the projection refusal)", err)
	}
	if got := r40dSha(t, path); got != before {
		t.Fatalf("finding bytes moved across the refusal (the state write "+
			"without its event):\n before %s\n after  %s", before, got)
	}
	for _, ev := range eventTypes {
		if got := r40dEventCount(t, c, ev); got != baselines[ev] {
			t.Fatalf("%s events = %d, want %d (the refusal must add none)",
				ev, got, baselines[ev])
		}
	}
	return cut
}

func findingsPathFor(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	return findings.FindingPath(c, fid)
}

// TestR40DRefusedImpactAndUnpriceableRestoreFindingBytes pins the two
// compound verbs: a refusal anywhere in the chain (this verb's save,
// Calibrate's nested save, or either event) must unwind to the pre-verb
// bytes, with NEITHER the verb's event NOR finding.calibrated landing.
func TestR40DRefusedImpactAndUnpriceableRestoreFindingBytes(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")

	// RecordEconomicImpact.
	c := riskCamp(t)
	fid := ingest(t, c)
	events := []string{"finding.impact_recorded", "finding.calibrated"}
	raw := r40dRefuse(t, c, fid, events, func() error {
		_, err := RecordEconomicImpact(c, fid, validation.VFloat(800_000),
			validation.VFloat(1_200_000), validation.VNull())
		return err
	})
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordEconomicImpact(c, fid, validation.VFloat(800_000),
		validation.VFloat(1_200_000), validation.VNull()); err != nil {
		t.Fatalf("retry impact on a repaired ledger: %v", err)
	}
	if got := r40dEventCount(t, c, "finding.impact_recorded"); got != 1 {
		t.Fatalf("impact_recorded events = %d, want 1", got)
	}
	if got := r40dEventCount(t, c, "finding.calibrated"); got != 1 {
		t.Fatalf("calibrated events after impact retry = %d, want 1", got)
	}

	// RecordUnpriceable (fresh campaign: priceable was just set true).
	t.Setenv("WEBV2_NOW", "2026-01-02T00:00:00.000000+00:00")
	c2 := riskCamp(t)
	fid2 := ingest(t, c2)
	raw2 := r40dRefuse(t, c2, fid2,
		[]string{"finding.unpriceable", "finding.calibrated"},
		func() error {
			_, err := RecordUnpriceable(c2, fid2, "address[255] slot",
				"r40d: no defensible number exists for this impact",
				"operator")
			return err
		})
	if err := os.WriteFile(c2.EventsPath, raw2, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordUnpriceable(c2, fid2, "address[255] slot",
		"r40d: no defensible number exists for this impact",
		"operator"); err != nil {
		t.Fatalf("retry unpriceable on a repaired ledger: %v", err)
	}
	f, err := findings.LoadFinding(c2, fid2)
	if err != nil {
		t.Fatal(err)
	}
	if v := validation.ObjAt(validation.ObjAt(f, "economic_impact"), "priceable"); v.Kind != validation.Bool || v.B {
		t.Fatalf("retried decision did not store priceable:false: %v", v)
	}
	if got := r40dEventCount(t, c2, "finding.unpriceable"); got != 1 {
		t.Fatalf("unpriceable events = %d, want 1", got)
	}
}

// TestR40DRefusedCalibrateRestoresFindingBytes pins Calibrate directly: the
// risk block (band included) is gate-read state.
func TestR40DRefusedCalibrateRestoresFindingBytes(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-03T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	raw := r40dRefuse(t, c, fid, []string{"finding.calibrated"},
		func() error {
			_, err := Calibrate(c, fid)
			return err
		})
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Calibrate(c, fid); err != nil {
		t.Fatalf("retry calibrate on a repaired ledger: %v", err)
	}
	if got := r40dEventCount(t, c, "finding.calibrated"); got != 1 {
		t.Fatalf("calibrated events = %d, want 1", got)
	}
}

// TestR40DRefusedReversibilityRestoresFindingBytes pins RecordReversibility:
// the classification is a named weight in validated_risk.
func TestR40DRefusedReversibilityRestoresFindingBytes(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-04T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	raw := r40dRefuse(t, c, fid,
		[]string{"finding.reversibility_set", "finding.calibrated"},
		func() error {
			_, err := RecordReversibility(c, fid, "irreversible")
			return err
		})
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordReversibility(c, fid, "irreversible"); err != nil {
		t.Fatalf("retry reversibility on a repaired ledger: %v", err)
	}
	if got := r40dEventCount(t, c, "finding.reversibility_set"); got != 1 {
		t.Fatalf("reversibility_set events = %d, want 1", got)
	}
}
