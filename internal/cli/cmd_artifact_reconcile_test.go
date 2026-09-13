package cli

// D3 CLI tests — `artifact-reconcile` (ord 75): re-hash the registry against
// the files, refresh what changed, report what is gone, and stay read-only
// under --dry.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func TestArtifactReconcileHelpAndArgparse(t *testing.T) {
	code, out, errS := run(t, "artifact-reconcile", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.HasPrefix(out, artifactReconcileUsage) {
		t.Fatalf("help does not start with the usage block: %q", out)
	}
	code, out, errS = run(t, "artifact-reconcile")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if errS != artifactReconcileUsage+"webv2 artifact-reconcile: error: the "+
		"following arguments are required: campaign\n" {
		t.Fatalf("stderr = %q", errS)
	}
	code, out, errS = run(t, "artifact-reconcile", "C-aaaaaaaaaa", "--bogus")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if errS != t14TopUsage+"webv2: error: unrecognized arguments: --bogus\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestArtifactReconcileRefreshesAndReportsMissing: one rewritten file is
// refreshed, one deleted file is reported, one untouched file is left alone.
func TestArtifactReconcileRefreshesAndReportsMissing(t *testing.T) {
	c, root := t15Campaign(t, "reconcile")
	changed := t15Register(t, c, "report.md", "report", "")
	stable := t15Register(t, c, "plan.md", "plan", "")
	gone := t15Register(t, c, "poc.sol", "poc", "")
	if err := os.WriteFile(filepath.Join(c.Root, "report.md"),
		[]byte("rewritten by someone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(c.Root, "poc.sol")); err != nil {
		t.Fatal(err)
	}
	// dry first: the output must promise the refresh without performing it.
	code, out, errS := run(t, "--root", root, "artifact-reconcile",
		c.CampaignID, "--dry")
	if code != 0 || errS != "" {
		t.Fatalf("dry exit %d err %q", code, errS)
	}
	for _, want := range []string{
		"artifact reconcile: 3 checked, 1 would refresh, 1 unchanged, 1 missing",
		"  " + changed + "\n",
		"  missing " + gone + "  " + filepath.Join(c.Root, "poc.sol") + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry output missing %q\n%s", want, out)
		}
	}
	if row, err := c.Artifact(changed); err != nil {
		t.Fatal(err)
	} else if v := objAt(row, "refresh_count"); v.Kind == validation.Int {
		t.Errorf("--dry refreshed the row (refresh_count=%d)", v.I)
	}
	// live: the changed row is refreshed and the summary counts it.
	code, out, errS = run(t, "--root", root, "artifact-reconcile", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out,
		"artifact reconcile: 3 checked, 1 refreshed, 1 unchanged, 1 missing\n") {
		t.Errorf("live output:\n%s", out)
	}
	row, err := c.Artifact(changed)
	if err != nil {
		t.Fatal(err)
	}
	if v := objAt(row, "refresh_count"); v.Kind != validation.Int || v.I != 1 {
		t.Errorf("refresh_count after live run: %+v", v)
	}
	// idempotent: nothing left to refresh.
	code, out, errS = run(t, "--root", root, "artifact-reconcile", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out,
		"artifact reconcile: 3 checked, 0 refreshed, 2 unchanged, 1 missing\n") {
		t.Errorf("second run:\n%s", out)
	}
	_ = stable
}

func TestArtifactReconcileUnknownCampaign(t *testing.T) {
	_, root := t15Campaign(t, "reconcile-unknown")
	code, out, errS := run(t, "--root", root, "artifact-reconcile",
		"C-0000000000")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if !strings.Contains(errS, "no such campaign") {
		t.Fatalf("stderr = %q", errS)
	}
}

// ---- T3: model.json vs ledger invariant-status drift ----------------------

// invStatus is one id/status pair in a drift fixture.
type invStatus struct{ id, status string }

// writeInvariantDriftFixture writes the two documents the drift report
// compares: `artifacts/protocol_model.json` (the statuses the MODEL claims)
// and `artifacts/invariant_links.json` (the statuses the ledger — and so the
// gate — holds). Ledger rows carry test_status so they read as current-shaped
// entries: a pre-structured entry is migrated on read, which is a different
// axis from this test. A model entry with an empty status is written with no
// `status` key at all (the schema makes it optional).
func writeInvariantDriftFixture(t *testing.T, c *state.Campaign,
	model, ledger []invStatus) {
	t.Helper()
	invs := make([]validation.Value, 0, len(model))
	for _, s := range model {
		kvs := []validation.KV{kvT("id", validation.VStr(s.id))}
		if s.status != "" {
			kvs = append(kvs, kvT("status", validation.VStr(s.status)))
		}
		invs = append(invs, validation.VObj(kvs...))
	}
	write := func(name string, v validation.Value) {
		t.Helper()
		p := filepath.Join(c.ArtifactsDir, name)
		if err := validation.WriteJson(p, v, ""); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("protocol_model.json", validation.VObj(
		kvT("invariants", validation.VArr(invs...))))
	reg := []validation.KV{}
	for _, s := range ledger {
		reg = append(reg, validation.KV{K: s.id, V: validation.VObj(
			kvT("test_status", validation.VStr("untested")),
			kvT("status", validation.VStr(s.status)),
			kvT("source", validation.VStr("model")))})
	}
	write("invariant_links.json", validation.VObj(
		kvT("invariants", validation.VObj(reg...))))
}

// driftHashes is the sha256 of both documents the drift report reads; the
// report is read-only on the model (one-writer law) and on the ledger.
func driftHashes(t *testing.T, c *state.Campaign) (string, string) {
	t.Helper()
	model, err := validation.Sha256File(
		filepath.Join(c.ArtifactsDir, "protocol_model.json"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := validation.Sha256File(
		filepath.Join(c.ArtifactsDir, "invariant_links.json"))
	if err != nil {
		t.Fatal(err)
	}
	return model, ledger
}

// TestArtifactReconcileReportsInvariantStatusDrift: a model claiming
// CONTRADICTED while the ledger holds UNVERIFIED is named once, the two
// agreeing invariants stay silent, and neither file is touched — in --dry and
// in a live run.
func TestArtifactReconcileReportsInvariantStatusDrift(t *testing.T) {
	c, root := t15Campaign(t, "reconcile-drift")
	writeInvariantDriftFixture(t, c,
		[]invStatus{
			{"INV-1", "CONTRADICTED"},         // drift: the ledger is UNVERIFIED
			{"INV-2", "UNVERIFIED"},           // agree
			{"INV-3", "CHECKED_AGAINST_CODE"}, // agree
		},
		[]invStatus{
			{"INV-1", "UNVERIFIED"},
			{"INV-2", "UNVERIFIED"},
			{"INV-3", "CHECKED_AGAINST_CODE"},
		})
	modelHash, ledgerHash := driftHashes(t, c)
	want := "invariant INV-1: model.json says CONTRADICTED, ledger says " +
		"UNVERIFIED — ledger governs\n"
	for _, args := range [][]string{
		{"--root", root, "artifact-reconcile", c.CampaignID, "--dry"},
		{"--root", root, "artifact-reconcile", c.CampaignID},
	} {
		code, out, errS := run(t, args...)
		if code != 0 || errS != "" {
			t.Fatalf("%v: exit %d err %q", args, code, errS)
		}
		if n := strings.Count(out, "invariant INV-"); n != 1 {
			t.Errorf("%v: drift lines = %d, want exactly 1\n%s", args, n, out)
		}
		if !strings.Contains(out, want) {
			t.Errorf("%v: output missing %q\n%s", args, want, out)
		}
		m, l := driftHashes(t, c)
		if m != modelHash {
			t.Errorf("%v: reconcile rewrote protocol_model.json", args)
		}
		if l != ledgerHash {
			t.Errorf("%v: reconcile rewrote invariant_links.json", args)
		}
	}
}

// TestArtifactReconcileDriftSilent: everything that is not a named
// disagreement prints nothing new — agreed statuses, ledger-only statuses, a
// model id the ledger never seeded, and statuses only the ledger carries.
func TestArtifactReconcileDriftSilent(t *testing.T) {
	cases := []struct {
		name   string
		model  []invStatus
		ledger []invStatus
	}{
		{"agree-all", []invStatus{
			{"INV-1", "UNVERIFIED"},
			{"INV-2", "CHECKED_AGAINST_CODE"},
		}, []invStatus{
			{"INV-1", "UNVERIFIED"},
			{"INV-2", "CHECKED_AGAINST_CODE"},
		}},
		{"ledger-only-status", []invStatus{}, []invStatus{
			{"INV-1", "CONTRADICTED"},
		}},
		{"model-id-never-seeded", []invStatus{
			{"INV-7", "CONTRADICTED"},
		}, []invStatus{}},
		{"model-without-statuses", []invStatus{
			{"INV-1", ""},
		}, []invStatus{
			{"INV-1", "UNVERIFIED"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, root := t15Campaign(t, "reconcile-silent")
			writeInvariantDriftFixture(t, c, tc.model, tc.ledger)
			code, out, errS := run(t, "--root", root, "artifact-reconcile",
				c.CampaignID)
			if code != 0 || errS != "" {
				t.Fatalf("exit %d err %q", code, errS)
			}
			if strings.Contains(out, "model.json says") {
				t.Errorf("drift reported where there is none:\n%s", out)
			}
		})
	}
}

// TestArtifactReconcileDriftNormalizesModelIDs: the ledger's canonical id is
// the normalized one, so a model spelling INV-01 against ledger key INV-1 is
// the same invariant — compared, and named in the ledger's spelling.
func TestArtifactReconcileDriftNormalizesModelIDs(t *testing.T) {
	c, root := t15Campaign(t, "reconcile-drift-norm")
	writeInvariantDriftFixture(t, c,
		[]invStatus{{"INV-01", "CONTRADICTED"}},
		[]invStatus{{"INV-1", "UNVERIFIED"}})
	code, out, errS := run(t, "--root", root, "artifact-reconcile",
		c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := "invariant INV-1: model.json says CONTRADICTED, ledger says " +
		"UNVERIFIED — ledger governs\n"
	if !strings.Contains(out, want) {
		t.Fatalf("output missing %q\n%s", want, out)
	}
}

// TestArtifactReconcileDriftAbsentModel: with no protocol model the report is
// exactly what it was before the drift check existed, even when the ledger
// holds statuses.
func TestArtifactReconcileDriftAbsentModel(t *testing.T) {
	c, root := t15Campaign(t, "reconcile-drift-nomodel")
	inv := validation.VObj(kvT("invariants", validation.VObj(
		validation.KV{K: "INV-1", V: validation.VObj(
			kvT("test_status", validation.VStr("untested")),
			kvT("status", validation.VStr("UNVERIFIED")))})))
	p := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	if err := validation.WriteJson(p, inv, ""); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-reconcile",
		c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if out != "artifact reconcile: 0 checked, 0 refreshed, 0 unchanged, 0 missing\n" {
		t.Fatalf("absent model changed the report:\n%s", out)
	}
}

// TestArtifactReconcileDriftLegacyLedgerReadOnly: a pre-structured ledger
// entry (no test_status) reads as UNVERIFIED — what the gate sees after
// migration — while the reconciler leaves the registry bytes alone. Reporting
// drift must never be the thing that rewrites state, not even under --dry.
func TestArtifactReconcileDriftLegacyLedgerReadOnly(t *testing.T) {
	c, root := t15Campaign(t, "reconcile-drift-legacy")
	writeInvariantDriftFixture(t, c,
		[]invStatus{{"INV-1", "CONTRADICTED"}}, nil)
	raw := validation.VObj(kvT("invariants", validation.VObj(
		validation.KV{K: "INV-1", V: validation.VObj(
			kvT("status", validation.VStr("CONTRADICTED")))})))
	p := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	if err := validation.WriteJson(p, raw, ""); err != nil {
		t.Fatal(err)
	}
	modelHash, ledgerHash := driftHashes(t, c)
	code, out, errS := run(t, "--root", root, "artifact-reconcile",
		c.CampaignID, "--dry")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := "invariant INV-1: model.json says CONTRADICTED, ledger says " +
		"UNVERIFIED — ledger governs\n"
	if !strings.Contains(out, want) {
		t.Fatalf("output missing %q\n%s", want, out)
	}
	m, l := driftHashes(t, c)
	if m != modelHash || l != ledgerHash {
		t.Errorf("--dry rewrote an input (model %v, ledger %v)", m == modelHash,
			l == ledgerHash)
	}
}
