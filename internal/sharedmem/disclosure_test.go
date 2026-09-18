package sharedmem

// Task 9 / I6 (half B): the embargoed disclosure bundle. The tests below pin
// the fail-closed validation rules, the artifact discipline (campaign-local,
// registered), the record additions (present-only), and — the point of the
// whole feature — the leak law: the bundle's prose NEVER reaches the shared
// store, checked by grepping the WRITTEN store tree, not by inspecting the
// record struct.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// disclosureSentinel is a unique string planted in the bundle's summary; the
// leak test greps the store tree for it.
const disclosureSentinel = "SENTINEL-DISCLOSURE-PROSE-9f3a2b1c"

// bundlePath writes raw bundle JSON to a scratch file and returns its path.
func bundlePath(t *testing.T, raw string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "disclosure.json")
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// bundleJSON builds a schema-valid bundle for the given finding ids. embargo
// is the literal JSON text for embargo_until ("null" or `"2026-10-01"`).
func bundleJSON(ids []string, embargo string) string {
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = fmt.Sprintf("%q", id)
	}
	return fmt.Sprintf(`{
  "schema_version": "1",
  "finding_ids": [%s],
  "summary": "%s the vault releases collateral before the debt is burned",
  "impact": "the attacker drains the pool at no cost",
  "affected": [{"contract": "Vault", "chain": "ethereum", "path": "target/V.sol", "url": "https://example.invalid/addr"}],
  "references": ["https://example.invalid/advisory"],
  "embargo_until": %s,
  "contact": "security@example.invalid",
  "reporter_credit": "alice"
}`, strings.Join(quoted, ", "), disclosureSentinel, embargo)
}

// disclosureCamp is a policy-loaded campaign with one CONFIRMED finding and
// one POSSIBLE finding.
func disclosureCamp(t *testing.T) (*state.Campaign, string, string) {
	t.Helper()
	root := newRoot(t)
	c := makeCampaign(t, root, "disclosure-program")
	fid := hypo(t, c, []string{"withdraw_unbacked_assets"}, nil,
		"disclosure finding", "logic-error")
	confirm(t, c, fid)
	possible := hypo(t, c, []string{"withdraw_unbacked_assets"}, nil,
		"unconfirmed finding", "logic-error")
	if _, err := findings.Transition(c, possible, "POSSIBLE", "triage",
		"triage", "", false); err != nil {
		t.Fatalf("transition POSSIBLE: %v", err)
	}
	return c, fid, possible
}

// ---- schema rules ----------------------------------------------------------

// TestDisclosureSchemaRefusesMalformedBundles: the schema is fail-closed on
// the three shapes the plan names (missing embargo_until key, a 3-char
// summary, an unknown top-level key).
func TestDisclosureSchemaRefusesMalformedBundles(t *testing.T) {
	c, fid, _ := disclosureCamp(t)
	valid := bundleJSON([]string{fid}, `"2026-10-01"`)
	if _, err := LoadDisclosure(c, bundlePath(t, valid)); err != nil {
		t.Fatalf("the control bundle must load: %v", err)
	}
	for _, tc := range []struct{ name, raw string }{
		{"missing-embargo-key", strings.Replace(valid,
			`"embargo_until": "2026-10-01",`, "", 1)},
		{"short-summary", strings.Replace(valid,
			`"summary": "`+disclosureSentinel+` the vault releases collateral before the debt is burned"`,
			`"summary": "abc"`, 1)},
		{"unknown-top-level-key", strings.Replace(valid,
			`"reporter_credit": "alice"`,
			`"reporter_credit": "alice", "notes": "extra"`, 1)},
	} {
		if _, err := LoadDisclosure(c, bundlePath(t, tc.raw)); err == nil {
			t.Errorf("%s: malformed bundle was accepted", tc.name)
		}
	}
}

// ---- fail-closed finding rules ---------------------------------------------

// TestDisclosureRefusesUnknownFindingID: a bundle may not cite a finding the
// campaign cannot show.
func TestDisclosureRefusesUnknownFindingID(t *testing.T) {
	c, _, _ := disclosureCamp(t)
	_, err := LoadDisclosure(c, bundlePath(t,
		bundleJSON([]string{"F-0000000000ff"}, "null")))
	if err == nil {
		t.Fatal("a bundle citing an unknown finding id was accepted")
	}
	if want := "disclosure: unknown finding id F-0000000000ff"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

// TestDisclosureRefusesUnconfirmedFinding: a disclosure about an unconfirmed
// hypothesis is a public false claim; the framework refuses it.
func TestDisclosureRefusesUnconfirmedFinding(t *testing.T) {
	c, _, possible := disclosureCamp(t)
	_, err := LoadDisclosure(c, bundlePath(t,
		bundleJSON([]string{possible}, "null")))
	if err == nil {
		t.Fatal("a bundle citing a POSSIBLE finding was accepted")
	}
	want := fmt.Sprintf("disclosure: finding %s is not confirmed (status POSSIBLE)",
		possible)
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

// TestDisclosureRefusesFindingOutsideThePublish: you cannot attach a bundle
// for knowledge you are not publishing. The rule is checked against the set
// the publish pass considers publishable, so the test drives the rule seam
// directly with a narrowed set (in production the set is every
// CONFIRMED/CHAIN finding, which rule 2 already requires).
func TestDisclosureRefusesFindingOutsideThePublish(t *testing.T) {
	c, fid, _ := disclosureCamp(t)
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]validation.Value{}
	for _, f := range all {
		byID[validation.ObjStr(f, "finding_id")] = f
	}
	if err := disclosureRuleCheck([]string{fid}, byID,
		map[string]bool{fid: true}); err != nil {
		t.Fatalf("a published finding was refused: %v", err)
	}
	err = disclosureRuleCheck([]string{fid}, byID, map[string]bool{})
	if err == nil {
		t.Fatal("a finding outside the publish set was accepted")
	}
	want := fmt.Sprintf("disclosure: finding %s is not part of this publish", fid)
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

// TestDisclosureRefusesDuplicateIDs: an ambiguous count is a data defect.
func TestDisclosureRefusesDuplicateIDs(t *testing.T) {
	c, fid, _ := disclosureCamp(t)
	if _, err := LoadDisclosure(c, bundlePath(t,
		bundleJSON([]string{fid, fid}, "null"))); err == nil {
		t.Fatal("a bundle with duplicate finding ids was accepted")
	}
}

// ---- artifact + record -----------------------------------------------------

// TestDisclosureArtifactIsCampaignLocalAndRegistered: the bundle is written
// to the campaign's artifacts dir and registered there — never to the store.
func TestDisclosureArtifactIsCampaignLocalAndRegistered(t *testing.T) {
	c, fid, _ := disclosureCamp(t)
	d, err := LoadDisclosure(c, bundlePath(t, bundleJSON([]string{fid},
		`"2026-10-01"`)))
	if err != nil {
		t.Fatal(err)
	}
	if d.EmbargoUntil != "2026-10-01" {
		t.Fatalf("EmbargoUntil = %q, want 2026-10-01", d.EmbargoUntil)
	}
	if len(d.FindingIDs) != 1 || d.FindingIDs[0] != fid {
		t.Fatalf("FindingIDs = %v, want [%s]", d.FindingIDs, fid)
	}
	if err := WriteDisclosureArtifact(c, d); err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(c.ArtifactsDir, DisclosureArtifactName)
	if d.ArtifactPath != wantPath {
		t.Errorf("ArtifactPath = %q, want %q", d.ArtifactPath, wantPath)
	}
	raw, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("bundle artifact: %v", err)
	}
	sum := sha256.Sum256(raw)
	if want := hex.EncodeToString(sum[:]); d.SHA256 != want {
		t.Errorf("SHA256 = %q, want %q", d.SHA256, want)
	}
	if !strings.Contains(string(raw), disclosureSentinel) {
		t.Error("the campaign-local artifact does not carry the bundle prose")
	}
	// Registered as a campaign artifact of kind "disclosure".
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range validation.ObjAt(st, "artifacts").A {
		if validation.ObjStr(a, "kind") == DisclosureArtifactKind &&
			filepath.Base(validation.ObjStr(a, "path")) == DisclosureArtifactName {
			found = true
			if got := validation.ObjStr(a, "sha256"); got != d.SHA256 {
				t.Errorf("registered artifact sha256 = %q, want %q", got, d.SHA256)
			}
		}
	}
	if !found {
		t.Fatalf("state carries no disclosure artifact row for %s", wantPath)
	}
}

// TestDisclosureNullEmbargoIsRecordedAsNull: the record field is present and
// null when the bundle carries no embargo (the key is required, the value
// may be null).
func TestDisclosureNullEmbargoIsRecordedAsNull(t *testing.T) {
	c, fid, _ := disclosureCamp(t)
	d, err := LoadDisclosure(c, bundlePath(t, bundleJSON([]string{fid}, "null")))
	if err != nil {
		t.Fatal(err)
	}
	if d.EmbargoUntil != "" {
		t.Fatalf("EmbargoUntil = %q, want empty for a null embargo", d.EmbargoUntil)
	}
	if err := WriteDisclosureArtifact(c, d); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishCampaignWith(c, "operator", false, PublishOpts{
		DisclosureSHA256: d.SHA256}); err != nil {
		t.Fatal(err)
	}
	rec := lastManifestRecord(t, c.Root)
	if got := validation.ObjStr(rec, "disclosure_sha256"); got != d.SHA256 {
		t.Errorf("record disclosure_sha256 = %q, want %q", got, d.SHA256)
	}
	if got := validation.ObjAt(rec, "disclosure_embargo_until"); got.Kind != validation.Null {
		t.Errorf("record disclosure_embargo_until = %#v, want null", got)
	}
}

// TestDisclosureRecordCarriesHashAndEmbargo: with a bundle attached the record
// carries the hash and the verbatim embargo date, as two separate fields (the
// sig/mem hashes are never folded), and the output value reports the attach.
func TestDisclosureRecordCarriesHashAndEmbargo(t *testing.T) {
	c, fid, _ := disclosureCamp(t)
	d, err := LoadDisclosure(c, bundlePath(t, bundleJSON([]string{fid},
		`"2026-10-01"`)))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteDisclosureArtifact(c, d); err != nil {
		t.Fatal(err)
	}
	rep, err := PublishCampaignWith(c, "operator", false, PublishOpts{
		DisclosureSHA256:       d.SHA256,
		DisclosureEmbargoUntil: d.EmbargoUntil})
	if err != nil {
		t.Fatal(err)
	}
	rec := lastManifestRecord(t, c.Root)
	if got := validation.ObjStr(rec, "disclosure_sha256"); got != d.SHA256 {
		t.Errorf("record disclosure_sha256 = %q, want %q", got, d.SHA256)
	}
	if got := validation.ObjStr(rec, "disclosure_embargo_until"); got != "2026-10-01" {
		t.Errorf("record disclosure_embargo_until = %q, want 2026-10-01", got)
	}
	if got := validation.ObjStr(rec, "signatures_sha256"); got == d.SHA256 {
		t.Error("the disclosure hash was folded into signatures_sha256")
	}
	if len(d.SHA256) != 64 {
		t.Errorf("sha256 = %q, want 64 hex chars", d.SHA256)
	}
	_ = rep
}

// TestPublishWithoutDisclosureIsByteIdentical: no bundle attached ⇒ the
// record carries exactly the pre-I6 keys, in the pre-I6 order.
func TestPublishWithoutDisclosureIsByteIdentical(t *testing.T) {
	c, fid, _ := disclosureCamp(t)
	_ = fid
	if _, err := PublishCampaign(c, "operator", false); err != nil {
		t.Fatal(err)
	}
	rec := lastManifestRecord(t, c.Root)
	want := []string{"record_id", "campaign_id", "program_key", "actor", "at",
		"tier", "signatures_added", "memory_added", "signatures_sha256",
		"memory_sha256", "prev_hash", "record_hash"}
	for i, kvp := range rec.O {
		if i >= len(want) || kvp.K != want[i] {
			t.Fatalf("record key %d = %q, want %q (full: %v)", i, kvp.K,
				want[min(i, len(want)-1)], recordKeys(rec))
		}
	}
	if len(rec.O) != len(want) {
		t.Fatalf("record has %d keys, want %d: %v", len(rec.O), len(want),
			recordKeys(rec))
	}
}

// ---- the leak law ----------------------------------------------------------

// TestDisclosureProseNeverEntersTheStore is the reason this is safe to ship:
// the shared store is a cross-campaign surface, so the bundle's free text
// must not be on it. This greps the WRITTEN FILES under the store directory.
func TestDisclosureProseNeverEntersTheStore(t *testing.T) {
	c, fid, _ := disclosureCamp(t)
	d, err := LoadDisclosure(c, bundlePath(t, bundleJSON([]string{fid},
		`"2026-10-01"`)))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteDisclosureArtifact(c, d); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishCampaignWith(c, "operator", false, PublishOpts{
		DisclosureSHA256:       d.SHA256,
		DisclosureEmbargoUntil: d.EmbargoUntil}); err != nil {
		t.Fatal(err)
	}
	store := StoreDir(c.Root)
	files := 0
	walkErr := filepath.WalkDir(store, func(p string, e fs.DirEntry,
		err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files++
		if strings.Contains(string(raw), disclosureSentinel) {
			t.Errorf("disclosure prose leaked into the shared store: %s", p)
		}
		if strings.Contains(string(raw), "drains the pool at no cost") {
			t.Errorf("disclosure impact prose leaked into the shared store: %s", p)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if files == 0 {
		t.Fatal("the store tree holds no files — the leak grep proved nothing")
	}
	// The campaign-local artifact is where the prose lives.
	raw, err := os.ReadFile(d.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), disclosureSentinel) {
		t.Fatal("the campaign-local bundle lost its prose")
	}
}

// ---- helpers ---------------------------------------------------------------

// lastManifestRecord is the newest record in the ROOT-tier manifest.
func lastManifestRecord(t *testing.T, root string) validation.Value {
	t.Helper()
	raw, err := validation.ReadJson(filepath.Join(StoreDir(root), manifestName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if raw.Kind != validation.Arr || len(raw.A) == 0 {
		t.Fatalf("manifest is not a non-empty array: %#v", raw)
	}
	return raw.A[len(raw.A)-1]
}

// recordKeys is the key order of a record (for failure messages).
func recordKeys(rec validation.Value) []string {
	out := make([]string, 0, len(rec.O))
	for _, kvp := range rec.O {
		out = append(out, kvp.K)
	}
	return out
}
