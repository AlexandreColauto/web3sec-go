package cli

// cmd_publish_test: Task 9 / I6 — the `publish --disclosure FILE` surface.
// The bundle is operator-supplied, campaign-local prose; the publish RECORD
// carries only its sha256 and the embargo date, and the printed line says
// plainly that the embargo is recorded, not enforced.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/validation"
)

// discSentinel is planted in the bundle summary; the store-leak grep uses it.
const discSentinel = "SENTINEL-DISCLOSURE-PROSE-cli-7c1d"

// writeDiscBundle writes a schema-valid disclosure bundle for the given
// finding ids; embargo is literal JSON ("null" or `"2026-10-01"`).
func writeDiscBundle(t *testing.T, ids []string, embargo string) string {
	t.Helper()
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = fmt.Sprintf("%q", id)
	}
	raw := fmt.Sprintf(`{
  "schema_version": "1",
  "finding_ids": [%s],
  "summary": "%s the vault releases collateral before the debt is burned",
  "impact": "the attacker drains the pool at no cost",
  "affected": [{"contract": "Vault", "chain": "ethereum", "path": "src/Vault.sol"}],
  "embargo_until": %s,
  "contact": "security@example.invalid",
  "reporter_credit": "alice"
}`, strings.Join(quoted, ", "), discSentinel, embargo)
	p := filepath.Join(t.TempDir(), "disclosure.json")
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// discArtifact is the campaign-local bundle path for a campaign.
func discArtifact(c *state.Campaign) string {
	return filepath.Join(c.ArtifactsDir, "disclosure-bundle.json")
}

// discSHA256 is the hex digest of the written bundle artifact.
func discSHA256(t *testing.T, c *state.Campaign) string {
	t.Helper()
	raw, err := os.ReadFile(discArtifact(c))
	if err != nil {
		t.Fatalf("read bundle artifact: %v", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// discRecord is the newest manifest record in the root-tier store.
func discRecord(t *testing.T, root string) validation.Value {
	t.Helper()
	raw, err := validation.ReadJson(
		filepath.Join(sharedmem.StoreDir(root), "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if raw.Kind != validation.Arr || len(raw.A) == 0 {
		t.Fatalf("manifest is not a non-empty array: %#v", raw)
	}
	return raw.A[len(raw.A)-1]
}

// TestPublishDisclosureLineRecordsTheEmbargo: the exact single output line,
// with a date.
func TestPublishDisclosureLineRecordsTheEmbargo(t *testing.T) {
	root, cid, c := noopCamp(t)
	withPolicy(t, c, root)
	fid := noopHypo(t, c, "disclosed finding", "")
	noopConfirm(t, c, fid)
	bundle := writeDiscBundle(t, []string{fid}, `"2026-10-01"`)
	code, out, errS := run(t, "--root", root, "publish", cid,
		"--actor", "operator", "--disclosure", bundle)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	sha := discSHA256(t, c)
	want := fmt.Sprintf(
		"disclosure: bundle %s (1 findings), embargo_until 2026-10-01 — recorded, not enforced\n",
		sha[:12])
	if !strings.Contains(out, want) {
		t.Fatalf("output lacks the disclosure line %q:\n%s", want, out)
	}
	rec := discRecord(t, root)
	if got := objStr(rec, "disclosure_sha256"); got != sha {
		t.Errorf("record disclosure_sha256 = %q, want %q", got, sha)
	}
	if got := objStr(rec, "disclosure_embargo_until"); got != "2026-10-01" {
		t.Errorf("record disclosure_embargo_until = %q, want 2026-10-01", got)
	}
	// The prose never rides the store: grep the written store tree.
	discAssertStoreClean(t, root)
}

// TestPublishDisclosureLineWithoutEmbargo: the null-embargo line.
func TestPublishDisclosureLineWithoutEmbargo(t *testing.T) {
	root, cid, c := noopCamp(t)
	withPolicy(t, c, root)
	fid := noopHypo(t, c, "disclosed finding", "")
	noopConfirm(t, c, fid)
	bundle := writeDiscBundle(t, []string{fid}, "null")
	code, out, errS := run(t, "--root", root, "publish", cid,
		"--actor", "operator", "--disclosure", bundle)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	sha := discSHA256(t, c)
	want := fmt.Sprintf(
		"disclosure: bundle %s (1 findings), no embargo\n", sha[:12])
	if !strings.Contains(out, want) {
		t.Fatalf("output lacks the disclosure line %q:\n%s", want, out)
	}
	rec := discRecord(t, root)
	if got := objAt(rec, "disclosure_embargo_until"); got.Kind != validation.Null {
		t.Errorf("record disclosure_embargo_until = %#v, want null", got)
	}
}

// TestPublishDisclosureFailClosed: every finding rule refuses with exit 1 and
// a `publish failed:` line, and nothing reaches the store.
func TestPublishDisclosureFailClosed(t *testing.T) {
	cases := []struct {
		name    string
		build   func(t *testing.T, c *state.Campaign) string
		wantSub string
	}{
		{"unknown-id", func(t *testing.T, c *state.Campaign) string {
			return writeDiscBundle(t, []string{"F-0000000000ff"}, "null")
		}, "publish failed: disclosure: unknown finding id F-0000000000ff"},
		{"unconfirmed", func(t *testing.T, c *state.Campaign) string {
			fid := noopHypo(t, c, "unconfirmed finding", "POSSIBLE")
			return writeDiscBundle(t, []string{fid},
				fmt.Sprintf("%q", "2026-10-01"))
		}, "is not confirmed (status POSSIBLE)"},
		{"duplicate", func(t *testing.T, c *state.Campaign) string {
			fid := noopHypo(t, c, "disclosed finding", "")
			noopConfirm(t, c, fid)
			return writeDiscBundle(t, []string{fid, fid}, "null")
		}, "duplicate finding id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, cid, c := noopCamp(t)
			withPolicy(t, c, root)
			bundle := tc.build(t, c)
			code, out, errS := run(t, "--root", root, "publish", cid,
				"--actor", "operator", "--disclosure", bundle)
			if code != 1 {
				t.Fatalf("exit %d, want 1: %s%s", code, out, errS)
			}
			if !strings.Contains(out, tc.wantSub) {
				t.Fatalf("stdout = %q, want %q", out, tc.wantSub)
			}
			if _, err := os.Stat(filepath.Join(sharedmem.StoreDir(root),
				"manifest.json")); err == nil {
				t.Fatal("a refused disclosure still reached the shared store")
			}
		})
	}
}

// TestPublishDisclosureUnreadableFile: a missing file is a publish failure,
// not a panic and not a silent skip.
func TestPublishDisclosureUnreadableFile(t *testing.T) {
	root, cid, c := noopCamp(t)
	withPolicy(t, c, root)
	missing := filepath.Join(t.TempDir(), "nope.json")
	code, out, errS := run(t, "--root", root, "publish", cid,
		"--actor", "operator", "--disclosure", missing)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "publish failed:") {
		t.Fatalf("stdout = %q, want a publish failed: line", out)
	}
}

// TestPublishDisclosureRequiresAValue: argparse's missing-argument law.
func TestPublishDisclosureRequiresAValue(t *testing.T) {
	code, _, errS := run(t, "publish", "C-1", "--actor", "a", "--disclosure")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "argument --disclosure: expected one argument") {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestPublishWithoutDisclosureKeepsTheRecordBytes: no flag ⇒ no bundle
// artifact, no disclosure key, and the pre-I6 record key order.
func TestPublishWithoutDisclosureKeepsTheRecordBytes(t *testing.T) {
	root, cid, c := noopCamp(t)
	withPolicy(t, c, root)
	fid := noopHypo(t, c, "disclosed finding", "")
	noopConfirm(t, c, fid)
	code, out, errS := run(t, "--root", root, "publish", cid,
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if strings.Contains(out, "disclosure:") {
		t.Fatalf("output names a disclosure without the flag:\n%s", out)
	}
	if _, err := os.Stat(discArtifact(c)); err == nil {
		t.Fatal("a bundle artifact was written without --disclosure")
	}
	rec := discRecord(t, root)
	want := []string{"record_id", "campaign_id", "program_key", "actor", "at",
		"tier", "signatures_added", "memory_added", "signatures_sha256",
		"memory_sha256", "prev_hash", "record_hash"}
	got := make([]string, 0, len(rec.O))
	for _, kvp := range rec.O {
		got = append(got, kvp.K)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("record keys = %v, want %v", got, want)
	}
}

// discAssertStoreClean greps every written file under the root-tier store for
// the bundle prose (the leak law, checked against bytes on disk).
func discAssertStoreClean(t *testing.T, root string) {
	t.Helper()
	store := sharedmem.StoreDir(root)
	files := 0
	err := filepath.WalkDir(store, func(p string, e os.DirEntry, err error) error {
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
		if strings.Contains(string(raw), discSentinel) {
			t.Errorf("disclosure prose leaked into the store: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("the store tree holds no files — the leak grep proved nothing")
	}
}
