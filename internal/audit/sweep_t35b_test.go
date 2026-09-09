package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// seededCampaign is the review-fixes `_seeded_campaign`: a pinned source
// snapshot plus one ingested finding, so every projection check is active.
func seededCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	c := initCampaign(t)
	target := filepath.Join(c.Root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	payload := validation.VObj(
		kv("title", validation.VStr("seeded finding title ok")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("description", validation.VStr(
				"capability sharing used for the cap test")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("V.sol")),
			kv("function", validation.VStr("f"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("EOA")),
			kv("capabilities", validation.VArr()))),
	)
	if _, err := findings.IngestHypothesis(c, payload, "code", "", ""); err != nil {
		t.Fatal(err)
	}
	return c
}

// Port of tests/test_review_fixes.py::test_audit_projection_flags_phantom_snapshot.
func TestAuditProjectionFlagsPhantomSnapshot(t *testing.T) {
	c := seededCampaign(t)
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	phantom := validation.VObj(
		kv("snapshot_id", validation.VStr("src-phantom00")),
		kv("pass", validation.VInt(1)),
		kv("pinned", validation.VBool(true)),
		kv("registered_at",
			validation.VStr("2026-09-02T00:00:00.000000+00:00")),
	)
	snaps := objAt(st, "snapshots")
	snaps.A = append(snaps.A, phantom)
	for i := range st.O {
		if st.O[i].K == "snapshots" {
			st.O[i].V = snaps
		}
	}
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if !anyProblem(report, "snapshot.pinned") {
		t.Errorf("no phantom-snapshot problem; projection=%v",
			problemsOf(report, "projection"))
	}
}

// Port of tests/test_review_fixes.py::test_audit_projection_flags_phantom_finding_file.
func TestAuditProjectionFlagsPhantomFindingFile(t *testing.T) {
	c := seededCampaign(t)
	entries, err := os.ReadDir(c.FindingsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("seeded campaign has no finding file")
	}
	raw, err := os.ReadFile(filepath.Join(c.FindingsDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	body, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	fid := state.NewID("F", 12)
	body.O = setOrAppendAudit(body.O, "finding_id", validation.VStr(fid))
	body.O = setOrAppendAudit(body.O, "title",
		validation.VStr("phantom finding"))
	if err := validation.WriteJson(filepath.Join(c.FindingsDir, fid+".json"),
		body, "finding"); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range problemsOf(report, "projection") {
		if strings.Contains(p, fid) {
			found = true
		}
	}
	if !found {
		t.Errorf("phantom finding %s not flagged; projection=%v", fid,
			problemsOf(report, "projection"))
	}
}

// setOrAppendAudit replaces key in place, or appends it.
func setOrAppendAudit(kvs []validation.KV, key string,
	val validation.Value) []validation.KV {
	for i := range kvs {
		if kvs[i].K == key {
			kvs[i].V = val
			return kvs
		}
	}
	return append(kvs, validation.KV{K: key, V: val})
}
