package findings

// v1.6 — the exec-record anchor at the two admission sites.
//
// The record is mutable JSON read straight from disk, so before the anchor an
// operator could run a failing suite and then stamp expected_outcome/
// expected_failure (or flip exit_status) into the record before minting. The
// ledger's digest closes that: the record must recompute to the digest the
// event committed to at exec time.
//
// FAIL-OPEN on ABSENT is pinned here too, and it is not accidental: the
// committed Python-era fixture carries two unanchored sandbox.exec events and
// scripts/verify-full.sh step 9 asserts audit PASS over it, and the two
// seeding harnesses write records with no event of their own.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// anchorFinding ingests one hypothesis and returns its finding id.
func anchorFinding(t *testing.T, c *state.Campaign) string {
	t.Helper()
	f, err := IngestHypothesis(c, hypoPayload(), "code", "05", "")
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(f, "finding_id")
}

// logAnchorEvent appends a carrier event for execID carrying exactly kvs plus
// the record's own anchor (pass no kvs for a legacy unanchored event, pass a
// hand-built pair for a malformed one).
func logAnchorEvent(t *testing.T, c *state.Campaign, typ, execID string,
	rec validation.Value, kvs ...validation.KV) {
	t.Helper()
	ref := execID
	all := append([]validation.KV{{K: "profile",
		V: validation.ObjAt(rec, "profile")}}, kvs...)
	if kvs == nil {
		all = append(all, sandbox.ExecRecordAnchorKVs(rec)...)
	}
	data := validation.VObj(all...)
	if _, err := c.Log(typ, &ref, &data); err != nil {
		t.Fatal(err)
	}
}

// tamperAnchorRecord rewrites the record the way the attack does: exit_status
// flipped, both expectation keys stamped in, and a stdout.log that carries a
// per-test [FAIL] line with the declared signature — so the record is
// admissible to every pre-anchor rule.
func tamperAnchorRecord(t *testing.T, c *state.Campaign,
	rec validation.Value) validation.Value {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, validation.ObjStr(rec, "exec_id"))
	if err := os.WriteFile(filepath.Join(dir, "stdout.log"),
		[]byte(logicOut), 0o644); err != nil {
		t.Fatal(err)
	}
	rec.O = validation.SetOrAppend(rec.O, "exit_status", validation.VInt(7))
	rec.O = validation.SetOrAppend(rec.O, "expected_outcome",
		validation.VStr(sandbox.EXPECT_FAIL))
	rec.O = validation.SetOrAppend(rec.O, "expected_failure",
		validation.VStr(declaredSig))
	p := filepath.Join(dir, "exec_record.json")
	if err := validation.WriteJson(p, rec, ""); err != nil {
		t.Fatal(err)
	}
	back, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	return back
}

// assertBothAdmissionSitesRefuse runs the two sites the anchor was wired into
// and asserts each refuses with the anchor's own sentence.
func assertBothAdmissionSitesRefuse(t *testing.T, c *state.Campaign,
	findingID string, edited validation.Value) {
	t.Helper()
	finding, err := LoadFinding(c, findingID)
	if err != nil {
		t.Fatal(err)
	}
	execID := validation.ObjStr(edited, "exec_id")
	_, err = IngestExecRefEvidence(c, findingID, finding,
		t2ExecRefItem(execID, "EV-anchor-a"))
	wantErr(t, err, "exec_record.json does not recompute")
	_, err = AddEvidence(c, findingID, execEvidenceItem(edited, "E4",
		"foundry-test", "the sandboxed PoC reproduced it", "EV-anchor-b"))
	wantErr(t, err, "exec_record.json does not recompute")
}

// TestMintRefusesAnExecRecordEditedAfterTheEvent is the BITE TEST. It walks
// the exact attack: an honest exit-0 record, the event that anchors it, and
// then a hand-edit that makes the record look like the absent-guard
// reproduction the change exists to admit.
//
// Three assertions, and the FIRST is the load-bearing one: the pre-anchor
// gate genuinely cannot tell the record was edited — that is why the anchor
// had to exist. Removing the anchor call from either findings site turns this
// red (mutation-checked: each removal was applied, observed failing, and
// reverted).
func TestMintRefusesAnExecRecordEditedAfterTheEvent(t *testing.T) {
	c := ingestCamp(t)
	fid := anchorFinding(t, c)
	honest := testExec(t, c, "docker-networkless", fid, 0, greenOut)
	execID := validation.ObjStr(honest, "exec_id")
	logAnchorEvent(t, c, "sandbox.exec", execID, honest)
	stored := sandbox.ExecRecordDigest(honest)

	edited := tamperAnchorRecord(t, c, honest)
	if err := ValidateExecRecord(execID, edited); err != nil {
		t.Fatalf("(i) the pre-anchor gate must NOT be able to tell the "+
			"record was edited — that is the whole point of the anchor; it "+
			"refused: %v", err)
	}
	err := sandbox.VerifyExecRecordAnchor(c, execID, edited)
	if err == nil {
		t.Fatal("(ii) the anchor check admitted a record edited after its " +
			"event")
	}
	recomputed := sandbox.ExecRecordDigest(edited)
	for _, d := range []string{stored, recomputed} {
		if !strings.Contains(err.Error(), d) {
			t.Fatalf("(ii) the refusal must name both digests; %q lacks %q",
				err.Error(), d)
		}
	}
	assertBothAdmissionSitesRefuse(t, c, fid, edited)
}

// TestAnUnanchoredLegacyRecordStillMints pins the fail-open decision: an exec
// with no carrier event at all (the two seeding harnesses) and one whose
// carrier carries no anchor key (every pre-anchor campaign, the committed
// Python-era fixture included) admit exactly as today.
func TestAnUnanchoredLegacyRecordStillMints(t *testing.T) {
	c := ingestCamp(t)
	fid := anchorFinding(t, c)

	// (a) no carrier event at all.
	orphan := testExec(t, c, "docker-networkless", fid, 0, greenOut)
	orphanID := validation.ObjStr(orphan, "exec_id")
	if err := sandbox.VerifyExecRecordAnchor(c, orphanID, orphan); err != nil {
		t.Fatalf("a record with no carrier event must admit (fail-open): %v",
			err)
	}
	finding, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IngestExecRefEvidence(c, fid, finding,
		t2ExecRefItem(orphanID, "EV-legacy-a")); err != nil {
		t.Fatalf("an unanchored record must still mint: %v", err)
	}

	// (b) a legacy-shaped carrier event: the three pre-anchor data keys.
	legacy := testExec(t, c, "docker-networkless", fid, 0, greenOut)
	legacyID := validation.ObjStr(legacy, "exec_id")
	logAnchorEvent(t, c, "sandbox.exec", legacyID, legacy,
		validation.KV{K: "exit", V: validation.VInt(0)})
	if err := sandbox.VerifyExecRecordAnchor(c, legacyID, legacy); err != nil {
		t.Fatalf("an unanchored carrier must admit (fail-open): %v", err)
	}
	if _, err := IngestExecRefEvidence(c, fid, finding,
		t2ExecRefItem(legacyID, "EV-legacy-b")); err != nil {
		t.Fatalf("an unanchored carrier must still mint: %v", err)
	}
}

// malformedAnchor is one §3.3 case: the anchor keys to log and the refusal
// substring they must produce.
type malformedAnchor struct {
	name string
	kvs  []validation.KV
	want string
}

// anchorKVs builds the two anchor keys; an empty side is omitted, because the
// malformed cases include each key on its own.
func anchorKVs(digest, alg string) []validation.KV {
	var out []validation.KV
	if digest != "" {
		out = append(out, validation.KV{K: sandbox.KeyExecRecordSHA256,
			V: validation.VStr(digest)})
	}
	if alg != "" {
		out = append(out, validation.KV{K: sandbox.KeyExecRecordSHA256Alg,
			V: validation.VStr(alg)})
	}
	return out
}

// malformedAnchors is §3.3's table: a digest with no label, a label with no
// digest, an unknown label, and a malformed digest VALUE — all refused. An
// unlabelled digest cannot be the escape hatch from the rule, and a digest
// that can never match is a mismatch, not an unverifiable curiosity. The
// empty-label case is spelled out with the key PRESENT, because
// anchorKVs(…, "") would omit it: a present-but-empty label reads as an
// absent one through AnchorProblem's rendered strings, and the refusal must
// say so rather than claim the key is missing (D4).
func malformedAnchors(hex64, alg string) []malformedAnchor {
	return []malformedAnchor{
		{"digest without a label", anchorKVs(hex64, ""),
			"digest with no encoding label"},
		{"empty label", []validation.KV{
			{K: sandbox.KeyExecRecordSHA256, V: validation.VStr(hex64)},
			{K: sandbox.KeyExecRecordSHA256Alg, V: validation.VStr("")}},
			"key is absent or empty"},
		{"label without a digest", anchorKVs("", alg),
			"names the anchor encoding but carries no digest"},
		{"unknown label", anchorKVs(hex64, "sha256"),
			"names anchor encoding"},
		{"uppercase digest", anchorKVs(strings.ToUpper(hex64), alg),
			"does not recompute"},
		{"short digest", anchorKVs("abc123", alg), "does not recompute"},
		{"non-string digest", []validation.KV{
			{K: sandbox.KeyExecRecordSHA256, V: validation.VInt(3)},
			{K: sandbox.KeyExecRecordSHA256Alg, V: validation.VStr(alg)}},
			"does not recompute"},
	}
}

func TestAMalformedAnchorRefuses(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	for _, tc := range malformedAnchors(hex64, sandbox.ExecRecordAnchorAlg) {
		t.Run(tc.name, func(t *testing.T) {
			c := ingestCamp(t)
			fid := anchorFinding(t, c)
			rec := testExec(t, c, "docker-networkless", fid, 0, greenOut)
			execID := validation.ObjStr(rec, "exec_id")
			logAnchorEvent(t, c, "sandbox.exec", execID, rec, tc.kvs...)
			err := sandbox.VerifyExecRecordAnchor(c, execID, rec)
			wantErr(t, err, tc.want)
		})
	}
}

// TestSeveralCarrierEventsMustAgree is §5 state (b) on the mint side: no
// digest wins by precedence, so the ref's carriers are walked in log order
// and the first disagreement refuses. No carrier event at all is nil.
func TestSeveralCarrierEventsMustAgree(t *testing.T) {
	for _, order := range []string{"mismatch first", "match first"} {
		t.Run(order, func(t *testing.T) {
			c := ingestCamp(t)
			fid := anchorFinding(t, c)
			rec := testExec(t, c, "docker-networkless", fid, 0, greenOut)
			execID := validation.ObjStr(rec, "exec_id")
			other := testExec(t, c, "docker-networkless", fid, 1, logicOut)
			otherDigest := sandbox.ExecRecordDigest(other)

			first, second := other, rec
			if order == "match first" {
				first, second = rec, other
			}
			logAnchorEvent(t, c, "sandbox.exec", execID, first)
			logAnchorEvent(t, c, "sandbox.exec.registered", execID, second)
			err := sandbox.VerifyExecRecordAnchor(c, execID, rec)
			wantErr(t, err, otherDigest)
			if !strings.Contains(err.Error(), "event "+otherDigest) {
				t.Fatalf("the refusal must name the disagreeing carrier "+
					"as the event digest: %v", err)
			}
		})
	}

	c := ingestCamp(t)
	fid := anchorFinding(t, c)
	rec := testExec(t, c, "docker-networkless", fid, 0, greenOut)
	// A ref with no carrier event at all is nil.
	if err := sandbox.VerifyExecRecordAnchor(c, "EXEC-ffffffffff", rec); err != nil {
		t.Fatalf("a ref with no carrier event must admit: %v", err)
	}
}

// TestAnUnparseableRecordRefuses is §5 state (a) on the mint side: an
// anchored event whose record exists but does not parse refuses rather than
// minting on an unverifiable anchor.
func TestAnUnparseableRecordRefuses(t *testing.T) {
	c := ingestCamp(t)
	fid := anchorFinding(t, c)
	rec := testExec(t, c, "docker-networkless", fid, 0, greenOut)
	execID := validation.ObjStr(rec, "exec_id")
	logAnchorEvent(t, c, "sandbox.exec", execID, rec)
	if err := os.WriteFile(filepath.Join(c.ExecsDir, execID,
		"exec_record.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	finding, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	_, err = IngestExecRefEvidence(c, fid, finding,
		t2ExecRefItem(execID, "EV-unparseable"))
	if err == nil {
		t.Fatal("an anchored, unparseable record must be refused")
	}
	if !strings.Contains(err.Error(), "ingest refused") {
		t.Fatalf("the refusal must name itself: %v", err)
	}
}
