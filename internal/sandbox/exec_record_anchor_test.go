package sandbox

// v1.6 — the exec-record anchor: the encoding, pinned.
//
// The digest is sha256 over validation.CanonSpaced(record) — the ledger's own
// canonicalizer — over the DECODED value, never the file bytes (WriteJson
// writes indented bytes, so a byte digest would be defeated by re-indentation
// alone). These tests pin the encoding, the absent-vs-null distinction, the
// round trip through WriteJson/ReadJson, and the one property that keeps the
// anchor off the record itself (the record schema is closed, and a
// self-referential digest would be defeated by a single hand-edit).

import (
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

// frozenAnchorRecord is a fixed record value: no clock, no id, so its digest
// is a pure function of its content and can be pinned as a literal.
func frozenAnchorRecord() validation.Value {
	return validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-0000000001")},
		validation.KV{K: "exit_status", V: validation.VInt(0)},
		validation.KV{K: "command", V: validation.VStr("forge test")},
		validation.KV{K: "artifact_hashes", V: validation.VObj(
			validation.KV{K: "stdout.log",
				V: validation.VStr("00ff")})},
	)
}

func TestExecRecordDigestIsCanonicalSpacedOverTheWholeRecord(t *testing.T) {
	rec := frozenAnchorRecord()
	canon := validation.CanonSpaced(rec)
	if got, want := ExecRecordDigest(rec),
		validation.Sha256Hex([]byte(canon)); got != want {
		t.Fatalf("ExecRecordDigest = %s, want Sha256Hex(CanonSpaced(rec)) "+
			"= %s", got, want)
	}
	got := ExecRecordDigest(rec)
	if len(got) != 64 {
		t.Fatalf("digest %q is %d chars, want 64 lowercase hex", got, len(got))
	}
	for _, r := range got {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			t.Fatalf("digest %q is not lowercase hex (offending %q)", got, r)
		}
	}
	// Sorted keys and the spaced separators: the digest is NOT the compact
	// flavour, and the two differ (the encoding label exists for this).
	if compact := validation.Sha256Hex([]byte(
		validation.CanonCompact(rec))); compact == got {
		t.Fatal("the compact and spaced canonicalizations hash identically; " +
			"the encoding label would name nothing")
	}
}

func TestExecRecordDigestChangesWhenExitStatusChanges(t *testing.T) {
	rec := frozenAnchorRecord()
	edited := setKey(rec, "exit_status", validation.VInt(7))
	if ExecRecordDigest(rec) == ExecRecordDigest(edited) {
		t.Fatal("exit_status 0 -> 7 left the digest unchanged: the anchor " +
			"does not cover exit_status")
	}
}

func TestExecRecordDigestChangesWhenTheExpectationIsAdded(t *testing.T) {
	rec := frozenAnchorRecord()
	edited := setKey(setKey(rec, "expected_outcome",
		validation.VStr(EXPECT_FAIL)), "expected_failure",
		validation.VStr("MarketNotListed"))
	if ExecRecordDigest(rec) == ExecRecordDigest(edited) {
		t.Fatal("adding expected_outcome/expected_failure left the digest " +
			"unchanged: the anchor does not cover the mint key")
	}
}

func TestExecRecordDigestDistinguishesAbsentFromNull(t *testing.T) {
	absent := validation.VObj(validation.KV{K: "exec_id",
		V: validation.VStr("EXEC-0000000001")})
	present := setKey(absent, "expected_outcome", validation.VNull())
	if ExecRecordDigest(absent) == ExecRecordDigest(present) {
		t.Fatal("absent and explicit-null hash identically: the digest " +
			"erases a distinction the record can carry")
	}
	// And the encoder really renders them differently (the digest follows).
	if validation.CanonSpaced(absent) == validation.CanonSpaced(present) {
		t.Fatal("CanonSpaced flattens absent into null")
	}
}

func TestExecRecordDigestRoundTripsThroughWriteJsonAndReadJson(t *testing.T) {
	// A schema-valid record with a non-ASCII command, written and read back:
	// WriteJson writes indented bytes and ReadJson re-parses them, so the
	// digest must survive the round trip (that is what makes a byte digest
	// unnecessary and a re-indentation harmless).
	c := newCampaign(t, "anchor-roundtrip")
	rec, err := RegisterExec(c, RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test héllo",
		ReportedBy: "operator", ExitStatus: 0, StdoutText: "Ran 1 test\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "exec_record.json")
	if err := validation.WriteJson(p, rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	back, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	if ExecRecordDigest(back) != ExecRecordDigest(rec) {
		t.Fatalf("the digest did not survive WriteJson/ReadJson: %s -> %s",
			ExecRecordDigest(rec), ExecRecordDigest(back))
	}
	// The file bytes are NOT the digest domain: a re-indentation must not
	// move the digest.
	if got := reindentedDigest(t, back); got != ExecRecordDigest(rec) {
		t.Fatalf("a re-write moved the digest: %s -> %s",
			ExecRecordDigest(rec), got)
	}
}

// reindentedDigest rewrites rec with no schema (the DumpIndented path) and
// returns the digest of the value read back.
func reindentedDigest(t *testing.T, rec validation.Value) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "reindented.json")
	if err := validation.WriteJson(p, rec, ""); err != nil {
		t.Fatal(err)
	}
	back, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	return ExecRecordDigest(back)
}

func TestExecRecordDigestNumberAndUnicodeRendering(t *testing.T) {
	rec := validation.VObj(
		validation.KV{K: "n", V: validation.VInt(7)},
		validation.KV{K: "f", V: validation.VFloat(0.1)},
		validation.KV{K: "s", V: validation.VStr("héllo")},
	)
	// CPython json.dumps(sort_keys=True, ensure_ascii=True): sorted keys,
	// ", "/": " separators, the non-ASCII code point escaped.
	const want = `{"f": 0.1, "n": 7, "s": "h\u00e9llo"}`
	if got := validation.CanonSpaced(rec); got != want {
		t.Fatalf("CanonSpaced = %s, want %s", got, want)
	}
	if got, wantDigest := ExecRecordDigest(rec),
		validation.Sha256Hex([]byte(want)); got != wantDigest {
		t.Fatalf("ExecRecordDigest = %s, want %s", got, wantDigest)
	}
}

func TestExecRecordAnchorIsNotOnTheRecord(t *testing.T) {
	c := newCampaign(t, "anchor-absent")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("echo ANCHOR", RunOpts{Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{KeyExecRecordSHA256, KeyExecRecordSHA256Alg} {
		for _, kv := range rec.O {
			if kv.K == key {
				t.Fatalf("the anchor key %q landed ON the record; the "+
					"record schema is closed and a self-referential "+
					"digest would be defeated by one hand-edit", key)
			}
		}
	}
	// ... and the record still validates: adding the anchor changed no
	// record byte.
	if err := validation.Validate(rec, "sandbox_execution", 1); err != nil {
		t.Fatalf("the record no longer validates against the closed "+
			"sandbox_execution schema: %v", err)
	}
}
