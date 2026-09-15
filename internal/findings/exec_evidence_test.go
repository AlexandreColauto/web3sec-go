package findings

// P2-2 — evidence laundering through the 10 MiB capture cap. A capture the
// exec record's own output_capture marks TRUNCATED must be unfit for
// evidence on every consumer of this file's gate:
//
//   - ValidateExecRecord (mint's exec-record gate AND the ingest exec_ref
//     gate — one function, two verbs) refuses it, naming the observed
//     capture accounting (which stream, kept vs total);
//   - the forge-meaningfulness check below it only ever saw the KEPT bytes,
//     so a clean-looking prefix plus a hidden trailing "[FAIL]" minted E4
//     before this gate existed — the flip this file's tests pin shut;
//   - an untruncated record behaves byte-for-byte as before (the gate is
//     additive: no output_capture, or one that marks no stream truncated,
//     takes the pre-P2-2 path unchanged).
//
// The CLI-side pins (mint exit codes, the verify --harness-result binder)
// live in internal/cli/zz_r38b_test.go.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// markCapture rewrites the exec's on-disk record with an output_capture
// object appended (the additive shape the sandbox's own run path writes for
// a live capture; the externally-reported registrations write none) and
// returns the updated record — the caller must use the RETURNED value, since
// appending to the record's keys can move the backing array. The rewrite
// validates against no schema: the fixture record is a minimal hand-built
// row, not a full sandbox_execution record.
func markCapture(rec validation.Value,
	kvs ...validation.KV) validation.Value {
	path := filepath.Join(filepath.Dir(objStr(rec, "stdout_path")),
		"exec_record.json")
	rec.O = append(rec.O, validation.KV{K: "output_capture",
		V: validation.VObj(kvs...)})
	if err := validation.WriteJson(path, rec, ""); err != nil {
		panic(err)
	}
	return rec
}

// r38bTruncated is output_capture exactly as the run path writes it for a
// stdout capture that hit the 10 MiB cap.
func r38bTruncated(total int64) []validation.KV {
	return []validation.KV{
		kv("cap_bytes", validation.VInt(10485760)),
		kv("stdout_total_bytes", validation.VInt(total)),
		kv("stdout_truncated", validation.VBool(true)),
		kv("stderr_total_bytes", validation.VInt(0)),
		kv("stderr_truncated", validation.VBool(false)),
		kv("output_withheld", validation.VBool(false)),
	}
}

// r38bComplete is output_capture for a capture under the cap: no stream
// marked truncated.
func r38bComplete(total int64) []validation.KV {
	return []validation.KV{
		kv("cap_bytes", validation.VInt(10485760)),
		kv("stdout_total_bytes", validation.VInt(total)),
		kv("stdout_truncated", validation.VBool(false)),
		kv("stderr_total_bytes", validation.VInt(0)),
		kv("stderr_truncated", validation.VBool(false)),
		kv("output_withheld", validation.VBool(false)),
	}
}

// TestValidateExecRecordRefusesTruncatedStdout pins the gate: a record whose
// output_capture marks stdout truncated is refused with the observed
// accounting (stream, kept vs total) — and the refusal fires even though the
// KEPT bytes are a clean passing forge summary, which is exactly the
// laundering shape the cap enabled.
func TestValidateExecRecordRefusesTruncatedStdout(t *testing.T) {
	rec := testExec(t, ingestCamp(t), "docker-networkless", "", 0,
		"Ran 1 test in 3ms (test suite successful)\n"+
			"xxxxx (10 MiB of filler the cap withheld) xxxxx\n")
	rec = markCapture(rec, r38bTruncated(10485846)...)
	id := objStr(rec, "exec_id")
	err := ValidateExecRecord(id, rec)
	wantErr(t, err, "exec "+id+": stdout capture marked truncated: kept "+
		"10485760 of 10485846 bytes (cap_bytes 10485760, "+
		"stdout_truncated=true)")
	wantErr(t, err, "unfit for evidence")
}

// TestValidateExecRecordRefusesTruncatedStderr pins the stderr arm: the
// forge-meaningfulness reader consumes BOTH logs, so a stderr the record
// marks truncated is refused too, naming stderr's own accounting.
func TestValidateExecRecordRefusesTruncatedStderr(t *testing.T) {
	rec := testExec(t, ingestCamp(t), "docker-networkless", "", 0, "PASS\n")
	rec = markCapture(rec,
		kv("cap_bytes", validation.VInt(10485760)),
		kv("stdout_total_bytes", validation.VInt(5)),
		kv("stdout_truncated", validation.VBool(false)),
		kv("stderr_total_bytes", validation.VInt(11000000)),
		kv("stderr_truncated", validation.VBool(true)),
		kv("output_withheld", validation.VBool(false)),
	)
	id := objStr(rec, "exec_id")
	err := ValidateExecRecord(id, rec)
	wantErr(t, err, "stderr capture marked truncated: kept 10485760 of "+
		"11000000 bytes (cap_bytes 10485760, stderr_truncated=true)")
}

// TestValidateExecRecordTruncatedWithheldTotal pins the withheld arm: a
// record whose totals are null (a live copier held the output) states no
// total — the refusal must say so instead of inventing a count (the ledger
// never claims what did not happen).
func TestValidateExecRecordTruncatedWithheldTotal(t *testing.T) {
	rec := testExec(t, ingestCamp(t), "docker-networkless", "", 0, "PASS\n")
	rec = markCapture(rec,
		kv("cap_bytes", validation.VInt(10485760)),
		kv("stdout_total_bytes", validation.VNull()),
		kv("stdout_truncated", validation.VBool(true)),
		kv("stderr_total_bytes", validation.VNull()),
		kv("stderr_truncated", validation.VBool(false)),
		kv("output_withheld", validation.VBool(true)),
	)
	id := objStr(rec, "exec_id")
	err := ValidateExecRecord(id, rec)
	wantErr(t, err, "stdout capture marked truncated: kept 10485760 of "+
		"None (output withheld — the true byte count is not in the record) "+
		"bytes (cap_bytes 10485760, stdout_truncated=true)")
}

// TestValidateExecRecordUntruncatedUnchanged pins the additive law: a record
// with an output_capture that marks NO stream truncated, and a record with
// no output_capture at all, both take the pre-P2-2 path — a clean forge
// summary passes the gate untouched.
func TestValidateExecRecordUntruncatedUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		mark []validation.KV
	}{
		{"no output_capture", nil},
		{"capture under the cap", r38bComplete(69)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := testExec(t, ingestCamp(t), "docker-networkless", "", 0,
				"PASS: test_exploit\n")
			if tc.mark != nil {
				rec = markCapture(rec, tc.mark...)
			}
			if err := ValidateExecRecord(objStr(rec, "exec_id"),
				rec); err != nil {
				t.Fatalf("untruncated record refused: %v", err)
			}
		})
	}
}

// TestIngestExecRefTruncatedRefused pins the ingest path through the SAME
// gate: an evidence item citing an exec whose capture the record marks
// truncated is refused by name — truncation alone flipped acceptance to
// refusal, the mirror of the mint-side flip.
func TestIngestExecRefTruncatedRefused(t *testing.T) {
	c := ingestCamp(t)
	rec := testExec(t, c, "docker-networkless", "", 0,
		"Ran 1 test in 3ms (test suite successful)\n")
	rec = markCapture(rec, r38bTruncated(10485846)...)
	id := objStr(rec, "exec_id")
	_, err := IngestHypothesis(c, t2ExecRefPayload(id, "EV-trunc"),
		"code", "", "")
	wantErr(t, err, "ingest refused: evidence EV-trunc exec_ref "+id+
		": exec "+id+": stdout capture marked truncated: kept 10485760 of "+
		"10485846 bytes")
}

// TestIngestExecRefTruncatedKeepsOrder pins the doc's phase order against
// the new clause: a payload that BOTH misdeclares its type AND cites a
// truncated exec reports the exec-ledger refusal (the exec_ref checks run
// before the derivation is consulted — the truncated record is the more
// actionable fact).
func TestIngestExecRefTruncatedKeepsOrder(t *testing.T) {
	c := ingestCamp(t)
	rec := testExec(t, c, "docker-networkless", "", 0, "PASS\n")
	rec = markCapture(rec, r38bTruncated(10485769)...)
	id := objStr(rec, "exec_id")
	p := t2ExecRefPayload(id, "EV-order")
	p.O = validation.SetOrAppend(p.O, "verification", validation.VObj(
		kv("reproduction", validation.VObj(
			kv("tier_reached", validation.VStr("T3"))))))
	p.O = validation.SetOrAppend(p.O, "evidence", validation.VArr(
		func() validation.Value {
			it := validation.VObj(t2ExecRefItem(id, "EV-order").O...)
			for i, e := range it.O {
				if e.K == "type" {
					it.O[i] = kv("type", validation.VStr("fork-test"))
				}
				if e.K == "level" {
					it.O[i] = kv("level", validation.VStr("E5"))
				}
			}
			return it
		}()))
	_, err := IngestHypothesis(c, p, "code", "", "")
	if err == nil {
		t.Fatal("truncated exec must be refused")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("the ledger refusal must fire before the derivation: %v",
			err)
	}
}

// TestExecTruncatedCaptureReader pins the shared reader's precedence and
// honesty laws: stdout before stderr, nil for a record without
// output_capture (the ledger never claims what did not happen), and nil for
// a capture that marks no stream.
func TestExecTruncatedCaptureReader(t *testing.T) {
	if tc := ExecTruncatedCapture(testExec(t, ingestCamp(t),
		"docker-networkless", "", 0, "PASS\n")); tc != nil {
		t.Fatalf("record without output_capture must read nil, got %+v", tc)
	}
	rec := testExec(t, ingestCamp(t), "docker-networkless", "", 0, "PASS\n")
	rec.O = append(rec.O, validation.KV{K: "output_capture", V: validation.VObj(
		kv("stdout_truncated", validation.VBool(false)),
		kv("stderr_truncated", validation.VBool(false)),
	)})
	if tc := ExecTruncatedCapture(rec); tc != nil {
		t.Fatalf("unmarked capture must read nil, got %+v", tc)
	}
	rec.O[len(rec.O)-1] = validation.KV{K: "output_capture",
		V: validation.VObj(
			kv("stdout_truncated", validation.VBool(false)),
			kv("stderr_truncated", validation.VBool(true)),
		)}
	tc := ExecTruncatedCapture(rec)
	if tc == nil || tc.Stream != "stderr" {
		t.Fatalf("stderr-only mark must return stderr, got %+v", tc)
	}
	if tc.Kept() != 0 {
		t.Fatalf("Kept with no cap_bytes = %d, want 0 (the record states no "+
			"cap — the reader invents nothing)", tc.Kept())
	}
}
