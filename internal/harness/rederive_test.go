package harness

// rederive_test.go — the shared decision entry point's own contract (r28b
// F2/F3). Package cli and section 11 both call DecideBound; these cases pin
// the arms it must reproduce, the exit-status law it reads, and the
// "scaffold bytes unavailable" carve-out for the audit's read arm.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"websec/internal/validation"
)

// rdRecord builds an exec record from raw key/value pairs.
func rdRecord(kvs ...validation.KV) validation.Value {
	return validation.VObj(kvs...)
}

// rdInv is the invariant record the scaffold renders from.
func rdInv(stmt string) validation.Value {
	return validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-1")},
		validation.KV{K: "statement", V: validation.VStr(stmt)},
	)
}

// rdProven is an attributed PROVEN line for rule inv_1 at loop_bound 4.
const rdProven = `{"rule":"inv_1","verdict":"PROVEN",` +
	`"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000}}` + "\n"

func rdSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestRecordExitStatusIsTheOneReading pins the F2 law: an int exit_status is
// the run's report, everything else — absent, null, or an integer wider than
// int64 — is -2 ("never reported a clean exit"), and the timeout bit is
// derived from the same reading.
func TestRecordExitStatusIsTheOneReading(t *testing.T) {
	cases := []struct {
		name string
		rec  validation.Value
		want int
	}{
		{"absent", rdRecord(validation.KV{K: "exec_id",
			V: validation.VStr("EXEC-1")}), -2},
		{"null", rdRecord(validation.KV{K: "exit_status",
			V: validation.VNull()}), -2},
		{"big", rdRecord(validation.KV{K: "exit_status",
			V: validation.VBigInt("99999999999999999999")}), -2},
		{"zero", rdRecord(validation.KV{K: "exit_status",
			V: validation.VInt(0)}), 0},
		{"one", rdRecord(validation.KV{K: "exit_status",
			V: validation.VInt(1)}), 1},
		{"killed", rdRecord(validation.KV{K: "exit_status",
			V: validation.VInt(137)}), 137},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RecordExitStatus(tc.rec); got != tc.want {
				t.Fatalf("RecordExitStatus = %d, want %d", got, tc.want)
			}
			if got, want := RecordTimedOut(tc.rec),
				TimedOutBit(tc.want); got != want {
				t.Fatalf("RecordTimedOut = %v, want %v", got, want)
			}
		})
	}
}

// TestDecideBoundReproducesTheBindsArms pins the whole decision: the hash
// arm, the Validate re-render, the harness-named violation, the unbound
// suffix and the audit's "bytes unavailable" carve-out.
func TestDecideBoundReproducesTheBindsArms(t *testing.T) {
	inv := rdInv("total always covers sum(payouts)")
	scaffold, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatal(err)
	}
	drifted := rdInv("total always covers sum(payouts), always")
	bound := rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-1")},
		validation.KV{K: "exit_status", V: validation.VInt(0)},
		validation.KV{K: "input_hashes", V: validation.VObj(
			validation.KV{K: "artifacts/harness/INV-1/INV.mspec",
				V: validation.VStr(rdSHA(scaffold))})})
	foreign := rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-2")},
		validation.KV{K: "exit_status", V: validation.VInt(0)},
		validation.KV{K: "input_hashes", V: validation.VObj(
			validation.KV{K: "artifacts/harness/INV-1/INV.mspec",
				V: validation.VStr(strings.Repeat("0", 64))})})
	unbound := rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-3")},
		validation.KV{K: "exit_status", V: validation.VInt(0)})
	// The shape the sandbox itself writes (sandbox.RegisterExec): every real
	// record carries its own captured-output digests, and NOTHING else.
	captures := rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-4")},
		validation.KV{K: "exit_status", V: validation.VInt(0)},
		validation.KV{K: "artifact_hashes", V: validation.VObj(
			validation.KV{K: "stdout.log", V: validation.VStr("aa")},
			validation.KV{K: "stderr.log", V: validation.VStr("bb")})})
	// A FOREIGN spec file — F5's notes-harness.txt shape, with the suffix the
	// old predicate also treated as harness evidence.
	foreignSpec := rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-5")},
		validation.KV{K: "exit_status", V: validation.VInt(0)},
		validation.KV{K: "input_hashes", V: validation.VObj(
			validation.KV{K: "notes-harness.txt", V: validation.VStr("aa")},
			validation.KV{K: "sibling.mspec", V: validation.VStr("bb")})})

	cases := []struct {
		name    string
		inv     validation.Value
		rec     validation.Value
		scr     []byte
		wantRun string
		wantSum string // exact when set
		wantBK  int    // -1 = must be nil
	}{
		{
			name: "matching hash binds and maps", inv: inv, rec: bound,
			scr: scaffold, wantRun: RungProvedBounded,
			wantSum: "proved bounded (k=4)", wantBK: 4,
		},
		{
			name: "matching hash over a drifted claim refuses",
			inv:  drifted, rec: bound, scr: scaffold,
			wantRun: RungInconclusive,
			wantSum: "scaffold-degraded: natspec invariant line changed",
			wantBK:  -1,
		},
		{
			name: "harness-named foreign hash refuses",
			inv:  inv, rec: foreign, scr: scaffold,
			wantRun: RungInconclusive,
			wantSum: "scaffold-bound violation: harness file hash " +
				"differs from stored scaffold",
			wantBK: -1,
		},
		{
			name: "no hash info maps with the unbound suffix",
			inv:  inv, rec: unbound, scr: scaffold,
			wantRun: RungProvedBounded,
			wantSum: "proved bounded (k=4)" + unboundSuffix, wantBK: 4,
		},
		{
			name: "unbound with drifted bytes refuses",
			inv:  drifted, rec: unbound, scr: scaffold,
			wantRun: RungInconclusive,
			wantSum: "scaffold-degraded: natspec invariant line changed",
			wantBK:  -1,
		},
		{
			// The audit's read arm could not obtain the bytes and the
			// record carries hash evidence: the hash arm cannot be
			// re-derived, so this refuses (constraint 3).
			name: "no bytes with hash evidence refuses",
			inv:  inv, rec: bound, scr: nil,
			wantRun: RungInconclusive,
			wantSum: "scaffold-degraded: scaffold bytes unavailable " +
				"(the hash arm cannot be re-derived)",
			wantBK: -1,
		},
		{
			// ...while the UNBOUND arm's mapping needs no bytes at all.
			name: "no bytes and no hash evidence maps unbound",
			inv:  inv, rec: unbound, scr: nil,
			wantRun: RungProvedBounded,
			wantSum: "proved bounded (k=4)" + unboundSuffix, wantBK: 4,
		},
		{
			// r29b F3(a): the sandbox's own capture digests are NOT
			// harness-file hash evidence, so this maps unbound instead of
			// refusing over a hash comparison that never existed.
			name: "no bytes with only capture digests maps unbound",
			inv:  inv, rec: captures, scr: nil,
			wantRun: RungProvedBounded,
			wantSum: "proved bounded (k=4)" + unboundSuffix, wantBK: 4,
		},
		{
			// r29b F5: a foreign file whose name merely CONTAINS harness (or
			// merely ends in .mspec) is not harness-file evidence either.
			name: "no bytes with foreign harness-named files maps unbound",
			inv:  inv, rec: foreignSpec, scr: nil,
			wantRun: RungProvedBounded,
			wantSum: "proved bounded (k=4)" + unboundSuffix, wantBK: 4,
		},
		{
			// F5's other half: a GENUINE scaffold filename is harness-file
			// evidence whatever its sha, so no bytes still refuses.
			name: "no bytes with a scaffold file key refuses",
			inv:  inv, scr: nil,
			rec: rdRecord(
				validation.KV{K: "exec_id", V: validation.VStr("EXEC-6")},
				validation.KV{K: "exit_status", V: validation.VInt(0)},
				validation.KV{K: "input_hashes", V: validation.VObj(
					validation.KV{K: "t/H.t.sol",
						V: validation.VStr("aa")})}),
			wantRun: RungInconclusive,
			wantSum: "scaffold-degraded: scaffold bytes unavailable " +
				"(the hash arm cannot be re-derived)",
			wantBK: -1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rung, summary, _, bk := DecideBound(MiniCertora, tc.inv, []byte(rdProven),
				tc.rec, tc.scr, false, 4, RecordExitStatus(tc.rec),
				MspecRuleName("INV-1"))
			if rung != tc.wantRun {
				t.Fatalf("rung = %q, want %q (%s)", rung, tc.wantRun, summary)
			}
			if summary != tc.wantSum {
				t.Fatalf("summary = %q, want %q", summary, tc.wantSum)
			}
			if tc.wantBK < 0 {
				if bk != nil {
					t.Fatalf("bounded_k = %d, want nil", *bk)
				}
				return
			}
			if bk == nil || *bk != tc.wantBK {
				t.Fatalf("bounded_k = %v, want %d", bk, tc.wantBK)
			}
		})
	}
}

// TestDecideBoundExitStatusFloorsTheBlessing pins the F2 half at the entry
// point: an absent exit_status floors a PROVEN line to inconclusive even
// when every hash arm passes.
func TestDecideBoundExitStatusFloorsTheBlessing(t *testing.T) {
	inv := rdInv("total always covers sum(payouts)")
	scaffold, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatal(err)
	}
	rec := rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-4")},
		validation.KV{K: "input_hashes", V: validation.VObj(
			validation.KV{K: "artifacts/harness/INV-1/INV.mspec",
				V: validation.VStr(rdSHA(scaffold))})})
	rung, summary, _, bk := DecideBound(MiniCertora, inv, []byte(rdProven),
		rec, scaffold, false, 4, RecordExitStatus(rec), MspecRuleName("INV-1"))
	if rung != RungInconclusive || bk != nil {
		t.Fatalf("absent exit_status blessed: rung=%q bk=%v", rung, bk)
	}
	if summary != "inconclusive (exit output unmapped)" {
		t.Fatalf("summary = %q", summary)
	}
}

// TestRecordedHashesIsOneReader pins the reader both callers share (the
// .mspec suffix is the arm a foreign spec file must trip).
func TestRecordedHashesIsOneReader(t *testing.T) {
	rec := rdRecord(validation.KV{K: "input_hashes", V: validation.VObj(
		validation.KV{K: "spec/INV.mspec", V: validation.VStr("aa")},
		validation.KV{K: "notes.txt", V: validation.VStr("bb")},
		validation.KV{K: "empty", V: validation.VStr("")})})
	hashes, named := RecordedHashes(rec)
	if len(hashes) != 2 || hashes[0] != "aa" || hashes[1] != "bb" {
		t.Fatalf("hashes = %v", hashes)
	}
	if !named {
		t.Fatal("a .mspec entry must read as harness-named")
	}
	if _, named := RecordedHashes(rdRecord(
		validation.KV{K: "input_hashes", V: validation.VObj(
			validation.KV{K: "notes.txt", V: validation.VStr("bb")})})); named {
		t.Fatal("an unrelated file must not read as harness-named")
	}
}
