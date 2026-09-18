package harness

import (
	"path/filepath"
	"strings"

	"websec/internal/validation"
)

// InvValue is the invariant value harness.Scaffold renders from: the
// registry entry plus the id the registry carries as its map KEY (Scaffold
// reads "id" off the record, so the key is passed in as that field). The
// scaffold command, the bind's Validate arm and the audit's re-derivation
// all go through here on purpose: if the inputs could drift, every bound run
// would be refused for bytes that never moved.
func InvValue(invID string, entry validation.Value) validation.Value {
	inv := entry
	inv.O = validation.SetOrAppend(
		append([]validation.KV(nil), entry.O...), "id",
		validation.VStr(invID))
	return inv
}

// scaffoldFileNames is the exact filename set the harness scaffold writer
// can emit for one invariant — cli.verifyScaffold's switch: "H.t.sol" for
// halmos, "F.t.sol" for forge-fuzz, "INV.mspec" for minicertora. Those are
// the harness files a run's recorded hashes may name (under any directory
// prefix: the sandbox hashes a workdir-relative path).
//
// r29b F5: this used to be "any basename containing harness, or any .mspec"
// — so a workdir file named notes-harness.txt read as a harness file and the
// bind refused a perfectly good PROVEN run with "scaffold-bound violation:
// harness file hash differs from stored scaffold", a comparison the run never
// made. A foreign file that merely has "harness" in its name maps normally; a
// GENUINE scaffold file whose sha differs still refuses.
var scaffoldFileNames = []string{"h.t.sol", "f.t.sol", "inv.mspec"}

// IsScaffoldFileKey reports whether a recorded-hash KEY names one of the
// harness scaffold files the writer emits (case-folded basename, so
// "artifacts/harness/INV-1/INV.mspec" and a bare "H.t.sol" both qualify).
// The bind's hash arm and every audit question about "does this record carry
// harness-file hash evidence?" ask this ONE predicate (r29b F5).
func IsScaffoldFileKey(key string) bool {
	base := strings.ToLower(filepath.Base(key))
	for _, name := range scaffoldFileNames {
		if base == name {
			return true
		}
	}
	return false
}

// ScaffoldFileHash is one recorded hash whose key names a scaffold file: the
// key verbatim (so a refusal can quote what the record says) and its sha
// ("" when the value was not a non-empty string, which is not hash
// evidence).
type ScaffoldFileHash struct {
	Key string
	SHA string
}

// ScaffoldFileHashes returns every recorded (key, sha) pair whose key names
// a harness scaffold file, in input_hashes-then-artifact_hashes order.
//
// This is the REAL question r29b F3 was about: whether a record carries
// harness-FILE hash evidence at all. RecordedHashes answers a wider one (it
// also collects every recorded sha, and every sandbox record carries the
// artifact_hashes stdout/stderr digests), so `len(hashes) > 0` was true for
// EVERY real record and the audit's "scaffold bytes unobtainable" arm told
// the operator about hash evidence the record never had.
func ScaffoldFileHashes(rec validation.Value) []ScaffoldFileHash {
	var out []ScaffoldFileHash
	for _, key := range []string{"input_hashes", "artifact_hashes"} {
		m := recordField(rec, key)
		if m.Kind != validation.Obj {
			continue
		}
		for _, kv := range m.O {
			if !IsScaffoldFileKey(kv.K) {
				continue
			}
			sha := ""
			if kv.V.Kind == validation.Str {
				sha = kv.V.S
			}
			out = append(out, ScaffoldFileHash{Key: kv.K, SHA: sha})
		}
	}
	return out
}

// NormalizeKind resolves a stored kind string case-insensitively to the
// canonical Kind some mapper implements, and reports whether one does at
// all. The reachable blessing-rung kinds (worked out from the bind paths,
// not guessed) are:
//
//   - halmos / forge-fuzz / minicertora — cli.harnessKindFor (the --kind
//     flag, which argparse already restricts to those three, or the
//     HARNESS-<INV>-<kind> suffix of a harness_scaffold event), whose
//     evidence is the exec's captured stdout and whose mapper is MapRun /
//     MapMinicertoraInvoc behind DecideBound;
//   - miniprover — cli.verifyAutoprove's report-bound rung
//     (cmd_verify_autoprove.go writes harness.Kind("miniprover"), with or
//     without a wrapping sandbox EXEC), whose evidence is the registered
//     report bytes and whose mapper is MapReport.
//
// Anything else — "mythril", "MINICERTORA" (a spelling the bind never
// writes), "" — names no mapper, so r29b F1 requires the audit to refuse it
// by name instead of skipping the rail.
func NormalizeKind(s string) (Kind, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(Halmos):
		return Halmos, true
	case string(ForgeFuzz):
		return ForgeFuzz, true
	case string(MiniCertora):
		return MiniCertora, true
	case "miniprover":
		return Kind("miniprover"), true
	}
	return "", false
}

// NormalizeScaffoldKind is NormalizeKind restricted to the three kinds the
// scaffold writer can render (cli.verifyScaffold's --scaffold/--kind
// vocabulary: halmos, forge-fuzz, minicertora). The report-bound kind
// ("miniprover") is a Kind a bind writes, but it has no scaffold and no
// --kind spelling, so the scaffolder's own resolver must not accept it.
func NormalizeScaffoldKind(s string) (Kind, bool) {
	k, ok := NormalizeKind(s)
	if !ok || string(k) == "miniprover" {
		return "", false
	}
	return k, true
}

// RecordedHashes collects every recorded file hash from the exec record
// (input_hashes plus artifact_hashes values) and whether any key names a
// harness scaffold FILE — H.t.sol / F.t.sol / INV.mspec, the names
// cli.verifyScaffold writes, under any directory prefix (r29b F5: the
// predicate is IsScaffoldFileKey, shared with the audit; it used to accept
// anything with "harness" in the basename or a ".mspec" suffix, so a workdir
// file named notes-harness.txt fabricated a scaffold-bound violation).
//
// Both the bind and the audit's "can I re-derive this without the scaffold
// bytes?" question read this one function. The harnessNamed BIT is what
// decides "this record carries harness-file hash evidence"; ScaffoldFileHashes
// is the same predicate with the keys and shas kept.
func RecordedHashes(rec validation.Value) (hashes []string,
	harnessNamed bool) {
	for _, key := range []string{"input_hashes", "artifact_hashes"} {
		m := recordField(rec, key)
		if m.Kind != validation.Obj {
			continue
		}
		for _, kv := range m.O {
			if kv.V.Kind == validation.Str && kv.V.S != "" {
				hashes = append(hashes, kv.V.S)
			}
			if IsScaffoldFileKey(kv.K) {
				harnessNamed = true
			}
		}
	}
	return hashes, harnessNamed
}

// ScaffoldDegradedReason reduces a harness.Validate error to the
// scaffold-line reason the refusal text carries. Validate's messages have
// two fixed shapes — lineDiffErr's "harness: scaffold-bound: <reason>
// (<region> line <n>: want <q> got <q>)" and BodyRegion's "harness:
// scaffold-bound: missing BODY start marker" (plus its siblings) — so the
// drift CLASS is what sits between the prefix and the first region detail;
// the quoted want/got bytes are diagnostics, not the refusal. Anything
// unrecognized rides whole: a refusal must never lose its reason.
func ScaffoldDegradedReason(err error) string {
	msg := strings.TrimPrefix(err.Error(), "harness: ")
	msg = strings.TrimPrefix(msg, "scaffold-bound: ")
	for _, anchor := range []string{" (pre-body line ", " (post-body line "} {
		if i := strings.Index(msg, anchor); i >= 0 {
			return msg[:i]
		}
	}
	return msg
}
