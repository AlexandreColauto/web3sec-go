package harness

// zz_r29b_reader_test.go — r29b F2/F5 at the shared seams.
//
// F2: ONE stdout reader (ReadExecStdout) with the bind's candidate order, its
// 1MB cap and its truncation semantics, so the audit can only ever map the
// bytes the bind mapped. The cap is pinned here by CONTENT, not by a comment.
//
// F5: IsScaffoldFileKey is the narrowed harness-file predicate — the exact
// filenames cli.verifyScaffold writes (H.t.sol / F.t.sol / INV.mspec) — so a
// workdir file that merely has "harness" in its name is not hash evidence.
//
// Neither test touches the twin: these are the Go half's own contracts.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// zzR29bWrite writes one file under a fresh temp dir and returns its path.
func zzR29bWrite(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestZZR29BReadExecStdoutCapsAndOrders pins the one reader's three laws:
// the 1MB cap (a bigger capture is TRUNCATED at exactly StdoutCap, so the
// tail the bind never saw can never be mapped), the candidate order (an
// absolute stored stdout_path first, then <execDir>/stdout.log, then a
// RELATIVE stored path), and the two refusal shapes the bind renders as
// "no captured stdout to map" / "stdout file unreadable".
func TestZZR29BReadExecStdoutCapsAndOrders(t *testing.T) {
	dir := t.TempDir()
	execDir := filepath.Join(dir, "execs", "EXEC-1")
	big := strings.Repeat("A", StdoutCap) + "PAST-THE-CAP"
	if got := len(big); got <= StdoutCap {
		t.Fatalf("fixture is not over the cap: %d", got)
	}
	zzR29bWrite(t, execDir, "stdout.log", big)

	t.Run("cap truncates at exactly StdoutCap", func(t *testing.T) {
		rec := rdRecord(validation.KV{K: "exec_id",
			V: validation.VStr("EXEC-1")})
		raw, err := ReadExecStdout(execDir, rec)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != StdoutCap {
			t.Fatalf("len(raw) = %d, want %d (the cap)", len(raw),
				StdoutCap)
		}
		if string(raw) != big[:StdoutCap] {
			t.Fatal("the reader returned bytes past the cap")
		}
	})

	t.Run("absolute stdout_path wins over the canonical path", func(t *testing.T) {
		other := zzR29bWrite(t, filepath.Join(dir, "elsewhere"),
			"capture.log", "FROM-THE-STORED-PATH\n")
		rec := rdRecord(validation.KV{K: "stdout_path",
			V: validation.VStr(other)})
		raw, err := ReadExecStdout(execDir, rec)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != "FROM-THE-STORED-PATH\n" {
			t.Fatalf("raw = %q", raw)
		}
	})

	t.Run("relative stdout_path is a last-resort fallback", func(t *testing.T) {
		// The r13 shape: a record written under `--root .` stores a
		// CWD-relative path, so joining it against execDir double-nests it.
		// The canonical file is there, so it wins.
		rec := rdRecord(validation.KV{K: "stdout_path",
			V: validation.VStr(filepath.Join("execs", "EXEC-1",
				"stdout.log"))})
		raw, err := ReadExecStdout(execDir, rec)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != StdoutCap {
			t.Fatalf("the canonical capture must win, got %d bytes",
				len(raw))
		}
	})

	t.Run("no capture at all is the sentinel", func(t *testing.T) {
		empty := filepath.Join(dir, "nothing")
		if err := os.MkdirAll(empty, 0o755); err != nil {
			t.Fatal(err)
		}
		rec := rdRecord(validation.KV{K: "exec_id",
			V: validation.VStr("EXEC-2")})
		if _, err := ReadExecStdout(empty, rec); !errors.Is(err,
			ErrNoCapturedStdout) {
			t.Fatalf("err = %v, want ErrNoCapturedStdout", err)
		}
	})

	t.Run("a named but absent capture is unreadable, with the errno", func(t *testing.T) {
		empty := filepath.Join(dir, "nothing2")
		if err := os.MkdirAll(empty, 0o755); err != nil {
			t.Fatal(err)
		}
		missing := filepath.Join(dir, "gone", "stdout.log")
		rec := rdRecord(validation.KV{K: "stdout_path",
			V: validation.VStr(missing)})
		_, err := ReadExecStdout(empty, rec)
		var ue *StdoutUnreadableError
		if !errors.As(err, &ue) {
			t.Fatalf("err = %v, want *StdoutUnreadableError", err)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the errno must survive the wrap: %v", err)
		}
	})
}

// TestZZR29BScaffoldFileKeyIsTheNarrowPredicate pins r29b F5's predicate and
// the reader that exposes it: a workdir file named notes-harness.txt (or any
// foreign ".mspec") is NOT harness-file evidence, while the three scaffold
// filenames the writer emits are — under any directory prefix, and whatever
// their sha says (the bind's "harness file with a different sha" arm needs
// the KEY, not a match).
func TestZZR29BScaffoldFileKeyIsTheNarrowPredicate(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"artifacts/harness/INV-1/INV.mspec", true},
		{"INV.mspec", true},
		{"a/b/H.t.sol", true},
		{"F.T.SOL", true},
		{"src/harness/INV.mspec", true},
		{"notes-harness.txt", false},
		{"harness", false},
		{"my-harness-file.sol", false},
		{"other.mspec", false},
		{"cap.mspec", false},
		{"stdout.log", false},
		{"layout.json", false},
		{"", false},
	} {
		if got := IsScaffoldFileKey(tc.key); got != tc.want {
			t.Fatalf("IsScaffoldFileKey(%q) = %v, want %v", tc.key, got,
				tc.want)
		}
	}
	// RecordedHashes' harnessNamed bit is that same predicate, and its
	// hashes list still carries every recorded sha (the hash arm compares
	// them all against the scaffold).
	digests := rdRecord(validation.KV{K: "artifact_hashes", V: validation.VObj(
		validation.KV{K: "stdout.log", V: validation.VStr("aa")},
		validation.KV{K: "stderr.log", V: validation.VStr("bb")})})
	hashes, named := RecordedHashes(digests)
	if len(hashes) != 2 || named {
		t.Fatalf("a real record's own digests are not harness-file "+
			"evidence: hashes=%v named=%v", hashes, named)
	}
	bound := rdRecord(validation.KV{K: "input_hashes", V: validation.VObj(
		validation.KV{K: "artifacts/harness/INV-1/INV.mspec",
			V: validation.VStr("cc")},
		validation.KV{K: "notes-harness.txt", V: validation.VStr("dd")})})
	hashes, named = RecordedHashes(bound)
	if !named {
		t.Fatal("a scaffold-file key must read as harness-named")
	}
	if len(hashes) != 2 {
		t.Fatalf("hashes = %v", hashes)
	}
	files := ScaffoldFileHashes(bound)
	if len(files) != 1 || files[0].Key != "artifacts/harness/INV-1/INV.mspec" ||
		files[0].SHA != "cc" {
		t.Fatalf("ScaffoldFileHashes = %+v", files)
	}
}

// TestZZR29BNormalizeKindIsCaseInsensitiveAndTotal pins r29b F1(a): the
// audit resolves a stored kind case-insensitively to the kind some mapper
// implements, and reports whether one does at all — the four kinds a bind
// can write (the three scaffold kinds plus miniprover, the report-bound
// kind cli.verifyAutoprove carries) — so no kind string can switch the rail
// off by being skipped.
func TestZZR29BNormalizeKindIsCaseInsensitiveAndTotal(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want  Kind
		known bool
	}{
		{"halmos", Halmos, true},
		{"HALMOS", Halmos, true},
		{"Halmos", Halmos, true},
		{" forge-fuzz ", ForgeFuzz, true},
		{"FORGE-FUZZ", ForgeFuzz, true},
		{"minicertora", MiniCertora, true},
		{"MINICERTORA", MiniCertora, true},
		{"miniprover", Kind("miniprover"), true},
		{"MiniProver", Kind("miniprover"), true},
		{"mythril", "", false},
		{"MYTHRIL", "", false},
		{"", "", false},
		{"mini certora", "", false},
	} {
		got, ok := NormalizeKind(tc.in)
		if ok != tc.known || got != tc.want {
			t.Fatalf("NormalizeKind(%q) = (%q, %v), want (%q, %v)",
				tc.in, got, ok, tc.want, tc.known)
		}
	}
}
