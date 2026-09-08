package cli

// T14 cmd_hint tests: the recorded line, the content floor, the argparse
// errors, and the Python-compatible JSONL serializer the hint store uses.
// Vectors captured from the live Python CLI (.scratch/t14/py5.json).

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/validation"
)

// readHintStore returns the campaign's append-only hint JSONL.
func readHintStore(t *testing.T, root, cid string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "campaigns", cid,
		"planner_hints.jsonl"))
	if err != nil {
		t.Fatalf("read hint store: %v", err)
	}
	return string(raw)
}

var hintIDRe = regexp.MustCompile(`^HINT-[0-9a-f]{8}: kind=`)

func TestHintRecordsPriority(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "hint", cid, "--kind",
		"priority", "--content",
		"investigate the share price accounting path next pass")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !hintIDRe.MatchString(out) {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.HasSuffix(out, ": kind=priority — investigate the share "+
		"price accounting path next pass\n") {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestHintRecordsExclusion(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "hint", cid, "--kind",
		"exclusion", "--content",
		"do not re-investigate the documented transfer path",
		"--source-ref", "MEM-x", "--actor", "reflection")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasSuffix(out, ": kind=exclusion — do not re-investigate "+
		"the documented transfer path\n") {
		t.Fatalf("stdout = %q", out)
	}
	// the hint store is append-only JSONL with the attributed fields
	raw := readHintStore(t, root, cid)
	for _, want := range []string{"\"kind\": \"exclusion\"",
		"\"source_ref\": \"MEM-x\"", "\"actor\": \"reflection\""} {
		if !strings.Contains(raw, want) {
			t.Fatalf("hint store missing %s: %s", want, raw)
		}
	}
}

func TestHintContentFloor(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "hint", cid, "--kind", "note",
		"--content", "short")
	if code != 1 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "error: a planner hint needs substantive content "+
		"(>=10 chars)\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestHintInvalidKind(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "hint", cid, "--kind", "bogus",
		"--content", "a substantive hint body for the invalid-choice vector")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != t14HintUsage+"webv2 hint: error: argument --kind: invalid "+
		"choice: 'bogus' (choose from 'priority', 'exclusion', 'detector', "+
		"'note')\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestHintRequiredArguments(t *testing.T) {
	code, _, errS := run(t, "hint")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != t14HintUsage+"webv2 hint: error: the following arguments are "+
		"required: campaign, --kind, --content\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestHintHelp(t *testing.T) {
	code, out, errS := run(t, "hint", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != t14HintHelp {
		t.Fatalf("help = %q, want %q", out, t14HintHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestPyJSONLine(t *testing.T) {
	// ensure_ascii=False: non-ASCII survives; separators are ", " / ": "
	v := validation.VObj(
		validation.KV{K: "kind", V: validation.VStr("note")},
		validation.KV{K: "content", V: validation.VStr("café — ok")},
		validation.KV{K: "n", V: validation.VInt(3)},
	)
	want := `{"kind": "note", "content": "café — ok", "n": 3}`
	if got := t14PyJSONLine(v); got != want {
		t.Fatalf("t14PyJSONLine = %q, want %q", got, want)
	}
	// empty array/object render Python-style, not null
	empty := t14PyJSONLine(validation.VObj(
		validation.KV{K: "a", V: validation.VArr()},
		validation.KV{K: "b", V: validation.VObj()}))
	if empty != `{"a": [], "b": {}}` {
		t.Fatalf("empty containers = %q", empty)
	}
}

func TestPyTuple(t *testing.T) {
	if got := t14PyTuple([]string{"a", "b"}); got != "('a', 'b')" {
		t.Fatalf("t14PyTuple = %q", got)
	}
	if got := t14PyTuple([]string{"a"}); got != "('a',)" {
		t.Fatalf("single-element tuple = %q", got)
	}
	if got := t14PyTuple(nil); got != "()" {
		t.Fatalf("empty tuple = %q", got)
	}
}
