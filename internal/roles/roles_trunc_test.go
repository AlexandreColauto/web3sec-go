package roles

// Regression: _bounded_json truncates by CHARACTERS (Python
// `raw[:max_chars]`), so a multi-byte rune straddling the budget must not
// shift the cut, and a JSON payload whose byte length exceeds the budget but
// whose character length does not must still be parsed.

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

func writeRolesFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBoundedJSONTruncatesByRunes(t *testing.T) {
	// "abcd—efgh" is 9 runes / 11 bytes; the cut at 5 must land after the
	// em dash, not mid-rune.
	p := writeRolesFile(t, "plan.json", "abcd\u2014efgh")
	v, err := boundedJSON(p, 5)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(v, "_truncated").Kind != validation.Bool ||
		!objAt(v, "_truncated").B {
		t.Fatalf("v = %v", v)
	}
	if got := objStr(v, "text"); got != "abcd\u2014" {
		t.Fatalf("text = %q", got)
	}
}

func TestBoundedJSONByteHeavyPayloadStillParses(t *testing.T) {
	// 12 runes but 21 bytes: the byte length exceeds the 12-char budget while
	// the character length does not, so the payload is parsed verbatim.
	body := "{\"a\":\"\u2014\u2014\u2014\u2014\"}"
	p := writeRolesFile(t, "plan.json", body)
	v, err := boundedJSON(p, 12)
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != validation.Obj || objStr(v, "a") != "\u2014\u2014\u2014\u2014" {
		t.Fatalf("v = %v", v)
	}
}
