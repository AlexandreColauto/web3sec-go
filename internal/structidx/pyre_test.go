// pyre_test.go: the engine is validated against spans produced by the LIVE
// Python `re` module over the exact patterns structural_index.py compiles
// (.scratch/t25/gen_vectors.py). Any divergence in lookaround, lazy
// quantifiers or multiline anchors fails here before it can reach an
// artifact.
package structidx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

type pyreCase struct {
	Label   string  `json:"label"`
	Pattern string  `json:"pattern"`
	Input   string  `json:"input"`
	Mode    string  `json:"mode"`
	Fold    bool    `json:"fold"`
	Multi   bool    `json:"multi"`
	At      int     `json:"at"`
	Spans   [][]int `json:"spans"`
}

func loadPyreCases(t *testing.T) []pyreCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var doc struct {
		Pyre []pyreCase `json:"pyre"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	if len(doc.Pyre) < 10 {
		t.Fatalf("pyre vectors: got %d, want >= 10", len(doc.Pyre))
	}
	return doc.Pyre
}

// flatten turns the engine's capture slice into Python's regs()-style list.
func flatten(caps []int) []int {
	out := make([]int, 0, len(caps))
	for _, v := range caps {
		out = append(out, v)
	}
	return out
}

func spansEqual(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// byteToChar maps the engine's byte offsets onto Python's character offsets
// (m.start() indexes the str, not the UTF-8 bytes). The engine itself is
// byte-oriented, which is what the parser's slicing needs; only the golden
// comparison has to translate.
func byteToChar(s string, pos int) int {
	if pos < 0 {
		return pos
	}
	n := 0
	for i := 0; i < pos && i < len(s); {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return n
}

func TestPyreMatchesPythonSpans(t *testing.T) {
	cases := loadPyreCases(t)
	checked := 0
	for _, c := range cases {
		rx := compilePyre(c.Pattern, c.Fold, c.Multi)
		var got [][]int
		switch c.Mode {
		case "findall":
			for _, caps := range rx.findAll(c.Input) {
				got = append(got, flatten(caps))
			}
		case "search":
			if caps, ok := rx.search(c.Input, 0); ok {
				got = append(got, flatten(caps))
			}
		case "match":
			if caps, ok := rx.match(c.Input, c.At); ok {
				got = append(got, flatten(caps))
			}
		default:
			t.Fatalf("%s: unknown mode %q", c.Label, c.Mode)
		}
		for i := range got {
			for j := range got[i] {
				got[i][j] = byteToChar(c.Input, got[i][j])
			}
		}
		if len(got) != len(c.Spans) {
			t.Fatalf("%s: %d matches, want %d (got %v want %v)",
				c.Label, len(got), len(c.Spans), got, c.Spans)
		}
		for i := range got {
			if !spansEqual(got[i], c.Spans[i]) {
				t.Fatalf("%s[%d]: spans %v, want %v (input %q)",
					c.Label, i, got[i], c.Spans[i], c.Input)
			}
		}
		checked++
	}
	if checked != len(cases) {
		t.Fatalf("checked %d of %d cases", checked, len(cases))
	}
}

func TestPyreSubAndEmptyMatchAdvance(t *testing.T) {
	rx := compilePyre(`\s+`, false, false)
	if got := rx.sub("a  b\n\tc", " "); got != "a b c" {
		t.Fatalf("sub whitespace: %q", got)
	}
	// Python: re.findall(r"(?=b)|(?=c)", "abc") -> empty matches at 1 and 2.
	empty := compilePyre(`(?=b)|(?=c)`, false, false)
	got := empty.findAll("abc")
	if len(got) != 2 || got[0][0] != 1 || got[1][0] != 2 {
		t.Fatalf("empty findall: %v", got)
	}
	// `$` matches before a trailing newline (Python, no MULTILINE).
	dollar := compilePyre(`c$`, false, false)
	if _, ok := dollar.search("abc\n", 0); !ok {
		t.Fatalf("$ must match before a trailing newline")
	}
	if _, ok := dollar.search("abc\nx", 0); ok {
		t.Fatalf("$ must not match mid-string without MULTILINE")
	}
}
