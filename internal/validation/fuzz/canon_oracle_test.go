package fuzz

import (
	"bytes"
	"encoding/json"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestCanonOracleDifferential byte-diffs the Go canonical encoder against the
// CPython oracle (scripts/canon-oracle.py) over seeded random JSON documents.
// Both sides parse the same document text, so the diff isolates the encoder.
// Integers are restricted to int64 (Value.I width; arbitrary-precision ints
// are a documented Go-side limitation) and inf/nan are excluded (Go's decoder
// rejects the JSON literals; the table tests cover them).
func TestCanonOracleDifferential(t *testing.T) {
	if testing.Short() {
		t.Skip("launches the CPython oracle")
	}
	py := "python3"
	if _, err := exec.LookPath(py); err != nil {
		t.Skip("python3 not available")
	}
	oracle := findOracle(t)

	const n = 1000
	rnd := rand.New(rand.NewSource(1))
	docs := make([]string, n)
	var input strings.Builder
	for i := range docs {
		docs[i] = genDoc(t, rnd)
		input.WriteString(docs[i])
		input.WriteByte('\n')
	}

	cmd := exec.Command(py, oracle)
	cmd.Stdin = strings.NewReader(input.String())
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("oracle run failed: %v\nstderr: %s", err, errBuf.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != n*2 {
		t.Fatalf("oracle produced %d lines, want %d", len(lines), n*2)
	}

	for i, doc := range docs {
		wantSpaced := lines[2*i]
		wantCompact := lines[2*i+1]
		got := validation.Canon(parseDoc(t, doc), false)
		if got != wantSpaced {
			t.Errorf("doc %d spaced\n got:  %s\nwant: %s", i, got, wantSpaced)
			continue
		}
		got = validation.Canon(parseDoc(t, doc), true)
		if got != wantCompact {
			t.Errorf("doc %d compact\n got:  %s\nwant: %s", i, got, wantCompact)
		}
	}
}

func parseDoc(t *testing.T, doc string) validation.Value {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		t.Fatalf("parse %q: %v", doc, err)
	}
	return validation.FromAny(raw)
}

func genDoc(t *testing.T, rnd *rand.Rand) string {
	t.Helper()
	b, err := json.Marshal(genValue(rnd, 0))
	if err != nil {
		t.Fatalf("marshal generated value: %v", err)
	}
	return string(b)
}

func genValue(rnd *rand.Rand, depth int) any {
	if depth >= 5 {
		return genScalar(rnd)
	}
	switch rnd.Intn(6) {
	case 0, 1:
		return genScalar(rnd)
	case 2:
		a := make([]any, rnd.Intn(5))
		for i := range a {
			a[i] = genValue(rnd, depth+1)
		}
		return a
	default:
		m := make(map[string]any, rnd.Intn(5))
		for i := 0; i < len(m); i++ {
			m[genString(rnd)] = genValue(rnd, depth+1)
		}
		return m
	}
}

func genScalar(rnd *rand.Rand) any {
	switch rnd.Intn(5) {
	case 0:
		return nil
	case 1:
		return rnd.Intn(2) == 0
	case 2:
		// int64 only: Value.I is int64 and arbitrary-precision ints are a
		// documented Go-side limitation (schemas constrain the domain).
		if rnd.Intn(2) == 0 {
			return json.Number(strconv.FormatInt(int64(rnd.Uint64()>>1), 10))
		}
		return json.Number(strconv.FormatInt(int64(rnd.Uint64()>>1)-math.MaxInt64, 10))
	case 3:
		// Finite floats only: inf/nan cannot travel through stdin JSON
		// (Go's decoder rejects the literals). pyFloat keeps the literal a
		// float on both parsers: Go's Marshal would emit an integer-valued
		// float as a bare integer, which CPython would read back as an int.
		for {
			f := math.Float64frombits(rnd.Uint64())
			if !math.IsNaN(f) && !math.IsInf(f, 0) {
				return pyFloat(f)
			}
		}
	default:
		return genString(rnd)
	}
}

// pyFloat marshals as a JSON number that both CPython and Go parse as a
// float (an integral value keeps a ".0" so CPython does not read an int).
type pyFloat float64

func (f pyFloat) MarshalJSON() ([]byte, error) {
	s := strconv.FormatFloat(float64(f), 'g', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return []byte(s), nil
}

func genString(rnd *rand.Rand) string {
	var b strings.Builder
	const pool = "abcXYZ019 \"\\\n\t\r\b\f<>&/\x00\x01\x1f\x7f é€\u2028\u2029"
	for i := 0; i < rnd.Intn(12); i++ {
		switch rnd.Intn(4) {
		case 0:
			b.WriteByte(pool[rnd.Intn(len(pool))])
		case 1:
			c := rnd.Intn(0x110000)
			if c >= 0xd800 && c <= 0xdfff {
				c = 0x20 // unpaired surrogates cannot be JSON input
			}
			b.WriteRune(rune(c))
		case 2:
			b.WriteRune(rune(0x10000 + rnd.Intn(0x10000))) // non-BMP
		default:
			b.WriteRune(rune(0x80 + rnd.Intn(0x780)))
		}
	}
	return b.String()
}

func findOracle(t *testing.T) string {
	t.Helper()
	_, this, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	dir := filepath.Dir(this)
	for i := 0; i < 10; i++ {
		p := filepath.Join(dir, "scripts", "canon-oracle.py")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("scripts/canon-oracle.py not found")
	return ""
}
