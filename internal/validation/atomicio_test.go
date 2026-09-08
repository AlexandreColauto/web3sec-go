package validation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadJsonRoundTrip: ReadJson preserves key order and the int/float
// distinction (json.load semantics).
func TestReadJsonRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.json")
	if err := os.WriteFile(p, []byte(`{"b": 1, "a": 1.5, "c": null}`), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != Obj || len(v.O) != 3 {
		t.Fatalf("bad object: %+v", v)
	}
	if v.O[0].K != "b" || v.O[1].K != "a" || v.O[2].K != "c" {
		t.Errorf("key order not preserved: %v", v.O)
	}
	if v.O[0].V.Kind != Int || v.O[0].V.I != 1 {
		t.Errorf("1 must be Int: %+v", v.O[0].V)
	}
	if v.O[1].V.Kind != Flt || v.O[1].V.F != 1.5 {
		t.Errorf("1.5 must be Flt: %+v", v.O[1].V)
	}
}

// TestReadJsonNonASCII: non-ASCII strings survive the read as raw UTF-8.
func TestReadJsonNonASCII(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "u.json")
	if err := os.WriteFile(p, []byte(`{"s": "café \u0627"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := objKey(v, "s"); got.Kind != Str || got.S != "café \u0627" {
		t.Errorf("non-ascii mangled: %+v", got)
	}
}

// TestWriteJsonFormat: mkdir parents, indent=2, ensure_ascii=False (raw
// UTF-8), exactly one trailing newline.
func TestWriteJsonFormat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a", "b", "out.json")
	data := VObj(
		KV{"a", VArr(VInt(1), VStr("x"))},
		KV{"b", VObj()},
		KV{"d", VStr("é")},
	)
	if err := WriteJson(p, data, ""); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"a\": [\n    1,\n    \"x\"\n  ],\n  \"b\": {},\n  \"d\": \"é\"\n}\n"
	if string(raw) != want {
		t.Errorf("format mismatch:\n got %q\nwant %q", string(raw), want)
	}
	if !strings.HasSuffix(string(raw), "}\n") || strings.HasSuffix(string(raw), "\n\n") {
		t.Error("trailing newline not exactly one")
	}
}

// TestWriteJsonValidation: a schema failure raises SchemaError and writes
// NOTHING (no file, no tmp residue).
func TestWriteJsonValidation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	bad := VObj(
		KV{"finding_id", VStr("nope")},
	)
	err := WriteJson(p, bad, "finding")
	var se *SchemaError
	if !asSchemaError(err, &se) {
		t.Fatalf("expected *SchemaError, got %v", err)
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Error("file must not exist after validation failure")
	}
	if _, statErr := os.Stat(p + ".tmp"); !os.IsNotExist(statErr) {
		t.Error("tmp file must not exist after validation failure")
	}
}

// TestWriteJsonAtomic: the tmp name is path+".tmp" (full suffix preserved)
// and no .tmp residue remains after success.
func TestWriteJsonAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	if err := WriteJson(p, VInt(1), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Error("tmp residue after success")
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != "1\n" {
		t.Errorf("scalar write: %q", raw)
	}
	// No-suffix path: foo -> foo.tmp
	p2 := filepath.Join(dir, "bare")
	if err := WriteJson(p2, VInt(2), ""); err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(p2)
	if string(raw2) != "2\n" {
		t.Errorf("bare write: %q", raw2)
	}
	if _, err := os.Stat(p2 + ".tmp"); !os.IsNotExist(err) {
		t.Error("tmp residue after bare write")
	}
}

// TestWriteJsonBigInt: integers beyond int64 round-trip exactly (Python
// ints are arbitrary precision; web3 wei values routinely exceed 2^63).
func TestWriteJsonBigInt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.json")
	v, err := ParseOrdered([]byte(`{"wei": 12345678901234567890, "neg": -115792089237316195423570985008687907853269984665640564039457584007913129639935}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteJson(p, v, ""); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	want := "{\n  \"wei\": 12345678901234567890,\n  \"neg\": -115792089237316195423570985008687907853269984665640564039457584007913129639935\n}\n"
	if string(raw) != want {
		t.Errorf("big-int round-trip:\n got %q\nwant %q", raw, want)
	}
	if got := PyRepr(objKey(v, "wei")); got != "12345678901234567890" {
		t.Errorf("PyRepr big-int: %q", got)
	}
}

// TestSha256File: matches sha256sum on a fixed input.
func TestSha256File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.bin")
	if err := os.WriteFile(p, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := Sha256File(p)
	if err != nil {
		t.Fatal(err)
	}
	// sha256("abc"), well-known
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if h != want {
		t.Errorf("sha256: got %s want %s", h, want)
	}
	if got := Sha256Hex([]byte("abc")); got != want {
		t.Errorf("Sha256Hex: %s", got)
	}
}

// TestAppendJsonl: append creates the file, each call adds one
// newline-terminated line.
func TestAppendJsonl(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.jsonl")
	if err := AppendJsonl(p, `{"a": 1}`); err != nil {
		t.Fatal(err)
	}
	if err := AppendJsonl(p, `{"a": 2}`); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	want := `{"a": 1}
{"a": 2}
`
	if string(raw) != want {
		t.Errorf("jsonl content: %q", raw)
	}
}

// TestAppendJsonlAscii: the ASCII-required log (events/costs split policy)
// rejects non-ASCII lines (Go-native hardening over the Python port).
func TestAppendJsonlAscii(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "e.jsonl")
	if err := AppendJsonlAscii(p, `{"a": 1}`); err != nil {
		t.Fatal(err)
	}
	if err := AppendJsonlAscii(p, `{"s": "é"}`); err == nil {
		t.Error("non-ascii line must be rejected")
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != `{"a": 1}
` {
		t.Errorf("rejected line must not be written: %q", raw)
	}
}
