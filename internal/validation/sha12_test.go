package validation

import "testing"

// TestSha12HexIsTheFirstTwelveHexChars (H11) pins the ONE id derivation the
// ingest path and its dataset adapters share. ingest, immunefi, sherlock and
// c4audit each carried a private copy of this three-line function; the
// refactor is only safe if the shared one derives exactly what each copy
// did, so the digest and the truncation are both pinned here.
func TestSha12HexIsTheFirstTwelveHexChars(t *testing.T) {
	const in = "immunefi-resolved|R-1"
	// sha256("immunefi-resolved|R-1"), independently computed.
	const full = "e9a730bce40d3f0aa6b45bd7a4b0913845c8d0507512d6ee08b8595500ade6d2"
	if got := Sha256Hex([]byte(in)); got != full {
		t.Fatalf("Sha256Hex(%q) = %q, want %q", in, got, full)
	}
	if got := Sha12Hex([]byte(in)); got != full[:12] {
		t.Fatalf("Sha12Hex(%q) = %q, want %q (= the digest's first 12 hex "+
			"chars; stored CASE- ids depend on this)", in, got, full[:12])
	}
	if got := Sha12Hex([]byte(in)); got != "e9a730bce40d" {
		t.Fatalf("Sha12Hex(%q) = %q, want the pinned literal %q", in, got,
			"e9a730bce40d")
	}
	if got := len(Sha12Hex([]byte(""))); got != 12 {
		t.Fatalf("Sha12Hex is %d chars for empty input, want 12", got)
	}
}
