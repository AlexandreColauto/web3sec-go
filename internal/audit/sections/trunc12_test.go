package sections

import "testing"

// trunc12 must not panic on a hash shorter than 12 bytes (the pre-fix
// s[:12] panicked on any tampered/truncated stored hash) and must truncate a
// long hash to its first 12 bytes.
func TestTrunc12ShortAndLong(t *testing.T) {
	if got := trunc12("abc"); got != "abc" {
		t.Errorf("trunc12(abc) = %q, want abc (short hash returned as-is)", got)
	}
	if got := trunc12(""); got != "" {
		t.Errorf("trunc12(\"\") = %q, want empty", got)
	}
	long := "0123456789abcdef" // 16 bytes
	if got := trunc12(long); got != "0123456789ab" {
		t.Errorf("trunc12(%q) = %q, want 0123456789ab", long, got)
	}
	exact := "0123456789ab" // exactly 12 bytes
	if got := trunc12(exact); got != exact {
		t.Errorf("trunc12(exact 12) = %q, want unchanged", got)
	}
}
