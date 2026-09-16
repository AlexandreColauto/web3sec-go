package taxonomy

import "testing"

func TestCanonicalClass(t *testing.T) {
	cases := []struct{ in, want string }{
		{"denial-of-service", "dos-griefing"},
		{"Denial-of-Service", "dos-griefing"}, // case-insensitive key, canonical value
		{"dos-griefing", "dos-griefing"},      // canonical passes through
		{"bridge-message", "bridge-message"},
		{"totally-unknown", "totally-unknown"}, // identity: unknown stays unknown
		{"", ""},
	}
	for _, tc := range cases {
		if got := CanonicalClass(tc.in); got != tc.want {
			t.Errorf("CanonicalClass(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if CanonicalClass("weird") == "unmapped" {
		t.Fatal("CanonicalClass must never invent the unmapped verdict")
	}
}
