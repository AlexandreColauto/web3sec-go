package wilson

import "testing"

func TestIntervalPinnedTable(t *testing.T) {
	cases := []struct {
		k, n   int
		lo, hi float64
	}{
		{2, 2, 0.342380, 1.0},        // the 2-gold case: NOT 20% — the
		{2, 3, 0.207660, 0.938508},   // doc's illustrative "20–100" belongs
		{15, 16, 0.716713, 0.988881}, // to 2/3, not 2/2 (G7 erratum, Task 19)
		{0, 1, 0.0, 0.793451},
		{8, 10, 0.490162, 0.943318},
	}
	for _, c := range cases {
		lo, hi := Interval(c.k, c.n)
		if d := lo - c.lo; d > 1e-5 || d < -1e-5 {
			t.Fatalf("Interval(%d,%d) lo = %v, want %v", c.k, c.n, lo, c.lo)
		}
		if d := hi - c.hi; d > 1e-5 || d < -1e-5 {
			t.Fatalf("Interval(%d,%d) hi = %v, want %v", c.k, c.n, hi, c.hi)
		}
	}
}

func TestIntervalEdges(t *testing.T) {
	if lo, hi := Interval(0, 0); lo != 0 || hi != 0 {
		t.Fatalf("n=0 must be (0,0), got (%v,%v)", lo, hi)
	}
	if lo, hi := Interval(-1, 5); lo != 0 || hi != 0 {
		t.Fatal("k<0 must be (0,0)")
	}
	if lo, hi := Interval(6, 5); lo != 0 || hi != 0 {
		t.Fatal("k>n must be (0,0) — nonsense input, refuse loudly-by-zero")
	}
}

func TestFormat(t *testing.T) {
	got := Format(2, 2, "recall")
	want := "recall: 2/2 (95% CI 34.2–100.0%)" // en-dash, one decimal
	if got != want {
		t.Fatalf("Format = %q, want %q", got, want)
	}
	if got := Format(0, 0, "precision"); got != "precision: 0/0 (95% CI n/a)" {
		t.Fatalf("empty n must render n/a, got %q", got)
	}
}
