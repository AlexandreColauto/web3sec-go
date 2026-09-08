package validation

import (
	"bytes"
	"math"
	"math/rand"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TestPythonRound: expectations captured from CPython 3.14 (the reference).
// Comparison is bit-exact so the -0.0 sign convention is checked too.
func TestPythonRound(t *testing.T) {
	negZero := math.Copysign(0, -1)
	tests := []struct {
		name string
		x    float64
		n    int
		want float64
	}{
		{"half to even down", 2.5, 0, 2},
		{"half to even up", 1.5, 0, 2},
		{"neg half to even down", -2.5, 0, -2},
		{"neg half to even up", -1.5, 0, -2},
		{"zero tie to even", 0.5, 0, 0},
		{"near int", 2.4, 0, 2},
		{"three half", 3.5, 0, 4},
		{"four half", 4.5, 0, 4},
		{"binary below decimal", 2.675, 2, 2.67},
		{"exact tie to even", 0.0625, 3, 0.062},
		{"neg exact tie to even", -0.0625, 3, -0.062},
		{"binary above decimal", 0.065, 2, 0.07},
		{"one one five", 1.15, 1, 1.1},
		{"five cent", 0.05, 1, 0.1},
		{"neg five cent", -0.05, 1, -0.1},
		{"tiny neg keeps sign", -1e-20, 2, negZero},
		{"tiny pos zero", 1e-20, 2, 0},
		{"already short", 2.5, 1, 2.5},
		{"float sum artifact", 0.1 + 0.2, 1, 0.3},
		{"eight cents", 0.08, 3, 0.08},
		{"big money", 123456.789, 2, 123456.79},
		{"max float", 1e308, 2, 1e308},
		{"min subnormal", 5e-324, 6, 0},
		{"min subnormal neg", -5e-324, 6, negZero},
		{"zero", 0, 2, 0},
		{"neg zero", negZero, 2, negZero},
		{"hundred", 100.0, 1, 100.0},
		{"neg hundred", -100.0, 1, -100.0},
		{"rounds to ten", 9.999999999999998, 4, 10.0},
		{"just under one", 0.9999999999999999, 1, 1.0},
		{"pi five", 3.141592653589793, 5, 3.14159},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pythonRound(tt.x, tt.n)
			if math.Float64bits(got) != math.Float64bits(tt.want) {
				t.Errorf("pythonRound(%v, %d) = %v, want %v", tt.x, tt.n, got, tt.want)
			}
		})
	}
}

// TestPythonRoundOracle byte-diffs pythonRound against CPython round(x, n)
// over structured (small-denominator binary rationals — the tie habitat) and
// random full-range floats. One oracle process for the whole corpus.
func TestPythonRoundOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("launches CPython")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	const n = 20000
	rnd := rand.New(rand.NewSource(11))
	var input strings.Builder
	vals := make([]float64, n)
	ns := []int{1, 2, 3, 4, 6} // the ndigits webv2 uses
	for i := range vals {
		switch rnd.Intn(3) {
		case 0:
			den := 1 << uint(rnd.Intn(30)+1)
			vals[i] = float64(rnd.Int63()%100000) / float64(den)
		case 1:
			v := math.Float64frombits(rnd.Uint64())
			if math.IsNaN(v) || math.IsInf(v, 0) {
				vals[i] = 0
			} else {
				vals[i] = v
			}
		default:
			vals[i] = math.Copysign(float64(rnd.Intn(10000))/10000.0, float64(rnd.Intn(2)-1))
		}
		input.WriteString(strconv.FormatFloat(vals[i], 'g', -1, 64))
		input.WriteByte(' ')
		input.WriteString(strconv.Itoa(ns[i%len(ns)]))
		input.WriteByte('\n')
	}
	cmd := exec.Command("python3", "-c",
		"import sys\n"+
			"for line in sys.stdin:\n"+
			"    x, n = line.split()\n"+
			"    sys.stdout.write(repr(round(float(x), int(n))) + '\\n')")
	cmd.Stdin = strings.NewReader(input.String())
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("oracle failed: %v\n%s", err, errBuf.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("oracle produced %d lines, want %d", len(lines), n)
	}
	for i, x := range vals {
		want, err := strconv.ParseFloat(lines[i], 64)
		if err != nil {
			t.Fatalf("parse oracle line %d %q: %v", i, lines[i], err)
		}
		got := pythonRound(x, ns[i%len(ns)])
		if math.Float64bits(got) != math.Float64bits(want) {
			t.Fatalf("pythonRound(%v, %d) = %v, CPython %v", x, ns[i%len(ns)], got, want)
		}
	}
}
