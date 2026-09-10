// T26 cmd_price tests: set/table, the money formats, and the error surface.
// Vectors captured from the live Python CLI (.scratch/t26/parity.py, steps
// price_*, byte-exact).
package cli

import (
	"strings"
	"testing"
)

func TestPriceSetAndTable(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "price", cid, "table")
	if code != 0 {
		t.Fatalf("empty table exit %d: %q", code, errS)
	}
	want := "(price table empty — `webv2 price " + cid + " set " +
		"<asset> <usd> --source ...`)\n"
	if out != want {
		t.Fatalf("empty table = %q, want %q", out, want)
	}

	code, out, errS = run(t, "--root", root, "price", cid, "set", "eth",
		"3200.5", "--source", "coingecko 2026-09-01", "--actor", "lead")
	if code != 0 {
		t.Fatalf("set exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "price row PRC-") ||
		!strings.HasSuffix(out, " eth @ $3,200.50 (source: coingecko "+
			"2026-09-01)\n") {
		t.Fatalf("set stdout = %q", out)
	}

	code, out, errS = run(t, "--root", root, "price", cid, "table")
	if code != 0 {
		t.Fatalf("table exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "  ETH          $      3,200.50  as of ") ||
		!strings.HasSuffix(out, "  src: coingecko 2026-09-01\n") {
		t.Fatalf("table stdout = %q", out)
	}
}

func TestPriceRejectsNonPositive(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	for _, tc := range []struct{ arg, want string }{
		{"0", "error: usd must be a positive number, got 0.0\n"},
		{"-1", "error: usd must be a positive number, got -1.0\n"},
	} {
		code, out, errS := run(t, "--root", root, "price", cid, "set", "eth",
			tc.arg)
		if code != 1 || out != "" {
			t.Fatalf("%s: exit %d out=%q err=%q", tc.arg, code, out, errS)
		}
		if errS != tc.want {
			t.Fatalf("%s: stderr = %q, want %q", tc.arg, errS, tc.want)
		}
	}
	// A missing positional is None in argparse: set_price compares None.
	code, _, errS := run(t, "--root", root, "price", cid, "set", "eth")
	if code != 1 ||
		errS != "error: usd must be a positive number, got None\n" {
		t.Fatalf("missing usd: exit %d err=%q", code, errS)
	}
}

func TestPriceArgparse(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "price", cid, "nope", "eth")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	want := t26PriceUsage + "webv2 price: error: argument price_action: " +
		"invalid choice: 'nope' (choose from 'set', 'table')\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}
