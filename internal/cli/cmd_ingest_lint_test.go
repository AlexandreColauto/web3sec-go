package cli

// Wave N, T4 — `webv2 ingest --lint`, through the real verb.
//
// The contract these tests pin:
//
//   - PARITY: a payload that walks the real pipeline gets the SAME verdict and
//     the SAME bytes under --lint — the refusal is byte-equal to the real
//     refusal on the same dirty payload (exit code, stdout, stderr), and the
//     --json acceptance output is byte-equal to the real one once the clock and
//     the finding-id stream are pinned (so "same output" is provable, not
//     eyeballed);
//   - NO WRITES: a clean payload — one that would charge a discovery slot and
//     save a finding — leaves the campaign directory bit-for-bit unchanged
//     (every entry plus every file's bytes hashed), while the same payload run
//     for real DOES change that hash (the witness is not blind);
//   - EXEC_REF: the T2 ledger path behaves identically under lint — an item
//     citing a held, SUCCEEDED exec accepts (writes nothing), an unknown
//     exec_ref refuses with the real refusal's bytes;
//   - GATE MATH: the discovery-budget refusal is gate math, so --lint still
//     refuses it (identically) instead of reporting a false accept.
//
// No child tool is executed: the exec ledger record is registered through
// sandbox.RegisterExec (externally-reported), exactly like the T2 fixture.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
)

// t4Title is a valid hypothesis title (the T2 fixture's), and t4E1 is a
// non-execution evidence item ABOVE the E0 baseline: it lands the finding at
// E1, so an accepted ingest has to charge the discovery slot — exactly the
// write a lint run must not perform.
const (
	t4Title = "Unguarded rescue moves protocol-held tokens"
	t4E1    = `{"evidence_id":"EV-1","level":"E1","type":"reasoning",` +
		`"description":"rescue is reachable from the public entry point"}`
)

// t4Payload is the shared hypothesis payload; evidence "" omits the key.
func t4Payload(title, evidence string) string {
	base := `{"title":"` + title + `","root_cause":{"class":"access-control",` +
		`"description":"rescue has no role check at all"},` +
		`"affected":[{"path":"V.sol"}],` +
		`"attacker":{"profile":"arbitrary EOA","capabilities":[]}`
	if evidence == "" {
		return base + "}"
	}
	return base + `,"evidence":[` + evidence + `]}`
}

// t4Digest is the "nothing was written" witness: every entry under dir
// (directories included, so a new directory is visible too) plus every file's
// bytes, in filepath.WalkDir's deterministic lexical order.
func t4Digest(t *testing.T, dir string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			fmt.Fprintf(h, "D %s\x00", rel)
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		fmt.Fprintf(h, "F %s\x00%d\x00", rel, len(raw))
		h.Write(raw)
		return nil
	})
	if err != nil {
		t.Fatalf("digest %s: %v", dir, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// t4LintBoth runs the same payload for real and under --lint and returns both
// triples (code, stdout, stderr).
func t4LintBoth(t *testing.T, root, cid, payload string) (
	rCode, lCode int, rOut, lOut, rErr, lErr string) {
	t.Helper()
	rCode, rOut, rErr = run(t, "--root", root, "ingest", cid,
		"--json-file", payload)
	lCode, lOut, lErr = run(t, "--root", root, "ingest", cid,
		"--json-file", payload, "--lint")
	return rCode, lCode, rOut, lOut, rErr, lErr
}

// TestIngestLintRefusalMatchesReal: on a dirty payload the lint refusal is the
// real refusal — same exit code, same stdout, same stderr, byte for byte.
func TestIngestLintRefusalMatchesReal(t *testing.T) {
	_, root, cid := t2Campaign(t)
	cases := []struct{ name, file, body, want string }{
		{"schema error", "schema.json", t4Payload("short", ""),
			"ingest failed: finding validation failed at title"},
		{"unknown exec_ref", "unknown.json",
			t2ExecRefPayloadJSON("EXEC-deadbeef01"),
			"ingest failed: ingest refused: evidence EV-ref1 cites exec_ref"},
		{"E4 claim without an exec", "e4.json",
			t4Payload(t4Title, `{"evidence_id":"EV-x","level":"E4",`+
				`"type":"foundry-test","description":"smuggled",`+
				`"sandbox_profile":"docker-networkless"}`),
			"ingest failed: ingest rejected: pre-loaded evidence EV-x at E4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := t2Write(t, root, tc.file, tc.body)
			rCode, lCode, rOut, lOut, rErr, lErr := t4LintBoth(t, root, cid, p)
			if rCode == 0 {
				t.Fatalf("the real ingest accepted a dirty payload: %q", rOut)
			}
			if lCode != rCode || lOut != rOut || lErr != rErr {
				t.Fatalf("--lint is not byte-equal to the real refusal:\n"+
					"real: exit %d out %q err %q\nlint: exit %d out %q err %q",
					rCode, rOut, rErr, lCode, lOut, lErr)
			}
			if !strings.Contains(rErr, tc.want) {
				t.Fatalf("refusal = %q\nwant it to contain %q", rErr, tc.want)
			}
		})
	}
}

// TestIngestLintWritesNothing: an accepted lint run leaves the campaign
// directory byte-identical, and the same payload run for real proves the
// digest can see a write.
func TestIngestLintWritesNothing(t *testing.T) {
	c, root, cid := t2Campaign(t)
	clean := t2Write(t, root, "clean.json", t4Payload(t4Title, t4E1))
	before := t4Digest(t, c.Dir)

	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", clean, "--lint")
	if code != 0 {
		t.Fatalf("lint exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "ingested F-") ||
		!strings.Contains(out,
			"[HYPOTHESIS] (class access-control, CONFIRMED floor E4)") {
		t.Fatalf("lint acceptance output = %q", out)
	}
	if after := t4Digest(t, c.Dir); after != before {
		t.Fatalf("--lint wrote to the campaign: %s -> %s", before, after)
	}
	if entries, err := os.ReadDir(c.FindingsDir); err != nil {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Fatalf("--lint created finding files: %v", entries)
	}

	// the witness is not blind: the real ingest of the same payload writes.
	code, _, errS = run(t, "--root", root, "ingest", cid, "--json-file", clean)
	if code != 0 {
		t.Fatalf("real ingest exit %d: %q", code, errS)
	}
	if after := t4Digest(t, c.Dir); after == before {
		t.Fatal("the digest missed a real ingest — it cannot witness a lint write")
	}
}

// TestIngestLintExecRefParity: the T2 exec_ref path under lint — a held,
// SUCCEEDED exec accepts and writes nothing; an exec_ref the ledger does not
// hold refuses with the real refusal's bytes.
func TestIngestLintExecRefParity(t *testing.T) {
	c, root, cid := t2Campaign(t)
	execID := t2RegisterExec(t, c, "")
	held := t2Write(t, root, "held.json", t2ExecRefPayloadJSON(execID))
	before := t4Digest(t, c.Dir)

	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", held, "--lint")
	if code != 0 {
		t.Fatalf("lint with a held exec exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "ingested F-") {
		t.Fatalf("lint acceptance output = %q", out)
	}
	if after := t4Digest(t, c.Dir); after != before {
		t.Fatalf("--lint with exec_ref wrote to the campaign: %s -> %s",
			before, after)
	}

	unknown := t2Write(t, root, "unknown.json",
		t2ExecRefPayloadJSON("EXEC-deadbeef01"))
	rCode, lCode, rOut, lOut, rErr, lErr := t4LintBoth(t, root, cid, unknown)
	if rCode != 2 {
		t.Fatalf("real refusal exit %d, want 2: %q", rCode, rErr)
	}
	if lCode != rCode || lOut != rOut || lErr != rErr {
		t.Fatalf("exec_ref refusal diverges under --lint:\n"+
			"real: exit %d out %q err %q\nlint: exit %d out %q err %q",
			rCode, rOut, rErr, lCode, lOut, lErr)
	}
	if !strings.Contains(rErr, "exec_ref 'EXEC-deadbeef01', which this "+
		"campaign's ledger does not hold") {
		t.Fatalf("unknown-ref refusal = %q", rErr)
	}
}

// TestIngestLintJSONMatchesRealByteForByte: with the clock and the finding-id
// stream pinned, `--lint --json` prints exactly the real `--json` output — the
// finding a real ingest would have written, down to the byte — and still writes
// nothing.
func TestIngestLintJSONMatchesRealByteForByte(t *testing.T) {
	c, root, cid := t2Campaign(t)
	p := t2Write(t, root, "json.json", t4Payload(t4Title, t4E1))
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	findings.SetFindingIDSource(func() string { return "F-abcdefabcdef" })
	defer findings.SetFindingIDSource(nil)

	rCode, rOut, rErr := run(t, "--root", root, "ingest", cid,
		"--json-file", p, "--json")
	if rCode != 0 {
		t.Fatalf("real --json exit %d: %q", rCode, rErr)
	}
	if !strings.Contains(rOut, "F-abcdefabcdef") {
		t.Fatalf("the pinned finding id is not in the real output: %q", rOut)
	}
	afterReal := t4Digest(t, c.Dir)

	lCode, lOut, lErr := run(t, "--root", root, "ingest", cid,
		"--json-file", p, "--json", "--lint")
	if lCode != 0 {
		t.Fatalf("lint --json exit %d: %q", lCode, lErr)
	}
	if lOut != rOut || lErr != rErr {
		t.Fatalf("--json --lint is not byte-equal to real --json:\n"+
			"real: %q\nlint: %q", rOut, lOut)
	}
	if after := t4Digest(t, c.Dir); after != afterReal {
		t.Fatalf("--lint --json wrote to the campaign: %s -> %s",
			afterReal, after)
	}
}

// TestIngestLintSASTLaneWritesNothing: `--lint` also covers the `--from` lane
// (the T2 pipeline reached through the tool-output adapter). The lane prints
// the same summary a real run prints — T4's ruling is "print what ingest would
// print" — and still writes nothing; the real run right after proves the
// digest can see the finding.
func TestIngestLintSASTLaneWritesNothing(t *testing.T) {
	c, root, cid := t2Campaign(t)
	p := t2Write(t, root, "slither.json", t4SlitherJSON)
	before := t4Digest(t, c.Dir)

	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--from", "slither", "--json-file", p, "--lint")
	if code != 0 {
		t.Fatalf("lint --from exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "slither ingest: 1 hypotheses created\n") {
		t.Fatalf("lint --from output = %q", out)
	}
	if after := t4Digest(t, c.Dir); after != before {
		t.Fatalf("--lint on the --from lane wrote to the campaign: %s -> %s",
			before, after)
	}

	code, _, errS = run(t, "--root", root, "ingest", cid,
		"--from", "slither", "--json-file", p)
	if code != 0 {
		t.Fatalf("real --from exit %d: %q", code, errS)
	}
	if after := t4Digest(t, c.Dir); after == before {
		t.Fatal("the digest missed a real --from ingest")
	}
}

// t4SlitherJSON is a minimal REAL Slither result (results is an object
// carrying detectors[], locations live in elements[].source_mapping — the
// shape internal/datasets/slither adapts).
const t4SlitherJSON = `{"success":true,"error":null,"results":{"detectors":[
  {"check":"reentrancy-eth","impact":"High","confidence":"Medium",
   "description":"Reentrancy in Bank.withdraw (src/Bank.sol#L6-L11)",
   "elements":[{"type":"function","name":"withdraw","source_mapping":{
     "filename_relative":"src/Bank.sol","filename_short":"src/Bank.sol",
     "is_dependency":false,"lines":[6,7,8,9,10,11]}}]}]}}`

// TestIngestLintRefusesExhaustedBudget: the discovery ceiling is gate math, so
// a lint run refuses an exhausted budget exactly like the real verb — the lint
// path must not turn a refusal into a false accept.
func TestIngestLintRefusesExhaustedBudget(t *testing.T) {
	c, root, cid := t2Campaign(t)
	if code, _, errS := run(t, "--root", root, "budget", cid,
		"--set-discovery", "1", "--actor", "t4"); code != 0 {
		t.Fatalf("budget exit %d: %q", code, errS)
	}
	rise := t2Write(t, root, "rise.json", t4Payload(t4Title, t4E1))
	if code, _, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", rise); code != 0 {
		t.Fatalf("the one slot did not charge: exit %d %q", code, errS)
	}
	again := t2Write(t, root, "again.json",
		t4Payload("A second rescue hypothesis wants the same slot", t4E1))
	before := t4Digest(t, c.Dir)

	rCode, lCode, rOut, lOut, rErr, lErr := t4LintBoth(t, root, cid, again)
	if rCode != 2 {
		t.Fatalf("real refusal exit %d, want 2: %q", rCode, rErr)
	}
	if lCode != rCode || lOut != rOut || lErr != rErr {
		t.Fatalf("the budget refusal diverges under --lint:\n"+
			"real: exit %d out %q err %q\nlint: exit %d out %q err %q",
			rCode, rOut, rErr, lCode, lOut, lErr)
	}
	if !strings.Contains(rErr, "discovery budget exhausted") {
		t.Fatalf("budget refusal = %q", rErr)
	}
	if after := t4Digest(t, c.Dir); after != before {
		t.Fatalf("a refused payload wrote to the campaign: %s -> %s",
			before, after)
	}
}
