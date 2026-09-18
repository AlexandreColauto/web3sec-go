package cli

// D4 CLI tests — `dedup-signature` (ord 76) and the tier-2 candidate flagging
// it complements.
//
// Before this verb the only way to record a tier-2/3 signature was to
// hand-write the 16-hex into the finding JSON: the setters existed, the CLI did
// not expose them, and the model-facing prompt named a Python function nothing
// dispatched. And a same-root-cause pair at DIFFERENT code sites was protected
// from auto-merge but flagged by nothing, so resolve-candidate could never
// adjudicate it and each half burned its own PoC cycle.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// dedupSigFinding ingests a hypothesis at a chosen code site, so two findings
// can share a root cause at different places.
func dedupSigFinding(t *testing.T, c *state.Campaign, title, class, path,
	fn string) string {
	t.Helper()
	payload := validation.VObj(
		kvT("title", validation.VStr(title)),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr(class)),
			kvT("description", validation.VStr("the mechanism described in detail")),
		)),
		kvT("affected", validation.VArr(validation.VObj(
			kvT("path", validation.VStr(path)),
			kvT("function", validation.VStr(fn)),
		))),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("arbitrary EOA")),
			kvT("capabilities", validation.VArr()),
		)),
	)
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return validation.ObjStr(f, "finding_id")
}

func TestDedupSignatureHelpAndArgparse(t *testing.T) {
	code, out, errS := run(t, "dedup-signature", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.HasPrefix(out, dedupSignatureUsage) ||
		!strings.Contains(out, "TARGET-AGNOSTIC") {
		t.Fatalf("help: %q", out)
	}
	vec := []struct {
		name string
		args []string
		want string
	}{
		{"no args", []string{"dedup-signature"},
			dedupSignatureUsage + "webv2 dedup-signature: error: the following " +
				"arguments are required: campaign, finding\n"},
		{"neither kind", []string{"dedup-signature", "C-aaaaaaaaaa", "F-1"},
			dedupSignatureUsage + "webv2 dedup-signature: error: one of " +
				"--root-cause or --economic is required\n"},
		{"both kinds", []string{"dedup-signature", "C-aaaaaaaaaa", "F-1",
			"--root-cause", "r", "--economic", "e"},
			dedupSignatureUsage + "webv2 dedup-signature: error: argument " +
				"--economic: not allowed with argument --root-cause\n"},
		{"cwe alone", []string{"dedup-signature", "C-aaaaaaaaaa", "F-1",
			"--economic", "e", "--cwe", "CWE-682"},
			dedupSignatureUsage + "webv2 dedup-signature: error: argument " +
				"--cwe: only meaningful with --root-cause\n"},
		{"missing value", []string{"dedup-signature", "C-aaaaaaaaaa", "F-1",
			"--root-cause"},
			dedupSignatureUsage + "webv2 dedup-signature: error: argument " +
				"--root-cause: expected one argument\n"},
		{"unknown", []string{"dedup-signature", "C-aaaaaaaaaa", "F-1",
			"--bogus"},
			t14TopUsage + "webv2: error: unrecognized arguments: --bogus\n"},
	}
	for _, v := range vec {
		code, out, errS := run(t, v.args...)
		if code != 2 || out != "" || errS != v.want {
			t.Errorf("%s: exit %d out %q err %q want %q",
				v.name, code, out, errS, v.want)
		}
	}
}

// TestDedupSignatureRootCauseComputesTheHash: the operator supplies a sentence,
// the tool stores the 16-hex — the hand-written-hash problem in reverse.
func TestDedupSignatureRootCauseComputesTheHash(t *testing.T) {
	c, root := t15Campaign(t, "dedup-sig")
	fid := dedupSigFinding(t, c, "unbacked withdrawal", "logic-error",
		"src/V.sol", "withdraw")
	const sentence = "attacker-controlled exchange rate creates unbacked " +
		"withdrawal value"
	code, out, errS := run(t, "--root", root, "dedup-signature", c.CampaignID,
		fid, "--root-cause", sentence, "--cwe", "CWE-682")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := findings.TextSignature(sentence)
	if out != fid+": root_cause_signature "+want+"\n  cwe CWE-682\n" {
		t.Fatalf("output\n%q\nwant the signature %s", out, want)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(f, "dedup"), "root_cause_signature"); got != want {
		t.Errorf("stored signature: %q", got)
	}
	if got := validation.ObjStr(validation.ObjAt(f, "dedup_meta"), "root_cause_sentence"); got != sentence {
		t.Errorf("stored sentence: %q", got)
	}
	if got := validation.ObjStr(validation.ObjAt(f, "root_cause"), "cwe"); got != "CWE-682" {
		t.Errorf("stored cwe: %q", got)
	}
	// Deterministic: the same sentence always hashes the same, a different one
	// does not.
	if findings.TextSignature(sentence) != want {
		t.Error("TextSignature is not deterministic")
	}
	if findings.TextSignature(sentence+"!") == want {
		t.Error("a different sentence produced the same signature")
	}
}

// TestDedupSignatureEconomic: the tier-3 sentence, and the event the sweep reads.
func TestDedupSignatureEconomic(t *testing.T) {
	c, root := t15Campaign(t, "dedup-sig-economic")
	fid := dedupSigFinding(t, c, "drain the pool", "logic-error", "src/V.sol", "f")
	const effect = "the attacker extracts the protocol's entire token balance"
	code, out, errS := run(t, "--root", root, "dedup-signature", c.CampaignID,
		fid, "--economic", effect)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := findings.TextSignature(effect)
	if out != fid+": economic_signature "+want+"\n" {
		t.Fatalf("output %q", out)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(f, "dedup"), "economic_signature"); got != want {
		t.Errorf("stored signature: %q", got)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := validation.ObjStr(events[len(events)-1], "type")
	if last != "dedup.economic_set" {
		t.Errorf("last event: %q", last)
	}
}

func TestDedupSignatureUnknownFinding(t *testing.T) {
	c, root := t15Campaign(t, "dedup-sig-missing")
	code, out, errS := run(t, "--root", root, "dedup-signature", c.CampaignID,
		"F-000000000000", "--root-cause", "x")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if !strings.Contains(errS, "no finding") {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestTier2FlagsCodeProtectedPairs is the D4 reachability fix: two findings
// with one root cause at different sites are protected from auto-merge, and
// before this they were flagged by nothing — so resolve-candidate could not see
// them. After the sweep each names the other, and the verdict lands.
func TestTier2FlagsCodeProtectedPairs(t *testing.T) {
	c, root := t15Campaign(t, "dedup-tier2-flag")
	a := dedupSigFinding(t, c, "withdraw path", "logic-error", "src/V.sol", "withdraw")
	b := dedupSigFinding(t, c, "deposit path", "logic-error", "src/W.sol", "deposit")
	const sentence = "attacker-controlled exchange rate creates unbacked " +
		"withdrawal value"
	for _, fid := range []string{a, b} {
		code, _, errS := run(t, "--root", root, "dedup-signature",
			c.CampaignID, fid, "--root-cause", sentence)
		if code != 0 {
			t.Fatalf("set signature for %s: exit %d %q", fid, code, errS)
		}
	}
	code, out, errS := run(t, "--root", root, "dedup", c.CampaignID)
	if code != 0 {
		t.Fatalf("dedup exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "\"tier2_clusters\"") {
		t.Fatalf("no tier-2 cluster in %s", out)
	}
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		f, err := findings.LoadFinding(c, pair[0])
		if err != nil {
			t.Fatal(err)
		}
		ids := validation.ObjAt(validation.ObjAt(f, "dedup"), "possible_duplicate_of")
		found := false
		for _, id := range ids.A {
			if id.Kind == validation.Str && id.S == pair[1] {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not name %s (flag missing): %s", pair[0], pair[1],
				validation.DumpIndented(ids))
		}
	}
	// The flag is not a merge: both findings are still live.
	for _, fid := range []string{a, b} {
		f, err := findings.LoadFinding(c, fid)
		if err != nil {
			t.Fatal(err)
		}
		if got := validation.ObjStr(f, "status"); got == "DUPLICATE" {
			t.Errorf("%s was merged, not flagged", fid)
		}
	}
	// And the pair is now adjudicable — the point of the flag.
	code, out, errS = run(t, "--root", root, "resolve-candidate", c.CampaignID,
		a, b, "--verdict", "distinct", "--note", "one cause, two hardened sites")
	if code != 0 {
		t.Fatalf("resolve-candidate exit %d out %q err %q", code, out, errS)
	}
}

// TestTier2KeepsAutoMergingSameSpotPairs: the guard on the flagging pass — a
// same-root-cause pair at the SAME site must still merge, not merely flag.
func TestTier2KeepsAutoMergingSameSpotPairs(t *testing.T) {
	c, root := t15Campaign(t, "dedup-tier2-samespot")
	a := dedupSigFinding(t, c, "first at the site", "logic-error", "src/V.sol", "f")
	b := dedupSigFinding(t, c, "second at the site", "logic-error", "src/V.sol", "f")
	const sentence = "attacker-controlled exchange rate creates unbacked " +
		"withdrawal value"
	for _, fid := range []string{a, b} {
		if code, _, errS := run(t, "--root", root, "dedup-signature",
			c.CampaignID, fid, "--root-cause", sentence); code != 0 {
			t.Fatalf("set signature: exit %d %q", code, errS)
		}
	}
	if code, _, errS := run(t, "--root", root, "dedup", c.CampaignID); code != 0 {
		t.Fatalf("dedup exit %d %q", code, errS)
	}
	// The older finding is kept; the younger is DUPLICATE of it.
	keep, err := findings.LoadFinding(c, a)
	if err != nil {
		t.Fatal(err)
	}
	dup, err := findings.LoadFinding(c, b)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(keep, "status"); got == "DUPLICATE" {
		t.Errorf("the first finding was merged away: %q", got)
	}
	if got := validation.ObjStr(dup, "status"); got != "DUPLICATE" {
		t.Errorf("same-spot pair did not auto-merge: status %q", got)
	}
	if got := validation.ObjStr(validation.ObjAt(dup, "dedup"), "duplicate_of"); got != a {
		t.Errorf("duplicate_of: %q want %q", got, a)
	}
}
