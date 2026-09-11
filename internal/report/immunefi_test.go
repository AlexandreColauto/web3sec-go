// immunefi_test.go — Task 25 (G18): report --format immunefi. The export
// shape is pinned here: six sections in fixed order on a fixture campaign,
// the empty-section checklist, multi-finding ordering, and the proof that
// the default md path is undisturbed (Generate untouched: the md render
// carries no immunefi bytes and the export never rewrites report.md).
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/bounty"
	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// immPolicy is the bounty testPolicy in literal order (program, scope,
// severity_rules, poc_requirements) — the mapping the Severity section
// renders against.
func immPolicy() validation.Value {
	return validation.VObj(
		kv("program", validation.VStr("Acme Protocol Immunefi")),
		kv("program_url", validation.VStr("https://immunefi.com/acme")),
		kv("platform", validation.VStr("immunefi")),
		kv("chains", validation.VArr(validation.VStr("ethereum"))),
		kv("asset_weight_usd", validation.VInt(50000000)),
		kv("scope", validation.VArr(
			validation.VObj(kv("target", validation.VStr("Vault")),
				kv("kind", validation.VStr("contract"))),
		)),
		kv("severity_rules", validation.VArr(
			validation.VObj(kv("severity", validation.VStr("critical")),
				kv("match", validation.VObj(
					kv("bug_classes", validation.VArr(validation.VStr("access-control"))),
					kv("require_invariant_violation", validation.VBool(true))))),
			validation.VObj(kv("severity", validation.VStr("high")),
				kv("match", validation.VObj(
					kv("bug_classes", validation.VArr(
						validation.VStr("economic-invariant"),
						validation.VStr("oracle-manipulation"))),
					kv("min_extractable_usd", validation.VInt(100000))))),
		)),
		kv("poc_requirements", validation.VObj(
			kv("min_evidence_level", validation.VStr("E5")),
			kv("require_fork_repro", validation.VBool(true)))),
	)
}

// immInstallSeams installs the bounty gate seams with make_submission_ready
// values: closed ladder, priced basis, proven fork PoC, immunized patch.
func immInstallSeams(t *testing.T, fid string) {
	t.Helper()
	ladder := validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("disposition", validation.VObj(
			kv("state", validation.VStr("complete")),
			kv("reason", validation.VNull()))),
		kv("maximal_rung_id", validation.VStr("R-abc123")),
		kv("axes_explored", validation.VArr()),
		kv("variants", validation.VArr()),
	)
	price := validation.VObj(
		kv("price_id", validation.VStr("PRC-abc123")),
		kv("asset", validation.VStr("ACME")),
		kv("usd", validation.VFloat(1.0)),
		kv("source", validation.VStr("fixture: fixed reference price")),
	)
	bounty.SetLoadLadder(func(*state.Campaign, string) (validation.Value, error) {
		return ladder, nil
	})
	bounty.SetPriceRow(func(*state.Campaign, string) (validation.Value, error) {
		return price, nil
	})
	bounty.SetForkPocStatus(func(*state.Campaign, string) (bool, string, error) {
		return true, "fork PoC proven: E5 fork-test (fork-runner, exit 0)", nil
	})
	bounty.SetWaivers(func(*state.Campaign, string) ([]validation.Value, error) {
		return []validation.Value{}, nil
	})
	bounty.SetImmunizationDetail(func(validation.Value) (string, string) {
		return "immunized", "patch blocks the fork PoC and all 3 boundary mutations"
	})
	bounty.SetContractPathResolver(func(*state.Campaign, string) string {
		return ""
	})
	t.Cleanup(func() {
		bounty.SetLoadLadder(nil)
		bounty.SetPriceRow(nil)
		bounty.SetForkPocStatus(nil)
		bounty.SetWaivers(nil)
		bounty.SetImmunizationDetail(nil)
		bounty.SetContractPathResolver(nil)
	})
}

// immCamp builds a campaign with a pinned target and the policy file on
// the state (the privDet pattern: state.InitOpts takes no policy path).
func immCamp(t *testing.T, withPolicy bool) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	t.Setenv("WEBV2_NOW", "2026-09-11T00:00:00.000000+00:00")
	t.Setenv("WEBV2_UUID", "imm-test")
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	c, err := state.Init(root, "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "t")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	if withPolicy {
		policyPath := filepath.Join(root, "policy.json")
		if err := validation.WriteJson(policyPath, immPolicy(), ""); err != nil {
			t.Fatal(err)
		}
		doc, err := validation.ReadJson(c.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		doc.O = validation.SetOrAppend(doc.O, "policy_path",
			validation.VStr(policyPath))
		if err := validation.WriteJson(c.StatePath, doc, "campaign_state"); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// immExploitArg is the check14 answer (>= 200 chars): who pays and why.
const immExploitArg = "Who pays: the protocol treasury and its depositors, who fund every " +
	"unbacked withdrawal the skewed price permits. Why the bug makes them pay: the spot " +
	"price read lets an arbitrary EOA trade against its own price impact, so each borrow " +
	"priced at the stale value extracts real backing while the accounting still claims " +
	"full collateralization after the dust settles on every single block."

// immConfirm ingests a full finding and drives it to CONFIRMED with local +
// fork PoCs, a priced economic impact, a prose fix, and G15 advisories on
// the fork evidence.
func immConfirm(t *testing.T, c *state.Campaign, title string) (string, string) {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("cwe", validation.VStr("CWE-682")),
			kv("description", validation.VStr(
				"spot price read lets attacker trade against own price")),
			kv("mechanism", validation.VStr(
				"the vault prices borrows from the unfenced spot reserve ratio")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("contract", validation.VStr("Vault")),
			kv("function", validation.VStr("borrow"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("economic_impact", validation.VObj(
			kv("blast_radius", validation.VStr("protocol-solvency")),
			kv("extractable_usd", validation.VInt(1500000)),
			kv("mechanism", validation.VStr("borrow against the stale spot price")),
			kv("price_basis", validation.VStr("PRC-abc123")))),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	local, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "imm-fixture", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatal(err)
	}
	fork, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile:    "fork-runner",
		Command:    "forge test --fork-url http://127.0.0.1:8545 --match-test test_exploit",
		FindingID:  &fid,
		ReportedBy: "imm-fixture", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+fid[:4]+"-local")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("local harness repro")),
		kv("sandbox_profile", objAt(local, "profile")),
		kv("artifact_id", objAt(local, "exec_id")))); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+fid[:4]+"-fork")),
		kv("level", validation.VStr("E5")),
		kv("type", validation.VStr("fork-test")),
		kv("description", validation.VStr("fork repro extracts 1.5M")),
		kv("sandbox_profile", objAt(fork, "profile")),
		kv("artifact_id", objAt(fork, "exec_id")),
		kv("reruns", validation.VStr("3/3")),
		kv("fork_stale", validation.VStr("12 blocks old")))); err != nil {
		t.Fatal(err)
	}
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "status", validation.VStr("CONFIRMED"))
	ver := objAt(f, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("status", validation.VStr("reproduced")),
		kv("tier_reached", validation.VStr("T3")),
		kv("attempts", validation.VArr())))
	ver.O = validation.SetOrAppend(ver.O, "recommendation", validation.VStr(
		"price borrows from the time-weighted oracle and fence the first "+
			"block after a reserve move"))
	f.O = validation.SetOrAppend(f.O, "verification", ver)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetExploitability(c, fid, true, immExploitArg); err != nil {
		t.Fatal(err)
	}
	return fid, pyStr(objAt(fork, "exec_id"))
}

// immMarkReady hand-stamps the stored gate output (no policy: the export
// reads the flags as-is, no refresh to clobber them).
func immMarkReady(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "bounty", validation.VObj(
		kv("eligible", validation.VBool(true)),
		kv("submission_ready", validation.VBool(true)),
		kv("blocking_reasons", validation.VArr())))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
}

func immRead(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func immHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestImmunefiSectionsPresent pins the export shape: all six sections in
// fixed order, every content source rendered, no checklist on a complete
// finding.
func TestImmunefiSectionsPresent(t *testing.T) {
	c := immCamp(t, true)
	fid, forkExec := immConfirm(t, c, "Attacker withdraws unbacked funds via price skew")
	immInstallSeams(t, fid)
	paths, err := GenerateImmunefi(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("paths = %v, want 1 file", paths)
	}
	want := filepath.Join(c.Dir, "report-immunefi-"+fid+".md")
	if paths[0] != want {
		t.Errorf("path = %q, want %q", paths[0], want)
	}
	text := immRead(t, want)
	headers := []string{"## Summary", "## Impact", "## Severity", "## PoC",
		"## Recommendation", "## Related areas"}
	last := -1
	for _, h := range headers {
		i := strings.Index(text, h)
		if i < 0 {
			t.Fatalf("missing section %q in:\n%s", h, text)
		}
		if i < last {
			t.Fatalf("section %q out of order in:\n%s", h, text)
		}
		last = i
	}
	for _, wantLine := range []string{
		"- title: Attacker withdraws unbacked funds via price skew",
		"- program: Acme Program",
		"submission_ready=True",
		"- exploit mechanism: the vault prices borrows from the unfenced spot reserve ratio",
		"- extractable: $1,500,000",
		"- program severity: **high**",
		"[OWASP SC02]",
		"fork-test",
		forkExec,
		"[reruns 3/3]",
		"[fork stale]",
		"- fix: price borrows from the time-weighted oracle",
		"contract `Vault`",
	} {
		if !strings.Contains(text, wantLine) {
			t.Errorf("missing %q in:\n%s", wantLine, text)
		}
	}
	if strings.Contains(text, "MISSING") {
		t.Errorf("complete finding must not render a checklist:\n%s", text)
	}
	if strings.Contains(text, "pre-submit checklist") {
		t.Errorf("complete finding must not open with a checklist:\n%s", text)
	}
}

// TestImmunefiMissingChecklist pins the fail-open law: a sparse ready
// finding still generates, every empty section renders the literal line,
// and the file opens with the checklist block naming them.
func TestImmunefiMissingChecklist(t *testing.T) {
	c := immCamp(t, false)
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("Sparse finding")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("unclassified")),
			kv("description", validation.VStr(
				"sparse fixture with no exportable detail")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	immMarkReady(t, c, fid)
	paths, err := GenerateImmunefi(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("sparse ready finding must still generate: paths = %v", paths)
	}
	text := immRead(t, paths[0])
	if !strings.Contains(text, "pre-submit checklist") {
		t.Fatalf("missing checklist block in:\n%s", text)
	}
	// Impact has a root-cause description, Summary has title+program+gate,
	// Related areas has the affected path: Severity (no policy), PoC (no
	// evidence) and Recommendation (no prose) are the empty three.
	for _, section := range []string{"Severity", "PoC", "Recommendation"} {
		line := "- " + section + ": MISSING (fill before submitting)"
		if got := strings.Count(text, line); got < 2 {
			t.Errorf("%q appears %d times, want >= 2 (checklist + body):\n%s",
				line, got, text)
		}
	}
	for _, section := range []string{"Summary", "Impact", "Related areas"} {
		if strings.Contains(text, "- "+section+": MISSING") {
			t.Errorf("section %q must not be MISSING:\n%s", section, text)
		}
	}
	if !strings.Contains(text, "- related: `src/V.sol`") {
		t.Errorf("missing related-affected line in:\n%s", text)
	}
	// The checklist block opens the file: it precedes the first section.
	if strings.Index(text, "pre-submit checklist") >
		strings.Index(text, "## Summary") {
		t.Errorf("checklist block must precede the sections:\n%s", text)
	}
	// Recommendation's missing line carries the prose fallback.
	if !strings.Contains(text,
		"- Recommendation: MISSING (fill before submitting) — not drafted") {
		t.Errorf("missing not-drafted fallback in:\n%s", text)
	}
}

// TestImmunefiMultiFindingOrdering pins determinism: one file per ready
// finding, paths sorted by finding id.
func TestImmunefiMultiFindingOrdering(t *testing.T) {
	c := immCamp(t, false)
	fids := []string{}
	for _, title := range []string{"First sparse bug", "Second sparse bug"} {
		f, err := findings.IngestHypothesis(c, validation.VObj(
			kv("title", validation.VStr(title)),
			kv("root_cause", validation.VObj(
				kv("class", validation.VStr("unclassified")),
				kv("description", validation.VStr(
					"sparse fixture with no exportable detail")))),
			kv("affected", validation.VArr(validation.VObj(
				kv("path", validation.VStr("src/V.sol"))))),
			kv("attacker", validation.VObj(
				kv("profile", validation.VStr("arbitrary EOA")),
				kv("capabilities", validation.VArr()))),
		), "code", "", "")
		if err != nil {
			t.Fatal(err)
		}
		fid := objStr(f, "finding_id")
		immMarkReady(t, c, fid)
		fids = append(fids, fid)
	}
	// A third finding that is NOT ready must not gain a file.
	other, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("Third finding stays out")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("unclassified")),
			kv("description", validation.VStr(
				"sparse fixture with no exportable detail")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	otherID := objStr(other, "finding_id")
	paths, err := GenerateImmunefi(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("paths = %v, want 2 files", paths)
	}
	sorted := append([]string{}, fids...)
	sort.Strings(sorted)
	want := []string{
		filepath.Join(c.Dir, "report-immunefi-"+sorted[0]+".md"),
		filepath.Join(c.Dir, "report-immunefi-"+sorted[1]+".md"),
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("paths[%d] = %q, want %q (full: %v)", i, paths[i], want[i], paths)
		}
	}
	for _, p := range paths {
		if strings.Contains(p, otherID) {
			t.Errorf("non-ready finding gained a file: %v", paths)
		}
	}
}

// TestImmunefiAllEmptyRendersFullChecklist pins the Related-areas MISSING
// path (unreachable through schema-valid findings — affected carries
// minItems 1 — so it is exercised synthetically) and the all-empty file:
// all six sections listed in the opening checklist block.
func TestImmunefiAllEmptyRendersFullChecklist(t *testing.T) {
	f := validation.VObj(
		kv("finding_id", validation.VStr("F-synth")),
		kv("title", validation.VStr("")),
	)
	lines := renderImmunefiFinding(f, validation.VNull(), "")
	text := strings.Join(lines, "\n")
	if !strings.Contains(text, "> pre-submit checklist: 6 section(s) MISSING") {
		t.Errorf("want 6-section checklist in:\n%s", text)
	}
	for _, section := range immunefiSections {
		// Each literal appears twice: the opening checklist copy and the
		// in-body line (Recommendation's body line extends it with the
		// "— not drafted" suffix, so it still contains the literal).
		line := "- " + section + ": MISSING (fill before submitting)"
		if got := strings.Count(text, line); got < 2 {
			t.Errorf("%q appears %d times, want >= 2:\n%s", line, got, text)
		}
	}
	if !strings.Contains(text,
		"- Recommendation: MISSING (fill before submitting) — not drafted") {
		t.Errorf("missing not-drafted body line in:\n%s", text)
	}
}

// TestImmunefiLeavesDefaultAlone is the zero-diff companion: the export
// never rewrites report.md and the default render carries no immunefi
// bytes (Generate's function region is untouched by the flag add).
func TestImmunefiLeavesDefaultAlone(t *testing.T) {
	c := immCamp(t, false)
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("Sparse finding")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("unclassified")),
			kv("description", validation.VStr(
				"sparse fixture with no exportable detail")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	immMarkReady(t, c, objStr(f, "finding_id"))
	mdPath, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	before := immHash(immRead(t, mdPath))
	if strings.Contains(immRead(t, mdPath), "Immunefi submission") {
		t.Errorf("default report.md must not carry immunefi bytes")
	}
	if _, err := GenerateImmunefi(c); err != nil {
		t.Fatal(err)
	}
	if after := immHash(immRead(t, mdPath)); after != before {
		t.Errorf("GenerateImmunefi rewrote report.md (hash %s -> %s)", before, after)
	}
}
