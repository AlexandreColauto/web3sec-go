package cli

// zz_r29b_bind_audit_test.go — r29b F1/F2/F5 end to end, bind vs audit.
//
// F1: a FORGED KIND must not switch the evidence rail off. The repro binds a
// real minicertora run, then edits verification.harness.kind to "mythril" (or
// "MINICERTORA") AND the last harness_run event's data.kind to the same
// string: the chain stays valid, harnessRunLine renders a line for any
// non-empty kind, and the old audit skipped the whole re-derivation for any
// kind outside {halmos, forge-fuzz, minicertora} — fourteen sections ok over
// a line whose own bytes said loop_bound 4. Now the kind must be one the
// bind can write, or the rung burns by name.
//
// F2: bind and audit must read the SAME stdout BYTES. The fixture below is a
// 1,048,638-byte capture (the repro's number) whose attributed PROVEN line
// ends before byte 1,048,576 and whose DUPLICATE attributed line sits after
// it: the bind maps the capped prefix (proved-bounded k=4) while the old
// audit's bare os.ReadFile read the whole file and burned that fresh bind
// with "inconclusive (duplicate verdict lines for rule)". The AUDIT side
// changed: it now reads through harness.ReadExecStdout, the bind's own
// reader, so the pin below is AGREEMENT (both proved-bounded k=4, green).
//
// F5: a workdir file named notes-harness.txt is not harness-file evidence —
// the bind records it as an ordinary input hash and maps normally, while a
// GENUINE scaffold file with a foreign sha still refuses.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// zzR29bBind runs the bind and returns its exact stdout.
func zzR29bBind(t *testing.T, root, cid, exec string) string {
	t.Helper()
	code, out, errS := run(t, "--root", root, "verify", cid,
		"--harness-result", "INV-1", "--exec", exec)
	if code != 0 {
		t.Fatalf("bind exit %d: out=%q err=%q", code, out, errS)
	}
	return out
}

// zzR29bAudit runs `audit --json` and returns (exit code, section ok, joined
// problems, harness_runs).
func zzR29bAudit(t *testing.T, root, cid string) (int, bool, string,
	validation.Value) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if out == "" {
		t.Fatalf("audit printed no report (exit %d, stderr %q)", code, errS)
	}
	rep, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("audit --json did not parse: %v\n%s", err, out)
	}
	sect := validation.ObjAt(validation.ObjAt(rep, "sections"), "invariant_verification")
	ok := validation.ObjAt(sect, "ok")
	joined := ""
	for _, p := range validation.ObjAt(sect, "problems").A {
		joined += p.S
	}
	return code, ok.Kind == validation.Bool && ok.B, joined,
		validation.ObjAt(sect, "harness_runs")
}

// zzR29bHarness is verification.harness for INV-1 read back from the links
// FILE — the state the audit reads.
func zzR29bHarness(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjAt(validation.ObjAt(validation.ObjAt(validation.ObjAt(links, "invariants"), "INV-1"),
		"verification"), "harness")
}

// zzR29bForgeKind rewrites the stored kind to a string no mapper implements
// (or to a spelling the bind never writes) AND lands the matching forged
// harness_run event through the campaign's own Log — so the chain stays
// valid and the slot/event backstop (harnessRungBacked) is satisfied on
// purpose: the ONLY thing wrong with the pair is the kind. Everything else
// (rung, exec, summary, bounded_k, proof digest) is copied from the honest
// bind, so a burn can only come from the kind.
func zzR29bSetSlotKind(t *testing.T, c *state.Campaign,
	kind string) validation.Value {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := validation.ObjAt(links, "invariants")
	entry := validation.ObjAt(reg, "INV-1")
	if entry.Kind != validation.Obj {
		t.Fatal("no INV-1 entry")
	}
	h := validation.ObjAt(validation.ObjAt(entry, "verification"), "harness")
	if h.Kind != validation.Obj {
		t.Fatal("no verification.harness to forge")
	}
	forged := h
	forged.O = validation.SetOrAppend(forged.O, "kind", validation.VStr(kind))
	entry.O = validation.SetOrAppend(entry.O, "verification",
		validation.VObj(validation.KV{K: "harness", V: forged}))
	reg.O = validation.SetOrAppend(reg.O, "INV-1", entry)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	return forged
}

// zzR29bForgeKind rewrites the slot kind AND lands the matching event built
// from the slot, for the exec-bound shape.
func zzR29bForgeKind(t *testing.T, c *state.Campaign, kind string) {
	t.Helper()
	forged := zzR29bSetSlotKind(t, c, kind)
	data := validation.VObj(
		kvT("kind", validation.VStr(kind)),
		kvT("rung", validation.VStr(validation.ObjStr(forged, "rung"))),
		kvT("exec", validation.VStr(validation.ObjStr(forged, "exec"))),
		kvT("invariant", validation.VStr("INV-1")),
		kvT("summary", validation.VStr(validation.ObjStr(forged, "summary"))),
		kvT("bounded_k", validation.ObjAt(forged, "bounded_k")),
		kvT("proof_sha256", validation.VStr(
			harnessProofDigest(validation.ObjAt(forged, "proof")))),
	)
	ref := "INV-1"
	if _, err := c.Log("harness_run", &ref, &data); err != nil {
		t.Fatal(err)
	}
}

// zzR29bForgeEventFromLast copies the LAST harness_run event for INV-1 and
// lands it again with the kind rewritten (and, when reportSHA is non-nil,
// report_sha256 rewritten too) — every provenance field the bind wrote is
// preserved, so a report-bound rung stays re-derivable and only the kind (or
// the digest) under test moves.
func zzR29bForgeEventFromLast(t *testing.T, c *state.Campaign, kind string,
	reportSHA *string) {
	t.Helper()
	zzR29bSetSlotKind(t, c, kind)
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := validation.VNull()
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_run" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(ev, "data"), "invariant") == "INV-1" {
			last = validation.ObjAt(ev, "data")
		}
	}
	if last.Kind != validation.Obj {
		t.Fatal("no harness_run event for INV-1 to copy")
	}
	forged := last
	forged.O = validation.SetOrAppend(forged.O, "kind", validation.VStr(kind))
	if reportSHA != nil {
		forged.O = validation.SetOrAppend(forged.O, "report_sha256",
			validation.VStr(*reportSHA))
	}
	ref := "INV-1"
	if _, err := c.Log("harness_run", &ref, &forged); err != nil {
		t.Fatal(err)
	}
}

// TestZZR29BForgedKindBurnsAndNamesTheKind is F1's repro: a real bind, then
// the kind (slot + last event) is rewritten to a string no mapper implements
// ("mythril") or to a spelling the bind never writes ("MINICERTORA"), with
// k inflated to 999999. The audit must burn and name the kind; before the
// fix it audited green and printed the inflated k.
func TestZZR29BForgedKindBurnsAndNamesTheKind(t *testing.T) {
	cases := []struct {
		kind     string
		wantText string
	}{
		{"mythril", "names no mapper this audit can re-derive"},
		{"MINICERTORA", "is not the canonical spelling"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			c, root := mcCamp(t, "r29b-forged-kind-"+strings.ToLower(tc.kind))
			execID := "EXEC-1"
			mcHarnessExec(t, c, execID, mcProvenLine,
				"minicertora --rule inv_1 --loop-bound 4",
				map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)},
				0)
			if out := zzR29bBind(t, root, c.CampaignID, execID); out !=
				"INV-1: proved-bounded (minicertora, k=4, "+execID+")\n" {
				t.Fatalf("bind stdout = %q", out)
			}
			// The legitimate bind is the control: green, pinned line.
			if code, ok, joined, runs := zzR29bAudit(t, root,
				c.CampaignID); code != 0 || !ok {
				t.Fatalf("a legitimate bind must audit green: exit %d "+
					"ok=%v problems=%q runs=%s", code, ok, joined,
					validation.CanonCompact(runs))
			} else if runs.Kind != validation.Arr || len(runs.A) != 1 ||
				runs.A[0].S != "INV-1: PROVEN-BOUNDED (minicertora, k=4, "+
					execID+")" {
				t.Fatalf("honest line = %s", validation.CanonCompact(runs))
			}
			// The forgery: kind in the slot AND in the last event, plus the
			// inflated bound the repro used.
			zzR29bSetBoundedK(t, c, 999999)
			zzR29bForgeKind(t, c, tc.kind)

			code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
			if code == 0 || ok {
				t.Fatalf("a forged kind must burn: exit %d ok=%v "+
					"problems=%q runs=%s", code, ok, joined,
					validation.CanonCompact(runs))
			}
			if !strings.Contains(joined, tc.wantText) {
				t.Fatalf("the burn must name the kind as the reason "+
					"(%q), got %q", tc.wantText, joined)
			}
			if !strings.Contains(joined, tc.kind) {
				t.Fatalf("the burn must name the kind %q, got %q",
					tc.kind, joined)
			}
			if runs.Kind != validation.Arr || len(runs.A) != 1 ||
				!strings.Contains(runs.A[0].S, tc.kind) ||
				!strings.HasSuffix(runs.A[0].S, " (UNBACKED)") {
				t.Fatalf("the burned line must be qualified: %s",
					validation.CanonCompact(runs))
			}
		})
	}
}

// zzR29bSetBoundedK rewrites the slot's bounded_k (the repro inflated it to
// 999999 alongside the kind).
func zzR29bSetBoundedK(t *testing.T, c *state.Campaign, k int64) {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := validation.ObjAt(links, "invariants")
	entry := validation.ObjAt(reg, "INV-1")
	ver := validation.ObjAt(entry, "verification")
	h := validation.ObjAt(ver, "harness")
	h.O = validation.SetOrAppend(h.O, "bounded_k", validation.VInt(k))
	ver.O = validation.SetOrAppend(ver.O, "harness", h)
	entry.O = validation.SetOrAppend(entry.O, "verification", ver)
	reg.O = validation.SetOrAppend(reg.O, "INV-1", entry)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
}

// TestZZR29BKindIsCanonicalAtTheSource is F1(c): the bind's own kind
// resolution is the one place a kind enters the ledger, and it accepts only
// the canonical vocabulary — so a ledger holding "mythril" can only be a
// forgery, and argparse refuses the flag before the resolver is reached.
func TestZZR29BKindIsCanonicalAtTheSource(t *testing.T) {
	c, root := mcCamp(t, "r29b-kind-source")
	// Unknown kinds (and the report-bound kind, which has no scaffold) are
	// refused outright: nothing is written to the ledger.
	for _, bad := range []string{"mythril", "MYTHRIL", "miniprover",
		"mini certora", ""} {
		if bad == "" {
			continue // "" is the "no --kind" arm: resolved from events
		}
		if k, err := harnessKindFor(c, "INV-1", bad); err == nil || k != "" {
			t.Fatalf("harnessKindFor(%q) = (%q, %v), want a refusal "+
				"(the bind writes only the canonical three)", bad, k, err)
		}
	}
	// A mis-cased spelling of a real kind CANONICALIZES — the ledger can
	// only ever hold the spelling the mappers know, so the audit never has
	// to burn a bind's own rung. (The CLI refuses it earlier still: argparse
	// restricts --kind to the canonical vocabulary.)
	for _, tc := range []struct{ in, want string }{
		{"halmos", "halmos"}, {"forge-fuzz", "forge-fuzz"},
		{"minicertora", "minicertora"}, {"MINICERTORA", "minicertora"},
		{"Halmos", "halmos"}, {" Forge-Fuzz ", "forge-fuzz"},
	} {
		k, err := harnessKindFor(c, "INV-1", tc.in)
		if err != nil || string(k) != tc.want {
			t.Fatalf("harnessKindFor(%q) = (%q, %v), want %q", tc.in, k,
				err, tc.want)
		}
	}
	// And the CLI's own door: argparse refuses the flag (exit 2) with the
	// pinned choice message, so nothing is stored and nothing is printed.
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", "EXEC-1", "--kind", "MYTHRIL")
	if code != 2 || !strings.Contains(errS, "invalid choice") {
		t.Fatalf("--kind MYTHRIL must be refused at parse: exit %d "+
			"out=%q err=%q", code, out, errS)
	}
}

// zzR29bOverCapStdout builds the F2 capture: the honest PROVEN line, then
// padding JSONL lines (rule "other", so the mapper skips them) filling the
// stream to EXACTLY harness.StdoutCap, then the SAME PROVEN line again —
// the duplicate that sits past the cap.
func zzR29bOverCapStdout(t *testing.T) string {
	t.Helper()
	head := mcProvenLine
	space := harness.StdoutCap - len(head)
	if space <= 0 {
		t.Fatalf("the PROVEN line already exceeds the cap (%d)", len(head))
	}
	padLine := func(n int) string {
		const pre = `{"rule":"other","note":"`
		const post = `"}` + "\n"
		if n < len(pre)+len(post) {
			t.Fatalf("pad line %d is shorter than its JSON frame", n)
		}
		return pre + strings.Repeat("p", n-len(pre)-len(post)) + post
	}
	const pad = 64
	var b strings.Builder
	b.WriteString(head)
	for i := 0; i < space/pad; i++ {
		b.WriteString(padLine(pad))
	}
	if rem := space % pad; rem > 0 {
		if rem >= 27 {
			b.WriteString(padLine(rem))
		} else {
			// Steal one pad line back so the final line can carry its frame.
			s := b.String()
			b.Reset()
			b.WriteString(s[:len(s)-pad])
			b.WriteString(padLine(pad + rem))
		}
	}
	if b.Len() != harness.StdoutCap {
		t.Fatalf("padding must land exactly on the cap: %d != %d", b.Len(),
			harness.StdoutCap)
	}
	b.WriteString(mcProvenLine) // the duplicate, past the cap
	return b.String()
}

// TestZZR29BCappedStdoutBindAndAuditAgree is F2's pin. The audit side is
// the one that changed: it used to read the whole capture with os.ReadFile
// and re-derive "inconclusive (duplicate verdict lines for rule)" over a run
// the bind had mapped as proved-bounded k=4 (and then burn that fresh bind).
// Both halves now go through harness.ReadExecStdout, so they agree — and the
// test proves the disagreement was real by re-mapping the BYTES PAST THE CAP
// through the same public mapper the audit uses: that mapping is the old
// audit's verdict.
func TestZZR29BCappedStdoutBindAndAuditAgree(t *testing.T) {
	c, root := mcCamp(t, "r29b-cap-duplicate")
	stdout := zzR29bOverCapStdout(t)
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile:    "docker-networkless",
		Command:    "minicertora --rule inv_1 --loop-bound 4",
		ReportedBy: "operator",
		ExitStatus: 0,
		StdoutText: stdout,
	})
	if err != nil {
		t.Fatal(err)
	}
	exec := validation.ObjStr(rec, "exec_id")
	raw, err := os.ReadFile(filepath.Join(c.ExecsDir, exec, "stdout.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= harness.StdoutCap {
		t.Fatalf("the fixture must exceed the cap: %d", len(raw))
	}
	// The bind maps the capped prefix: one attributed line, PROVEN k=4.
	want := "INV-1: proved-bounded (minicertora, k=4, " + exec + ")\n"
	if out := zzR29bBind(t, root, c.CampaignID, exec); out != want {
		t.Fatalf("bind stdout = %q, want %q", out, want)
	}
	// What the OLD audit read and mapped: the whole file, duplicate line
	// included. This is the burn it used to raise against the fresh bind.
	rung, summary, _, _ := harness.MapMinicertora(raw, 0,
		harness.MspecRuleName("INV-1"))
	if rung != harness.RungInconclusive ||
		!strings.Contains(summary, "duplicate verdict lines") {
		t.Fatalf("the uncapped bytes must be the disagreement the fix "+
			"removed: rung=%q summary=%q", rung, summary)
	}
	// The audit now sees the bind's bytes: agreement, no burn.
	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	if code != 0 || !ok {
		t.Fatalf("bind and audit must agree over the capped bytes: "+
			"exit %d ok=%v problems=%q", code, ok, joined)
	}
	wantLine := "INV-1: PROVEN-BOUNDED (minicertora, k=4, " + exec + ")"
	if runs.Kind != validation.Arr || len(runs.A) != 1 ||
		runs.A[0].S != wantLine {
		t.Fatalf("harness_runs = %s, want [%q]",
			validation.CanonCompact(runs), wantLine)
	}
}

// TestZZR29BHarnessNamedWorkdirFileMapsNormally is F5's repro: a run whose
// workdir holds notes-harness.txt records that file as an ordinary input
// hash. The bind must map the run normally (before the fix it refused with
// "scaffold-bound violation: harness file hash differs from stored
// scaffold" — a comparison nothing in the record made), and the audit must
// agree. The counter-half is pinned too: a GENUINE scaffold file with a
// foreign sha still refuses.
func TestZZR29BHarnessNamedWorkdirFileMapsNormally(t *testing.T) {
	c, root := mcCamp(t, "r29b-workdir-harness-name")
	wd := t.TempDir()
	if err := os.WriteFile(filepath.Join(wd, "notes-harness.txt"),
		[]byte("operator notes, not a scaffold\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile:    "docker-networkless",
		Command:    "minicertora --rule inv_1 --loop-bound 4",
		ReportedBy: "operator",
		ExitStatus: 0,
		Workdir:    &wd,
		StdoutText: mcProvenLine,
	})
	if err != nil {
		t.Fatal(err)
	}
	exec := validation.ObjStr(rec, "exec_id")
	// The record the sandbox really wrote: the file rides under its own name.
	ih := validation.ObjAt(rec, "input_hashes")
	if validation.ObjStr(ih, "notes-harness.txt") == "" {
		t.Fatalf("fixture: input_hashes = %s",
			validation.CanonCompact(ih))
	}
	out := zzR29bBind(t, root, c.CampaignID, exec)
	if out != "INV-1: proved-bounded (minicertora, k=4, "+exec+")\n" {
		t.Fatalf("a foreign 'harness'-named input file must map normally, "+
			"got %q", out)
	}
	if got := validation.ObjStr(zzR29bHarness(t, c), "summary"); got !=
		"proved bounded (k=4) (unbound: harness file hash not recorded)" {
		t.Fatalf("summary = %q (no scaffold file was hashed, so the run "+
			"is unbound)", got)
	}
	if code, ok, joined, _ := zzR29bAudit(t, root, c.CampaignID); code != 0 ||
		!ok {
		t.Fatalf("the audit must agree: exit %d ok=%v problems=%q", code,
			ok, joined)
	}

	// The counter-half: the SAME name shape, but a genuine scaffold file
	// (INV.mspec) whose sha differs from the stored one still refuses.
	const foreignID = "EXEC-foreign-scaffold"
	mcHarnessExec(t, c, foreignID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": strings.Repeat("0", 64)},
		0)
	if got := zzR29bBind(t, root, c.CampaignID, foreignID); got !=
		"INV-1: inconclusive (minicertora, "+foreignID+")\n" {
		t.Fatalf("a genuine scaffold file with a foreign sha must refuse, "+
			"got %q", got)
	}
	if got := validation.ObjStr(zzR29bHarness(t, c), "summary"); got !=
		"scaffold-bound violation: harness file hash differs from stored scaffold" {
		t.Fatalf("refusal summary = %q", got)
	}
}

// zzR29bReport writes a minimal-but-contractual reports/report.json (the
// shape cmd_verify_autoprove_test.go's apReport documents: schema 1.0,
// published, no publish_problems, a bound flag set and one property whose
// rollup is PROVEN over the scaffold-pinned rule).
func zzR29bReport(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "report.json")
	body := `{"schema_version": "1.0", "published": true, ` +
		`"publish_problems": [], "review_independent": true, ` +
		`"capabilities_missing": [], ` +
		`"flags": {"loop_bound": 4, "path_cap": 64, "timeout_ms": 30000}, ` +
		`"property_outcomes": {"total_never_wraps": {"outcome": "PROVEN", ` +
		`"per_rule": {"inv_1": "PROVEN", "inv_1_via_getter": "PROVEN"}}}, ` +
		`"review_findings": []}` + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestZZR29BReportBoundKindStillReDerives covers F1(a)'s FOURTH reachable
// blessing kind: cli.verifyAutoprove writes harness.Kind("miniprover") on
// both the slot and the event, and its rung is MapReport's — re-derived from
// the registered report bytes, not from any exec stdout. The kind dispatch
// must route BOTH provenance shapes there (REPORT-<digest12>, and the
// EXEC-wrapped form autoprove writes when it was handed a ledger id), and a
// forged scaffold kind over report provenance must burn by name instead of
// riding the report re-derivation to a green audit.
func TestZZR29BReportBoundKindStillReDerives(t *testing.T) {
	c, root := mcCamp(t, "r29b-report-bound")
	rep := zzR29bReport(t, t.TempDir())
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--autoprove", "INV-1", "--property", "total_never_wraps",
		"--report", rep)
	if code != 0 {
		t.Fatalf("autoprove exit %d: out=%q err=%q", code, out, errS)
	}
	h := zzR29bHarness(t, c)
	if validation.ObjStr(h, "kind") != "miniprover" {
		t.Fatalf("fixture kind = %s", validation.CanonCompact(h))
	}
	if !strings.HasPrefix(validation.ObjStr(h, "exec"), "REPORT-") {
		t.Fatalf("fixture exec = %s", validation.CanonCompact(h))
	}
	if code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID); code != 0 ||
		!ok {
		t.Fatalf("a report-bound rung must still be re-derived and stay "+
			"green: exit %d ok=%v problems=%q runs=%s", code, ok, joined,
			validation.CanonCompact(runs))
	}
	// The report arm must RUN whatever canonical kind the slot carries (the
	// kind is not what selects MapReport there). Two forgings prove it: a
	// kind no mapper implements burns by name, and a canonical kind whose
	// event pins a digest the store does not hold burns on the report bytes
	// — a skipped arm would have returned clean on both.
	zzR29bForgeEventFromLast(t, c, "mythril", nil)
	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	if code == 0 || ok {
		t.Fatalf("a forged kind over report provenance must burn: "+
			"exit %d ok=%v problems=%q runs=%s", code, ok, joined,
			validation.CanonCompact(runs))
	}
	if !strings.Contains(joined, "mythril") {
		t.Fatalf("the burn must name the kind, got %q", joined)
	}
	missing := strings.Repeat("0", 64)
	zzR29bForgeEventFromLast(t, c, "halmos", &missing)
	code, ok, joined, runs = zzR29bAudit(t, root, c.CampaignID)
	if code == 0 || ok {
		t.Fatalf("the report arm must re-derive under any canonical "+
			"kind: exit %d ok=%v problems=%q runs=%s", code, ok, joined,
			validation.CanonCompact(runs))
	}
	if !strings.Contains(joined, "no registry artifact holds the report") {
		t.Fatalf("the report arm must be the one that burned, got %q",
			joined)
	}
}

// TestZZR29BExecWrappedReportKindIsReDerived drives the same kind through
// the OTHER provenance shape the bind can write: autoprove handed a real
// ledger EXEC id (autoproveEventData carries whatever --exec it was given).
// The old dispatch keyed on the exec prefix FIRST and then skipped any kind
// outside {halmos, forge-fuzz, minicertora}, so this legitimate blessing was
// never re-derived at all; the kind-first dispatch routes it to MapReport.
func TestZZR29BExecWrappedReportKindIsReDerived(t *testing.T) {
	c, root := mcCamp(t, "r29b-report-exec")
	provenance, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile:    "docker-networkless",
		Command:    "miniprover run --loop-bound 4",
		ReportedBy: "operator",
		ExitStatus: 0,
		StdoutText: "report-only wrapper\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	exec := validation.ObjStr(provenance, "exec_id")
	rep := zzR29bReport(t, t.TempDir())
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--autoprove", "INV-1", "--property", "total_never_wraps",
		"--report", rep, "--exec", exec)
	if code != 0 {
		t.Fatalf("autoprove --exec exit %d: out=%q err=%q", code, out, errS)
	}
	h := zzR29bHarness(t, c)
	if validation.ObjStr(h, "kind") != "miniprover" || validation.ObjStr(h, "exec") != exec {
		t.Fatalf("fixture = %s", validation.CanonCompact(h))
	}
	if code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID); code != 0 ||
		!ok {
		t.Fatalf("an EXEC-wrapped report-bound rung must be re-derived "+
			"from its report bytes and stay green: exit %d ok=%v "+
			"problems=%q runs=%s", code, ok, joined,
			validation.CanonCompact(runs))
	}
}
