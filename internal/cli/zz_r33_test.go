package cli

// zz_r33_test.go — round 33, end to end: every finding is "the bind decided
// it, the audit never re-derived it", so every test here is a BIND-VS-AUDIT
// pair over one campaign:
//
//	F1  one record, two readers. The bind reads the invocation bound with the
//	    record's KIND (harness.RecordInvocationBound(kind, rec)); all three
//	    section-11 sites read it KIND-FREE. `halmos --fuzz-runs 4000` bound as
//	    --kind forge-fuzz therefore bound honestly (k=4000) and audited as a
//	    foreign-flag floor: the audit burned a bind that re-binds
//	    byte-for-byte. The pin below is AGREEMENT, and the honest shapes
//	    (a matching command) stay in agreement too.
//	F2  one proof, two rows. A second invariant copying the proven (report
//	    pin, property) pair audits green with two blessing lines while the
//	    verb refuses the same bind with exit 2.
//	F3  the schema_version gate (the verb's own door) was never re-derived by
//	    harness.DecideReport, so a pinned report with "2.0" or no version at
//	    all was blessed.
//	F4  exec provenance: a label the exec ledger does not hold, and a
//	    REPORT-<digest12> label that does not name the pinned bytes.
//	F5  a report rung wearing an exec-shaped kind.
//
// The verb's own refusal bytes are pinned next to each audit burn, because
// the law is that both halves answer from the SAME inputs through the SAME
// code path — a fixed audit over an unchanged bind refusal (F3, F4(a)) would
// be the mirror-image lie.

import (
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// r33Body is reports/report.json keyed by one or more property titles, each
// PROVEN over the single rule inv_1. It is the shape zzR32bBody writes, with
// the property set a parameter so the fold-equal repro can key BOTH "p1" and
// "P1" in one report.
func r33Body(props ...string) string {
	var b strings.Builder
	b.WriteString(`{"schema_version": "1.0", "published": true, ` +
		`"publish_problems": [], "review_independent": true, ` +
		`"capabilities_missing": [], ` +
		`"flags": {"loop_bound": 4, "path_cap": 64, "timeout_ms": 30000}, ` +
		`"property_outcomes": {`)
	for i, p := range props {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(`"` + p + `": {"outcome": "PROVEN", ` +
			`"per_rule": {"inv_1": "PROVEN"}}`)
	}
	b.WriteString(`}, "review_findings": []}` + "\n")
	return b.String()
}

// r33LastEvent is the LAST harness_run event data for iid.
func r33LastEvent(t *testing.T, c *state.Campaign, iid string) validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := validation.VNull()
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		if objStr(objAt(ev, "data"), "invariant") == iid {
			last = objAt(ev, "data")
		}
	}
	if last.Kind != validation.Obj {
		t.Fatalf("no harness_run event for %s", iid)
	}
	return last
}

// r33Land lands one harness_run event through the campaign's own Log (the
// chain stays valid, so the ONLY thing wrong is the field under test).
func r33Land(t *testing.T, c *state.Campaign, iid string,
	data validation.Value) {
	t.Helper()
	ref := iid
	if _, err := c.Log("harness_run", &ref, &data); err != nil {
		t.Fatal(err)
	}
}

// r33Repin lands a copy of iid's last harness_run event with one key set.
func r33Repin(t *testing.T, c *state.Campaign, iid, key string,
	v validation.Value) {
	t.Helper()
	forged := r33LastEvent(t, c, iid)
	forged.O = validation.SetOrAppend(forged.O, key, v)
	r33Land(t, c, iid, forged)
}

// r33Slot is iid's stored verification.harness object.
func r33Slot(t *testing.T, c *state.Campaign, iid string) validation.Value {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	return objAt(objAt(objAt(objAt(links, "invariants"), iid),
		"verification"), "harness")
}

// r33SetSlot rewrites one string field of iid's stored verification.harness.
func r33SetSlot(t *testing.T, c *state.Campaign, iid, key, val string) {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	e := objAt(reg, iid)
	if e.Kind != validation.Obj {
		t.Fatalf("fixture: no %s in links", iid)
	}
	h := objAt(objAt(e, "verification"), "harness")
	if h.Kind != validation.Obj {
		t.Fatalf("fixture: no verification.harness on %s", iid)
	}
	h.O = validation.SetOrAppend(h.O, key, validation.VStr(val))
	e.O = validation.SetOrAppend(e.O, "verification",
		validation.VObj(validation.KV{K: "harness", V: h}))
	reg.O = validation.SetOrAppend(reg.O, iid, e)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
}

// r33CopyRow copies from's whole (slot, event) report rung onto to — F2's
// repro verbatim ("INV-2's slot and event copy INV-1's report pin and
// property"), written through the campaign's own writers so the chain and the
// slot/event backstop are valid and the ONLY thing wrong is the second claim.
func r33CopyRow(t *testing.T, c *state.Campaign, from, to string) {
	t.Helper()
	src := r33Slot(t, c, from)
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	e := objAt(reg, to)
	if e.Kind != validation.Obj {
		t.Fatalf("fixture: no %s in links", to)
	}
	e.O = validation.SetOrAppend(e.O, "verification",
		validation.VObj(validation.KV{K: "harness", V: src}))
	reg.O = validation.SetOrAppend(reg.O, to, e)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	ev := r33LastEvent(t, c, from)
	ev.O = validation.SetOrAppend(ev.O, "invariant", validation.VStr(to))
	r33Land(t, c, to, ev)
}

// r33AssertBurned is the shared burn assertion: the audit must exit non-zero
// with section 11 not-ok, the problems must name every fragment, and the
// burned row's rendered line must be qualified UNBACKED. unbackedIID names
// the row whose blessing is gone; other rows (the first claimant of a
// collided property) legitimately keep theirs.
func r33AssertBurned(t *testing.T, code int, ok bool, joined string,
	runs validation.Value, unbackedIID string, frags ...string) {
	t.Helper()
	if code == 0 || ok {
		t.Fatalf("section 11 must burn: exit %d ok=%v problems=%q runs=%s",
			code, ok, joined, validation.CanonCompact(runs))
	}
	for _, frag := range frags {
		if !strings.Contains(joined, frag) {
			t.Fatalf("the burn must name %q, got %q", frag, joined)
		}
	}
	found := false
	for _, r := range runs.A {
		if r.Kind != validation.Str ||
			!strings.HasPrefix(r.S, unbackedIID+":") {
			continue
		}
		found = true
		if !strings.HasSuffix(r.S, " (UNBACKED)") {
			t.Fatalf("%s's burned rung must not print unqualified: %q",
				unbackedIID, r.S)
		}
	}
	if !found {
		t.Fatalf("%s must still render its (qualified) line: %s",
			unbackedIID, validation.CanonCompact(runs))
	}
}

// r33ReportCampaign is a minicertora-scaffolded campaign with INV-1 and INV-2
// seeded, INV-1 bound by a real `verify --autoprove` run, and the honest audit
// asserted green — the starting point every report-rung finding mutates.
func r33ReportCampaign(t *testing.T, program string) (*state.Campaign,
	string) {
	t.Helper()
	c, root := mcCamp(t, program)
	t15SeedInvariant(t, c, "INV-2", "withdrawals must never exceed deposits")
	zzR32bBindHonest(t, root, c, "p1", r33Body("p1"))
	zzR32bHonestControl(t, root, c)
	return c, root
}

// TestR33KindAwareBoundBindAndAuditAgree is F1's pin. The record's command is
// `halmos --fuzz-runs 4000` while the rung is bound as --kind forge-fuzz: a
// real command, a real bound flag, and a KIND the bind keeps and the audit
// used to throw away. forge owns --fuzz-runs, so the bind reads 4000 and maps
// proved-bounded; the kind-free reader derives the tool from argv[0]
// ("halmos"), calls the flag foreign and FLOORS, and DecideBound only lets a
// floor override the caller — so the floored k survived and the audit burned
// the very bind whose stdout re-binds byte-for-byte. The pin is AGREEMENT:
// the bind's own verdict, reproduced.
func TestR33KindAwareBoundBindAndAuditAgree(t *testing.T) {
	cases := []struct {
		name    string
		scaffol string
		command string
		stdout  string
		kind    string
		want    string
	}{
		{"forge kind over a halmos-named command", "forge-fuzz",
			"halmos --fuzz-runs 4000", r26ForgePass, "forge-fuzz",
			"INV-1: proved-bounded (forge-fuzz, k=4000, "},
		{"honest forge command", "forge-fuzz",
			"forge test --fuzz-runs 4000", r26ForgePass, "forge-fuzz",
			"INV-1: proved-bounded (forge-fuzz, k=4000, "},
		{"honest halmos command", "halmos",
			"halmos --root . --loop 100", harnessProvedStdout, "halmos",
			"INV-1: proved-bounded (halmos, k=100, "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, root := harnessCamp(t, tc.scaffol, "")
			const execID = "EXEC-r33-bound"
			harnessExec(t, c, execID, tc.stdout, tc.command, nil, 0)
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--harness-result", "INV-1", "--exec",
				execID, "--kind", tc.kind)
			if code != 0 {
				t.Fatalf("bind exit %d: out=%q err=%q", code, out, errS)
			}
			if want := tc.want + execID + ")\n"; out != want {
				t.Fatalf("bind stdout = %q, want %q", out, want)
			}
			code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
			if code != 0 || !ok {
				t.Fatalf("the audit must AGREE with the bind it can "+
					"re-bind: exit %d ok=%v problems=%q runs=%s", code,
					ok, joined, validation.CanonCompact(runs))
			}
			got := ""
			if runs.Kind == validation.Arr && len(runs.A) == 1 {
				got = runs.A[0].S
			}
			if strings.Contains(got, "UNBACKED") ||
				!strings.HasPrefix(got, "INV-1: PROVEN-BOUNDED ("+
					tc.kind+", k=") {
				t.Fatalf("audit line = %q", got)
			}
		})
	}
}

// TestR33DuplicateRowBurnsAndBindRefuses is F2's pin, both halves. The
// campaign is a real report bind for INV-1; INV-2's slot and its event then
// copy that proven pair verbatim. Before the fix section 11 rendered TWO
// unqualified blessing lines over ONE proof and exited 0, while re-binding
// those bytes for INV-2 exits 2 at the verb — the sentence the audit now
// re-derives.
func TestR33DuplicateRowBurnsAndBindRefuses(t *testing.T) {
	c, root := r33ReportCampaign(t, "r33-f2-duplicate")
	r33CopyRow(t, c, "INV-1", "INV-2")

	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	r33AssertBurned(t, code, ok, joined, runs, "INV-2",
		"already bound to INV-1", "one property's proof binds one invariant")
	// The FIRST claimant keeps its rung: only the later row burns.
	for _, r := range runs.A {
		if r.Kind == validation.Str &&
			strings.HasPrefix(r.S, "INV-1: PROVEN-BOUNDED") &&
			strings.Contains(r.S, "UNBACKED") {
			t.Fatalf("the first claimant must keep its blessing: %q", r.S)
		}
	}

	// The bind's own answer for the same claim: exit 2, naming the holder.
	rep := zzR32bWrite(t, r33Body("p1"))
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--autoprove", "INV-2", "--property", "p1", "--report", rep)
	if code != 2 {
		t.Fatalf("the verb must refuse the duplicate attribution: exit %d "+
			"out=%q err=%q", code, out, errS)
	}
	for _, frag := range []string{"property", "'p1'",
		"already bound to INV-1", "one property's proof binds one " +
			"invariant"} {
		if !strings.Contains(errS, frag) {
			t.Fatalf("the verb's refusal must name %q: %q", frag, errS)
		}
	}
}

// TestR33FoldEqualDuplicateBurns is F2's fold-equal variant: the report is
// keyed BOTH "p1" and "P1" (so the copied row's name resolves exactly and
// every other rail passes) while the two rows name different spellings. The
// bind's holder scan folds with harness.SamePropertyName, so the verb refuses
// this bind too; the audit must collide on the same folded pair.
func TestR33FoldEqualDuplicateBurns(t *testing.T) {
	c, root := mcCamp(t, "r33-f2-fold")
	t15SeedInvariant(t, c, "INV-2", "withdrawals must never exceed deposits")
	zzR32bBindHonest(t, root, c, "p1", r33Body("p1", "P1"))
	zzR32bHonestControl(t, root, c)

	r33CopyRow(t, c, "INV-1", "INV-2")
	r33Repin(t, c, "INV-2", "property", validation.VStr("P1"))

	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	r33AssertBurned(t, code, ok, joined, runs, "INV-2",
		"already bound to INV-1")

	rep := zzR32bWrite(t, r33Body("p1", "P1"))
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--autoprove", "INV-2", "--property", "P1", "--report", rep)
	if code != 2 {
		t.Fatalf("the verb must refuse the folded duplicate: exit %d "+
			"out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "already bound to INV-1") {
		t.Fatalf("the verb's refusal = %q", errS)
	}
}

// TestR33DuplicateControlsStayGreen is F2's honest-control half: two
// DIFFERENT properties from one report, and one invariant re-claiming its own
// property over a newer report (the refresh the verb discloses with a
// warning), both stay green and unqualified.
func TestR33DuplicateControlsStayGreen(t *testing.T) {
	t.Run("two properties from one report", func(t *testing.T) {
		c, root := mcCamp(t, "r33-f2-two-props")
		t15SeedInvariant(t, c, "INV-2",
			"withdrawals must never exceed deposits")
		rep := zzR32bWrite(t, r33Body("p1", "p2"))
		for iid, prop := range map[string]string{"INV-1": "p1",
			"INV-2": "p2"} {
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--autoprove", iid, "--property", prop,
				"--report", rep)
			if code != 0 {
				t.Fatalf("bind %s: exit %d out=%q err=%q", iid, code,
					out, errS)
			}
		}
		code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
		if code != 0 || !ok {
			t.Fatalf("two properties of one report must both bless: "+
				"exit %d ok=%v problems=%q runs=%s", code, ok, joined,
				validation.CanonCompact(runs))
		}
		if len(runs.A) != 2 {
			t.Fatalf("both rows must render: %s",
				validation.CanonCompact(runs))
		}
	})
	t.Run("one invariant re-claims its own property", func(t *testing.T) {
		c, root := mcCamp(t, "r33-f2-refresh")
		a := zzR32bWrite(t, r33Body("p1"))
		b := zzR32bWrite(t, strings.Replace(r33Body("p1"),
			`"path_cap": 64`, `"path_cap": 65`, 1))
		for i, rep := range []string{a, b} {
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--autoprove", "INV-1", "--property", "p1",
				"--report", rep)
			if code != 0 {
				t.Fatalf("bind %d: exit %d out=%q err=%q", i, code, out,
					errS)
			}
		}
		code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
		if code != 0 || !ok {
			t.Fatalf("a row re-binding its own property over a newer "+
				"report is a refresh, not a collision: exit %d ok=%v "+
				"problems=%q runs=%s", code, ok, joined,
				validation.CanonCompact(runs))
		}
	})
}

// TestR33CrossPinDuplicateBurns is the rail's KEY pin, and it is why the key
// is the folded property and not (pin, property): the bind's holder scan
// reads the property title ALONE, so the same property over a DIFFERENT
// report is still "already bound" at the verb — pinned here, both halves. An
// audit keyed on the pin would bless exactly the duplicate attribution the
// bind refuses (F2's forgery with one byte of the report changed).
//
// The campaign is built so that the SECOND report is genuinely in the store
// (a different property was bound from it), so the audit's registry re-read
// succeeds and the ONLY thing wrong with the forged row is the second claim
// of p1.
func TestR33CrossPinDuplicateBurns(t *testing.T) {
	c, root := mcCamp(t, "r33-f2-cross-pin")
	t15SeedInvariant(t, c, "INV-2", "withdrawals must never exceed deposits")
	a := zzR32bWrite(t, r33Body("p1"))
	// Report b differs from a (so its pin differs) and carries BOTH titles,
	// so an exact property lookup succeeds for either.
	b := zzR32bWrite(t, strings.Replace(r33Body("p1", "p2"),
		`"path_cap": 64`, `"path_cap": 65`, 1))
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--autoprove", "INV-1", "--property", "p1", "--report", a)
	if code != 0 {
		t.Fatalf("first bind: exit %d out=%q err=%q", code, out, errS)
	}
	// INV-2 legitimately binds p2 from report b: report b's bytes are in
	// the store, and INV-2's row is an honest one.
	code, out, errS = run(t, "--root", root, "verify", c.CampaignID,
		"--autoprove", "INV-2", "--property", "p2", "--report", b)
	if code != 0 {
		t.Fatalf("second bind: exit %d out=%q err=%q", code, out, errS)
	}
	shaB := objStr(r33LastEvent(t, c, "INV-2"), "report_sha256")
	if shaB == objStr(r33LastEvent(t, c, "INV-1"), "report_sha256") {
		t.Fatal("fixture drift: the two reports must have different pins")
	}
	// Half one: the verb refuses the cross-pin duplicate of p1 for INV-2.
	code, out, errS = run(t, "--root", root, "verify", c.CampaignID,
		"--autoprove", "INV-2", "--property", "p1", "--report", b)
	if code != 2 || !strings.Contains(errS, "was already bound to INV-1") {
		t.Fatalf("the verb must refuse a cross-pin duplicate: exit %d "+
			"out=%q err=%q", code, out, errS)
	}
	// Half two: the same claim, forged into the row the refused bind would
	// have overwritten — pin, label and property kept consistent.
	r33SetSlot(t, c, "INV-2", "exec", harness.ReportExecLabel(shaB))
	r33Repin(t, c, "INV-2", "exec",
		validation.VStr(harness.ReportExecLabel(shaB)))
	r33Repin(t, c, "INV-2", "property", validation.VStr("p1"))
	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	r33AssertBurned(t, code, ok, joined, runs, "INV-2",
		"already bound to INV-1")
}

// TestR33SchemaGateBytesAndAuditBurn is F3's pin, both halves: the verb's
// refusal bytes for a "2.0" report and for one with no usable schema_version
// (byte-pinned, because the schema gate moved out of this file and into the
// shared decision), and the audit burn over a pinned copy of those bytes —
// naming the schema state, not a downstream gate.
func TestR33SchemaGateBytesAndAuditBurn(t *testing.T) {
	for _, tc := range []struct{ name, body, state string }{
		{"2.0", strings.Replace(r33Body("p1"),
			`"schema_version": "1.0"`, `"schema_version": "2.0"`, 1),
			"'2.0'"},
		{"absent", strings.Replace(r33Body("p1"),
			`"schema_version": "1.0", `, "", 1),
			"'ABSENT (pre-1.0 report)'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.body == r33Body("p1") {
				t.Fatal("fixture drift: the mutation did not apply")
			}
			c, root := mcCamp(t, "r33-f3-"+tc.name)
			rep := zzR32bWrite(t, tc.body)
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--autoprove", "INV-1", "--property", "p1",
				"--report", rep)
			wantErr := "verify --autoprove: report schema_version " +
				tc.state + " is not understood (this build speaks " +
				"1.0.x) — refusing to best-effort a contract change\n"
			if code != 2 || out != "" || errS != wantErr {
				t.Fatalf("verb: exit %d out=%q stderr\n got %q\nwant %q",
					code, out, errS, wantErr)
			}

			// The audit half: a real 1.0 bind, then the stored copy is
			// replaced by the very bytes the verb just refused.
			c2, root2 := r33ReportCampaign(t, "r33-f3-pin-"+tc.name)
			zzR32bForgeCopy(t, c2, []byte(tc.body))
			code, ok, joined, runs := zzR29bAudit(t, root2, c2.CampaignID)
			r33AssertBurned(t, code, ok, joined, runs, "INV-1",
				"schema_version", tc.state,
				"a fresh bind of these very bytes is refused")
		})
	}
}

// TestR33SchemaPatchFormStaysGreen is F3's control: the whole 1.x family is
// understood, the "1.0.3" patch form included, on BOTH halves.
func TestR33SchemaPatchFormStaysGreen(t *testing.T) {
	body := strings.Replace(r33Body("p1"), `"schema_version": "1.0"`,
		`"schema_version": "1.0.3"`, 1)
	c, root := mcCamp(t, "r33-f3-patch")
	zzR32bBindHonest(t, root, c, "p1", body)
	zzR32bHonestControl(t, root, c)
}

// TestR33ReportExecProvenanceBurnsAndVerbRefuses is F4, both arms, both
// halves.
//
//	(a) exec = a label the exec ledger does not hold. The verb refuses
//	    `--exec EXEC-99999999-nope` with its own sentence; forging the label
//	    into the slot and the event of an otherwise honest report rung used to
//	    audit green and print the ghost as the witness.
//	(b) exec = "REPORT-000000000000" over a real pin. The verb computes the
//	    label from the digest it mapped, so the audit can and must re-derive
//	    it.
func TestR33ReportExecProvenanceBurnsAndVerbRefuses(t *testing.T) {
	const ghost = "EXEC-99999999-nope"
	t.Run("ghost exec label", func(t *testing.T) {
		c, root := mcCamp(t, "r33-f4-ghost")
		rep := zzR32bWrite(t, r33Body("p1"))
		code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
			"--autoprove", "INV-1", "--property", "p1", "--report", rep,
			"--exec", ghost)
		want := "verify: no exec " + validation.PyReprStr(ghost) +
			" in this campaign's exec ledger\n"
		if code != 2 || out != "" || errS != want {
			t.Fatalf("verb: exit %d out=%q stderr\n got %q\nwant %q",
				code, out, errS, want)
		}

		c2, root2 := r33ReportCampaign(t, "r33-f4-ghost-pin")
		r33SetSlot(t, c2, "INV-1", "exec", ghost)
		r33Repin(t, c2, "INV-1", "exec", validation.VStr(ghost))
		code, ok, joined, runs := zzR29bAudit(t, root2, c2.CampaignID)
		r33AssertBurned(t, code, ok, joined, runs, "INV-1", ghost,
			"which the exec ledger does not hold")
	})
	t.Run("label that does not name the pin", func(t *testing.T) {
		c, root := r33ReportCampaign(t, "r33-f4-label")
		sha := objStr(r33LastEvent(t, c, "INV-1"), "report_sha256")
		honest := "REPORT-" + sha[:12]
		if got := objStr(r33Slot(t, c, "INV-1"), "exec"); got != honest {
			t.Fatalf("fixture drift: honest label = %q", got)
		}
		// The bind's own rule, from the bind's own function.
		if harness.ReportExecLabel(sha) != honest {
			t.Fatalf("the verb's label rule disagrees with the audit's")
		}
		r33SetSlot(t, c, "INV-1", "exec", "REPORT-000000000000")
		r33Repin(t, c, "INV-1", "exec",
			validation.VStr("REPORT-000000000000"))
		code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
		r33AssertBurned(t, code, ok, joined, runs, "INV-1",
			"REPORT-000000000000", sha[:12], honest)
	})
}

// TestR33ReportRungWearingAnExecKindBurns is F5: the honest bind writes
// harness.ReportKind ("miniprover") on the slot AND the event — asserted here
// from the real bind — so a report rung wearing halmos is a shape no verb
// produced, and the audit burns it instead of printing a provenance that
// names a captured stdout nothing read. The pinned report bytes are honest in
// this repro, so the burn can only come from the pairing.
func TestR33ReportRungWearingAnExecKindBurns(t *testing.T) {
	c, root := r33ReportCampaign(t, "r33-f5-kind")
	if got := objStr(r33Slot(t, c, "INV-1"), "kind"); got !=
		string(harness.ReportKind) {
		t.Fatalf("the verb must write %q, found %q",
			string(harness.ReportKind), got)
	}
	if got := objStr(r33LastEvent(t, c, "INV-1"), "kind"); got !=
		string(harness.ReportKind) {
		t.Fatalf("the verb's event must carry %q, found %q",
			string(harness.ReportKind), got)
	}
	r33SetSlot(t, c, "INV-1", "kind", "halmos")
	r33Repin(t, c, "INV-1", "kind", validation.VStr("halmos"))
	code, ok, joined, runs := zzR29bAudit(t, root, c.CampaignID)
	r33AssertBurned(t, code, ok, joined, runs, "INV-1", "halmos",
		string(harness.ReportKind), "no mapper produced this pairing")
}
