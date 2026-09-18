// cmd_verify_autoprove: `webv2 verify <C> --autoprove INV-x --property
// TITLE --report <run>/reports/report.json [--exec EXEC-x]`.
//
// The Phase B mapper of docs/MINIPROVER_INTEGRATION.md §5: MiniProver
// (the auto-prover) drives MiniCertora to author+verify a whole property
// set; this verb consumes the run's machine artifact — reports/report.json
// — and binds the resulting rung to one invariant of the campaign ledger.
//
// Attribution law mirrors the minicertora mapper: EXACT property-title
// match, refusal otherwise (prover titles are agent-authored; guessing a
// binding would attribute one property's proof to another's ledger row).
// Exit codes of the prover are tripwires ONLY — per §3 of the guide,
// verdict authority is report.json. Here, authority is the property's
// own rollup outcome, which the prover computes worst-first.
package cli

import (
	"fmt"
	"os"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// autoproveReport is what we trust from the file, kept small on purpose.
//
// r33 F3: the schema_version family this build speaks now lives on the ONE
// decision (harness.ReportSchemaMajor, read by harness.DecideReportSchema)
// instead of here — the verb's door and the audit's re-derivation must
// refuse the same report in the same words, and a constant only one of them
// can see is exactly how a "2.0" report got blessed by section 11.

// verifyAutoprove is cmd_verify's --autoprove branch.
// AutoproveSwapSeam, when armed by a test, runs between parse and the
// pre-bind recheck — the deterministic stand-in for an adversary racing
// a write onto the report path (r23 swap rail).
var AutoproveSwapSeam func()

// autoproveBind carries one verifyAutoprove invocation's shared bind
// context; the extracted stages below are its methods, called by the
// orchestrator in the original body's order.
type autoproveBind struct {
	c   *state.Campaign
	a   *verifyArgs
	r   *Runner
	raw []byte

	rep     validation.Value
	digest  string
	links   validation.Value
	entry   validation.Value
	rung    string
	summary string
	bk      *int
	outcome string
	exec    string
	prior   string
	artID   string
}

func verifyAutoprove(c *state.Campaign, a *verifyArgs, r *Runner) error {
	s := &autoproveBind{c: c, a: a, r: r}
	if err := s.autoproveCheckFlags(); err != nil {
		return err
	}
	if err := s.autoproveLoadReport(); err != nil {
		return err
	}
	if err := s.autoproveResolveEntry(); err != nil {
		return err
	}
	if err := s.autoproveCheckHolder(); err != nil {
		return err
	}
	if err := s.autoproveResolveExec(); err != nil {
		return err
	}
	if err := s.autoproveDecide(); err != nil {
		return err
	}
	s.autoproveStageEntry()
	if err := s.autoproveRegisterArtifact(); err != nil {
		return err
	}
	if err := s.autoproveBindEvent(); err != nil {
		return err
	}
	s.autoprovePrintResult()
	return nil
}

func (s *autoproveBind) autoproveCheckFlags() error {
	if s.a.property == "" {
		return t14ExitErr(2,
			"verify --autoprove needs --property <exact title the prover "+
				"gave the property> — attribution is exact-match by "+
				"design (property titles are agent-authored; a guessed "+
				"binding attributes one property's proof to another)\n")
	}
	if s.a.report == "" {
		return t14ExitErr(2,
			"verify --autoprove needs --report PATH (the run's "+
				"reports/report.json)\n")
	}
	return nil
}
func (s *autoproveBind) autoproveLoadReport() error {
	raw, err := os.ReadFile(s.a.report)
	if err != nil {
		return t14ExitErr(2, "verify --autoprove cannot read the report: %v\n",
			err)
	}
	rep, perr := validation.ParseOrdered(raw)
	if perr != nil || rep.Kind != validation.Obj {
		return t14ExitErr(2, "verify --autoprove: %s does not parse as one "+
			"JSON object — reports/report.json is the machine contract; "+
			"the run directory or a tampered copy is not\n", s.a.report)
	}
	s.raw, s.rep = raw, rep
	s.digest = validation.Sha256Hex(raw)
	// r33 F3: the schema gate is harness.DecideReportSchema — the FIRST
	// gate of the one shared decision (harness.DecideReport), asked here so
	// that this verb refuses a report it cannot read BEFORE it loads links,
	// scans the property-holder ledger or touches the exec ledger (its
	// historical position, and the position its refusal bytes are pinned
	// in). The sentence and the state it names come from the gate, so the
	// audit's re-derivation of a pinned copy refuses in the same words;
	// before this the gate existed only here and section 11 blessed a
	// report whose schema_version was "2.0" or absent.
	if dec := harness.DecideReportSchema(rep); dec.Gate != harness.GateNone {
		return t14ExitErr(2, "verify --autoprove: %s", dec.Refusal)
	}
	return nil
}

func (s *autoproveBind) autoproveResolveEntry() error {
	links, err := invariants.LoadLinks(s.c)
	if err != nil {
		return err
	}
	s.links = links
	entry, found := harnessInvEntry(links, s.a.autoprove)
	if !found {
		return t14ExitErr(2, "verify: unknown invariant %s\n",
			validation.PyReprStr(s.a.autoprove))
	}
	s.entry = entry
	return nil
}

// autoproveCheckHolder is the double-credit rail: the (report, property)
// pair must not already be bound to another invariant.
func (s *autoproveBind) autoproveCheckHolder() error {
	// r20 F9: a proof is a property's, and a property proves ONE
	// invariant — binding the same (report, property) to a second
	// ledger row would duplicate credit for one proof (the double-count
	// the dedup law refuses everywhere else). Scan the event ledger
	// (not display state): the claim must not be laundered by a later
	// overwrite of the first binding.
	// r21 F3: the rail keys on the PROPERTY TITLE, not (digest,property):
	// a trailing newline churned the sha and re-registered the same
	// proof for a second invariant clean. A property is a named claim —
	// the name is the identity; the digest is F10's freshness concern.
	if holder, first := autoprovePropertyHolder(s.c, s.a.property); holder != "" && holder != s.a.autoprove {
		return t14ExitErr(2, "verify --autoprove: property %s was already "+
			"bound to %s (%s) — one property's proof binds one invariant; "+
			"give the second invariant its OWN property (digest churn is "+
			"not a new proof)\n",
			validation.PyReprStr(s.a.property), holder, first)
	}
	return nil
}

// autoproveResolveExec picks the provenance row's exec: the operator's
// --exec when given (checked), else the content-addressed report label.
func (s *autoproveBind) autoproveResolveExec() error {
	exec := s.a.execID
	if exec != "" {
		// r20 F7: a provenance row naming a nonexistent EXEC is a
		// fabricated witness — the same harnessExecRecord check the
		// minicertora mapper refuses with.
		if _, _, eerr := harnessExecRecord(s.c, exec); eerr != nil {
			return eerr
		}
	}
	if exec == "" {
		// No sandbox EXEC wrapped this report: the digest identifies
		// what was mapped, and says so — an honest "report-only"
		// provenance row, not a fabricated EXEC id.
		//
		// r33 F4(b): the label rule is harness.ReportExecLabel, the ONE
		// home — section 11 re-derives the label from the pin with the
		// same function, so a forged "REPORT-000000000000" over a
		// different digest burns instead of printing itself as the
		// witness.
		exec = harness.ReportExecLabel(s.digest)
	}
	s.exec = exec
	return nil
}

// autoproveDecide runs the run-level gates and the mid-run swap rail,
// then records the mapped rung/summary/bounded_k/outcome.
func (s *autoproveBind) autoproveDecide() error {
	// The run-level gates FIRST: a rollup over a run the prover itself
	// refuses to publish is not evidence of anything.
	//
	// r19 P2 / r20 F6 / r22 F2 / r22 F5 / r24 F3 / r25 F2 — and, since
	// r32b F1, ALL FIVE GATES PLUS THE EXACT PROPERTY LOOKUP AND THE TYPED
	// BOUND live in harness.DecideReport, the SAME function section 11 now
	// re-derives from the pinned copy's bytes with the property name the
	// event binds. They used to exist only here, so the audit blessed a
	// report rung (a SUSPECT finding, published:false) that a fresh bind of
	// those very bytes refuses. One implementation, one sentence: the
	// Refusal is this verb's own text, byte for byte.
	dec := harness.DecideReport(s.rep, s.a.property)
	if dec.Gate != harness.GateNone {
		return t14ExitErr(2, "verify --autoprove: %s", dec.Refusal)
	}
	s.rung, s.summary, s.bk, s.outcome = dec.Rung, dec.Summary,
		dec.BoundedK, dec.Outcome
	if AutoproveSwapSeam != nil {
		AutoproveSwapSeam() // test-only: write the file post-parse
	}
	// r23: the file was read at parse time; anything changing it between
	// then and the bind makes the event's report_sha256 a name for bytes
	// the registry never hashed. Refuse mid-run swaps BEFORE the bind —
	// nothing to unwind, the re-run maps whatever is current.
	if cur, rerr := os.ReadFile(s.a.report); rerr != nil ||
		validation.Sha256Hex(cur) != s.digest {
		return t14ExitErr(2, "verify --autoprove: the report changed on "+
			"disk while being mapped (parse-time sha %s, now different) — "+
			"a bind must name the exact bytes it read; re-run against the "+
			"current file\n", s.digest[:12])
	}
	return nil
}

// autoproveStageEntry stamps the verification.harness field onto the
// invariant entry and captures the prior bind's digest baseline.
func (s *autoproveBind) autoproveStageEntry() {
	// proof sidecar is minicertora-only BY SCHEMA ("ABSENT for other
	// kinds") — the report itself is registered as the artifact instead:
	// its hash rides the event, and the campaign store keeps the bytes.
	s.entry.O = validation.SetOrAppend(s.entry.O, "verification",
		validation.VObj(harnessField(harness.Kind("miniprover"), s.rung, s.exec,
			s.bk, s.summary, validation.VNull())))
	// r20 F3: the rung is campaign STATE — links + event land together or
	// not at all (linksThenLog, the same law the minicertora path got).
	// The artifact registers AFTER the bind: a refused pair must not
	// leave a registered-but-never-logged report behind.
	// (F10: the PRIOR digest is captured BEFORE this bind's event exists
	// — asking after the append would always "find" the current run.)
	s.prior = autoprovePriorDigest(s.c, s.a.autoprove)
}

// autoproveRegisterArtifact registers the content-addressed report copy
// and refuses when the registry's own hash disagrees with the bind.
func (s *autoproveBind) autoproveRegisterArtifact() error {
	// r24 F1 (critic F1): REGISTER FIRST and let the registry's own
	// hash vote on the bind. The old order (bind, then register) left
	// the event naming bytes the registry might never have held — a
	// swap in the window was permanent, audit-invisible, and the
	// transient stderr warning pointed at evidence nothing stored.
	// Now: register (which hashes the path), compare against the
	// mapped digest, and refuse — pruning the fresh row — when the
	// registry holds different bytes than the bind would name. A
	// refused linksThenLog likewise prunes: no registered-but-unlogged
	// ghost in either direction.
	rebindReason := "autoprove result re-bound"
	if s.prior != "" && s.prior != s.digest {
		rebindReason = fmt.Sprintf("autoprove re-bound over a CHANGED "+
			"report: prior event sha %s, this file %s", s.prior, s.digest)
		fmt.Fprintln(s.r.Err, "  WARNING: "+s.a.autoprove+" was previously "+
			"bound from a DIFFERENT report digest ("+s.prior[:12]+"… -> "+
			s.digest[:12]+"…) — "+rebindReason)
	}
	// r25 F4: bind a CONTENT-ADDRESSED COPY under the campaign, not the
	// mutable operator path. Refresh-overwrite is the destructive act:
	// a refused re-bind used to prune (or a successful one rewrite) the
	// row a PRIOR live bind's event cites — evidence ownership erased by
	// an unrelated later act. With the copy, each digest is its own
	// immutable row inside the store: prior citations always survive,
	// reconcile can never substitute a foreign byte into a pinned sha
	// (the copy IS the store), and the registry hash that VOTES on the
	// bind hashes exactly what the event names.
	copyPath, cerr := storeReportCopy(s.c, s.digest, s.raw)
	if cerr != nil {
		return t14ExitErr(2, "verify --autoprove: cannot store the "+
			"report copy: %v\n", cerr)
	}
	artID, err := s.c.RegisterOrRefresh("harness", copyPath,
		"miniprover report bound to "+s.a.autoprove+" (property "+
			s.a.property+", rollup "+s.outcome+")", nil,
		rebindReason)
	if err != nil {
		return err
	}
	s.artID = artID
	regDig := ""
	if row, aerr := s.c.Artifact(artID); aerr == nil {
		regDig = validation.ObjStr(row, "sha256")
	}
	if regDig != s.digest {
		_, _ = s.c.PruneArtifact(artID,
			"pruned: registry digest does not match the mapped report "+
				"bytes at bind time")
		return t14ExitErr(2, "verify --autoprove: the registry hashed "+
			"the report as %s but this bind maps %s — the bytes differ, "+
			"and an event would name evidence the store does not hold; "+
			"refused, artifact row pruned\n", regDig, s.digest)
	}
	return nil
}

// autoproveBindEvent lands the rung atomically (linksThenLog) and, on a
// refusal, prunes the fresh artifact row only when no live bind cites it.
func (s *autoproveBind) autoproveBindEvent() error {
	if err := linksThenLog(s.c, func() error {
		return harnessSaveEntry(s.c, s.links, s.a.autoprove, s.entry)
	}, func() error {
		bkV := validation.VNull()
		if s.bk != nil {
			bkV = validation.VInt(int64(*s.bk))
		}
		edata := autoproveEventData(s.a.autoprove, s.rung, s.exec, s.summary,
			s.a.property, s.digest, bkV, s.rep)
		_, lerr := s.c.Log("harness_run", &s.a.autoprove, &edata)
		return lerr
	}); err != nil {
		// r25 F4: NEVER destroy evidence a LIVE bind still cites. The
		// REFUSED bind's own event does not exist (unwind restored it),
		// but an EARLIER bind may pin this row's digest — pruning it
		// then would burn the prior, honest rung on §11 for an
		// operator hiccup that touched nothing of theirs. Cite-check
		// first, BY ROW ID (r35 F1: the id is what an id-shaped
		// citation names), and prune only an orphan.
		if cited, cerr := artifactCitedByLiveBinds(s.c, s.artID); cerr == nil &&
			!cited {
			_, perr := s.c.PruneArtifact(s.artID,
				"pruned: bind refused — "+err.Error())
			if perr != nil {
				return fmt.Errorf("%w (AND the artifact row %s could not "+
					"be pruned: %v — a registered-but-unbound report; "+
					"reconcile by hand)", err, s.artID, perr)
			}
		} else {
			fmt.Fprintf(s.r.Err, "  NOTE: artifact %s stays: a live bind "+
				"cites its bytes; this refused bind left no event\n",
				s.artID)
		}
		return err
	}
	return nil
}

// autoprovePrintResult is the success output: the pinned one-line rung
// summary plus the two degradation notes.
func (s *autoproveBind) autoprovePrintResult() {
	fmt.Fprintf(s.r.Out, "%s: %s — %s\n", s.a.autoprove, s.rung, s.summary)
	if !t26Truthy(s.rep, "review_independent") {
		fmt.Fprintln(s.r.Out, "  note: review was NOT independent (same or "+
			"no reviewer model) — the rollup rides one model's opinion")
	}
	if cm := validation.ObjAt(s.rep, "capabilities_missing"); len(objKVs(cm)) > 0 {
		fmt.Fprintf(s.r.Out, "  verifier gaps at run time: %d capabilities "+
			"missing (degraded run; see tools/minicertora_conformance.py)\n",
			len(objKVs(cm)))
	}
}
