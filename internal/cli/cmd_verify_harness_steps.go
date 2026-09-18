package cli

// cmd_verify_harness_steps: the --harness-result bind's extracted
// pipeline stages (moved verbatim from cmd_verify_harness.go, which keeps
// the concern's documentation and the orchestrator).

import (
	"fmt"
	"websec/internal/findings"
	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/validation"
)

func (s *harnessResultBind) harnessResultCheckExec() error {
	if s.a.execID == "" {
		return t14ExitErr(2,
			"verify --harness-result needs --exec EXEC-...\n")
	}
	return nil
}

func (s *harnessResultBind) harnessResultLoadEntry() error {
	links, err := invariants.LoadLinks(s.c)
	if err != nil {
		return err
	}
	s.links = links
	entry, found := harnessInvEntry(links, s.a.harnessResult)
	if !found {
		return t14ExitErr(2, "verify: unknown invariant %s\n",
			validation.PyReprStr(s.a.harnessResult))
	}
	s.entry = entry
	return nil
}

func (s *harnessResultBind) harnessResultResolveKind() error {
	kind, err := harnessKindFor(s.c, s.a.harnessResult, s.a.kind)
	if err != nil {
		return err
	}
	s.kind = kind
	return nil
}

// harnessResultLoadStdout loads the exec record and its captured stdout,
// refusing a truncated stdout capture outright.
func (s *harnessResultBind) harnessResultLoadStdout() error {
	rec, execDir, err := harnessExecRecord(s.c, s.a.execID)
	if err != nil {
		return err
	}
	s.rec, s.execDir = rec, execDir
	raw, err := harnessExecStdout(execDir, rec)
	if err != nil {
		return err
	}
	s.raw = raw
	// P2-2: a run whose stdout the record marks TRUNCATED never binds a
	// rung — not from the kept bytes, and not from their content. The
	// mapper's verdict lines could sit past the cap in either direction:
	// what the kept prefix shows (a verdict line present, or absent) is
	// unprovable both ways, so the bind refuses with the observed capture
	// accounting instead of mapping a half-file. (A record that marks
	// only STDERR truncated still binds: the binder maps the stdout
	// stream, and those kept bytes are complete.)
	if tc := findings.ExecTruncatedCapture(rec); tc != nil &&
		tc.Stream == "stdout" {
		return t14ExitErr(2, "verify: exec %s stdout is unfit to bind a "+
			"rung: %s — the run's verdict lines could sit past the cap "+
			"(their absence AND their presence are unprovable), so no "+
			"rung is bound from a truncated capture; re-run the harness "+
			"with output under the capture cap\n",
			validation.PyReprStr(s.a.execID), tc.Accounting())
	}
	return nil
}

// harnessResultLoadScaffold loads the T17 scaffold artifact bytes.
func (s *harnessResultBind) harnessResultLoadScaffold() error {
	scaffold, err := harnessScaffoldBytes(s.c, s.a.harnessResult, s.kind)
	if err != nil {
		return err
	}
	s.scaffold = scaffold
	return nil
}

// harnessResultCheckCompiler resolves the exec's compiler pin and refuses
// a run whose reported solc disagrees with it.
func (s *harnessResultBind) harnessResultCheckCompiler() error {
	// r18 (A2, §6.2 of the integration doc): provenance was RECORDED but
	// never ENFORCED — a run compiled by a different solc than the
	// campaign's exec record pins bound its rung today. Now the mapper
	// compares the report lines' solc_version against the pinned
	// compiler (the --solc-path the command itself named, else the
	// record's tool_versions row) and REFUSES a mismatch. When no pin
	// is visible from either source the run proceeds, marked UNCHECKED
	// in the proof — honest, not silent.
	pin, pinSource, pinNamedUnresolved, pinErr := harnessCompilerPin(s.rec)
	if pinErr != nil {
		return pinErr
	}
	s.pin, s.pinSource, s.pinNamedUnresolved = pin, pinSource, pinNamedUnresolved
	reported := harnessReportedCompilers(s.raw)
	s.reported = reported
	if pin != "" && len(reported) > 0 {
		for _, v := range reported {
			if v != pin {
				return t14ExitErr(2,
					"verify: toolchain-mismatch for %s — the harness "+
						"reports solc %s, the exec pinned solc %s (%s); "+
						"rerun with a matching compiler (the provenance "+
						"is recorded, now it is also enforced)\n",
					s.a.harnessResult, v, pin, pinSource)
			}
		}
	}
	return nil
}

// harnessResultMapRung reads the run's status bits and asks the ONE home
// in package harness for the rung (harnessMapBound).
func (s *harnessResultBind) harnessResultMapRung() {
	// The minicertora mapper is exit-status aware: an int exit_status is
	// the run's own report, anything else (absent/null/big) is "unknown"
	// (-2), and MapMinicertora's negative floor refuses it — a run that
	// never reported a clean exit is never promoted. timedOut covers
	// -1 and the 128+N signal deaths, so -2 is the fail-open remainder.
	// r28b F2: BOTH readings now come from the one home in package
	// harness, so the audit's re-derivation cannot hold a second opinion
	// about an absent exit status (it read 0 there, the bind reads -2).
	s.timedOut = harnessTimedOut(s.rec)
	s.exitStatus = harness.RecordExitStatus(s.rec)
	// r32 F1/F2/F8: the invocation bound is read from the record by the ONE
	// reader — the command field's SHAPE first (a present non-string is an
	// unreadable invocation, never an absent one), then the parse shaped by
	// THIS kind (forge's u32/clap rules, halmos's and minicertora's Python
	// ints, and a foreign bound flag as a floor). harness.DecideBound
	// re-reads the same record through the same reader, so the bind and
	// section 11's re-derivation cannot disagree about any of it.
	s.k = harness.RecordInvocationBound(s.kind, s.rec)
	_ = s.pinSource
	s.ruleName = harness.MspecRuleName(s.a.harnessResult)
	// Validate renders from the same value the scaffold command rendered
	// from, so the re-render can only differ where the bytes really moved.
	s.inv = harnessInvValue(s.a.harnessResult, s.entry)
	s.rung, s.summary, s.proof, s.boundedK = harnessMapBound(s.kind, s.inv,
		s.raw, s.rec, s.scaffold, s.timedOut, s.k, s.exitStatus, s.ruleName)
}

// harnessResultStampProof writes the compiler_pin state line onto the
// proof sidecar (when one exists).
func (s *harnessResultBind) harnessResultStampProof() {
	if s.proof.Kind == validation.Obj {
		// r19 P1 #3: there are THREE states, not two. A pin with NO
		// report lines carrying solc_version compared NOTHING — stamping
		// "checked against pinned" there was the same lie in reverse
		// (law 3: an unmade comparison is never reported as made).
		state := "unchecked (no compiler pin visible on this record)"
		// r20 F4: "checked" must mean the ATTRIBUTED line's own
		// solc_version agreed with the pin — a foreign rule line's
		// version checked the RUN, not this proof.
		avOK := false
		if s.proof.Kind == validation.Obj {
			// r21 F4: an EMPTY solc_version is exactly "carries no
			// version" — Kind alone resurrected the "checked" lie.
			if v := validation.ObjAt(s.proof, "solc_version"); v.Kind == validation.Str &&
				v.S != "" {
				avOK = true
			}
		}
		switch {
		case s.pin != "" && len(s.reported) > 0 && avOK:
			state = "checked against pinned solc " + s.pin
		case s.pin != "" && len(s.reported) > 0 && !avOK:
			state = "checked at run level against pinned solc " + s.pin +
				" (the attributed line carries no solc_version of its own)"
		case s.pin != "":
			state = "unchecked (pin " + s.pin + " from " + s.pinSource +
				"; the attributed report lines carry no solc_version to " +
				"compare — nothing was verified)"
		}
		if s.pinNamedUnresolved != "" {
			state += " [note: the exec names --solc-path " +
				s.pinNamedUnresolved + " in a form this check could not " +
				"resolve; the pin above is NOT that binary]"
		}
		s.proof.O = validation.SetOrAppend(s.proof.O, "compiler_pin",
			validation.VStr(state))
	}
}

// harnessResultStageBind stamps verification.harness onto the entry and
// builds the harness_run event payload.
func (s *harnessResultBind) harnessResultStageBind() {
	s.entry.O = validation.SetOrAppend(s.entry.O, "verification",
		validation.VObj(harnessField(s.kind, s.rung, s.a.execID, s.boundedK,
			s.summary, s.proof)))
	s.hrunData = validation.VObj(
		// r21: kind rides the event so the audit backstop can back-check
		// the slot's kind too (additive to the event payload).
		validation.KV{K: "kind", V: validation.VStr(string(s.kind))},
		validation.KV{K: "rung", V: validation.VStr(s.rung)},
		validation.KV{K: "exec", V: validation.VStr(s.a.execID)},
		validation.KV{K: "invariant", V: validation.VStr(s.a.harnessResult)},
		validation.KV{K: "summary", V: validation.VStr(s.summary)},
		// r22 F3: the backstop can only back-check what the event
		// carries — k rides too (null = the run stated no bound).
		validation.KV{K: "bounded_k", V: func() validation.Value {
			if s.boundedK != nil {
				return validation.VInt(int64(*s.boundedK))
			}
			return validation.VNull()
		}()},
		// r23 F1: the proof subtree's fingerprint rides the event — k=
		// and poc: render FROM it, so "backed" must mean it too.
		validation.KV{K: "proof_sha256",
			V: validation.VStr(harnessProofDigest(s.proof))},
	)
}

// harnessResultCommit lands the rung atomically (linksThenLog).
func (s *harnessResultBind) harnessResultCommit() error {
	if err := linksThenLog(s.c, func() error {
		return harnessSaveEntry(s.c, s.links, s.a.harnessResult, s.entry)
	}, func() error {
		_, lerr := s.c.Log("harness_run", &s.a.harnessResult, &s.hrunData)
		return lerr
	}); err != nil {
		return err
	}
	return nil
}

// harnessResultWritePoc is the L4 consumption seam on the run path: the
// rung (entry + event) is on record before the derived artifact is
// attempted, so a refusal to bridge must never cost the record of the run.
func (s *harnessResultBind) harnessResultWritePoc() error {
	// The rung (entry + event) is on record before the derived artifact is
	// attempted: the PoC is a view of the rung, so a refusal to bridge must
	// never cost the record of the run, and an I/O error here leaves a
	// campaign whose re-verify reproduces the file byte-for-byte.
	if s.kind == harness.MiniCertora && s.rung == harness.RungCounterexample {
		if err := harnessWriteBridgedPoc(s.c, s.a.harnessResult, s.raw, s.ruleName,
			s.r); err != nil {
			return err
		}
	}
	return nil
}

// harnessResultPrint is the pinned stdout record of the bound rung.
func (s *harnessResultBind) harnessResultPrint() {
	switch {
	case s.rung == harness.RungProvedBounded && s.boundedK != nil:
		fmt.Fprintf(s.r.Out, "%s: %s (%s, k=%d, %s)\n", s.a.harnessResult,
			s.rung, string(s.kind), *s.boundedK, s.a.execID)
	case s.rung == harness.RungProvedBounded:
		// The display k is sidecar-first: proved-bounded with a nil
		// bounded_k is a *valid* outcome (bounds.loop_bound absent,
		// non-int or too large for int64 — the mapper keeps its own
		// copy in proof.bounds), so read it from there instead of
		// dereferencing the convenience pointer. The k-less form below
		// is the last resort: same print shape as every other rung.
		if k, ok := proofLoopBoundText(s.proof); ok {
			fmt.Fprintf(s.r.Out, "%s: %s (%s, k=%s, %s)\n",
				s.a.harnessResult, s.rung, string(s.kind), k, s.a.execID)
		} else {
			fmt.Fprintf(s.r.Out, "%s: %s (%s, %s)\n", s.a.harnessResult,
				s.rung, string(s.kind), s.a.execID)
		}
	default:
		fmt.Fprintf(s.r.Out, "%s: %s (%s, %s)\n", s.a.harnessResult, s.rung,
			string(s.kind), s.a.execID)
	}
}

// proofLoopBoundText is the proved-bounded display k read off the proof
// sidecar: proof.bounds.loop_bound when it is an integer (the exact
// decimal text, so a bound beyond int64 renders verbatim rather than
// losing digits). ok=false for a missing sidecar, a null/malformed
// bounds object, or a non-integer loop_bound.
func proofLoopBoundText(proof validation.Value) (string, bool) {
	lb := validation.ObjAt(validation.ObjAt(proof, "bounds"), "loop_bound")
	if lb.Kind != validation.Int {
		return "", false
	}
	return validation.IntText(lb), true
}
