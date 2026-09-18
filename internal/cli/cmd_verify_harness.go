package cli

// cmd_verify_harness: `webv2 verify <campaign> --harness-result INV-id
// --exec EXEC-... [--kind halmos|forge-fuzz|minicertora]` (Task 18, G8) —
// land one harness run's rung on its invariant as verification.harness.
//
// There is deliberately NO auto-detect hook: a stray halmos run must never
// be attributed to an invariant by guesswork, so attribution is always an
// explicit operator act (both ids on the command line). The flow:
//
//  1. load the EXEC record (execs/EXEC-*/exec_record.json) and read its
//     stdout file (stdout_path, resolved relative to the exec dir when
//     relative; read capped at 1MB);
//  2. resolve the kind: --kind, else the scaffold artifact id
//     HARNESS-<INV>-<kind> from the harness_scaffold events (ambiguous
//     when both skeletons exist — then --kind is required);
//  3. load the scaffold ARTIFACT bytes T17 wrote (harness_scaffold event
//     ref -> registered artifact -> file) and bind the run to them
//     (Decision 2b): a recorded hash equal to the scaffold sha binds the
//     run — and the bytes are then re-rendered from the CURRENT claim by
//     harness.Validate, so a claim edited after the run is a
//     scaffold-degraded refusal (rung inconclusive, the output is NOT
//     used); a harness-named hash entry with a different sha is a
//     scaffold-bound violation (same refusal, hash wording); no hash info
//     leaves the run unbound — Validate then judges the on-disk harness
//     file itself against the CURRENT claim (the same scaffold-degraded
//     refusal on drift, since that file is the only artifact left), and a
//     file that still matches maps normally with an "(unbound: ...)"
//     suffix;
//  4. map the stdout to a rung: an untimed minicertora run through
//     MapMinicertoraInvoc(raw, exit_status, MspecRuleName(inv), k) —
//     MapMinicertora plus the invocation-level degenerate-bound floor,
//     which also captures the proof sidecar for every attributed verdict
//     line (UNKNOWN included) — and every other run through
//     MapRun(kind, stdout, timedOut, k). Write verification.harness
//     {kind, rung, exec, bounded_k, summary[, proof]} onto the invariant
//     entry (the existing invariant_links.json store — no parallel store)
//     and log a harness_run {rung, exec, invariant, summary} audit event;
//  5. on a minicertora COUNTEREXAMPLE rung, hand the run's own witness to
//     the L4 bridge and write the runnable PoC artifact
//     artifacts/harness/<INV>/poc-<INV>.json through the same write/commit
//     path the scaffold uses (see "The bridged PoC artifact" below).
//
// The bridged PoC artifact. A counterexample is a witness, and the fork
// wave consumes it as a sequence_poc. The doc is bridged from the
// ATTRIBUTED VERDICT LINE in the exec stdout artifact — not from the
// stored proof sidecar, which carries `calls` but deliberately not
// final_storage — so the operator's optional storage-layout sidecar can
// ground the witness's final readings as final_assertions
// (harness.BridgeWitnessLine). The sidecar is
// artifacts/harness/<INV>/layout.json beside the PoC: one JSON OBJECT
// mapping "<Contract>.<var>" to a DECIMAL slot string, plus optional
// companion "<Contract>" -> "0x…40-hex" address entries (the form the
// bridge reads to point an assertion at a target the sequence actually
// calls). It is operator input, never written by this command, and it is
// SHAPE-CHECKED here (object of strings) while the bridge keeps ownership
// of what grounds: a reading whose contract or slot the layout does not
// state is skipped, never guessed, so a well-shaped sidecar that grounds
// nothing is a layoutless document and NOT an error.
//
// The seam is presence-gated and never guesses. Nothing is written unless
// the rung is a minicertora counterexample AND the witness bridged
// cleanly: an inconclusive refusal (bound violation, scaffold-degraded,
// exit-unmapped) writes no file, and a bridgable-looking line that is not
// (no calls, a symbolic sender, a non-wei value) writes no file either —
// the refusal is named on STDERR ("verify: poc for 'INV-1' not written:
// …") while the rung, the summary and the audit's derived
// "| poc: N calls bridged" line are untouched: the rung is this command's
// record and a refusal to derive a file must never cost it. A malformed
// layout sidecar is likewise ignored with one stderr note (the bridge then
// runs exactly as if no sidecar existed), because a broken operator file
// must not turn a mappable run into an error. OVERWRITE law: the file is a
// derived view of the invariant's latest counterexample, so a re-verify
// rewrites that one path — and writes NOTHING (no registry churn, no
// event) when the bridged bytes are unchanged, which is what makes a
// re-verify byte-identical and event-for-event idempotent. The write is
// silent on stdout by design: the harness-result print line is pinned.
//
// What this path does NOT do (rails): it appends no evidence items to
// findings (mint's E4 gate does not accept host profiles — promotion
// rides triage reading the rung), and it queues no learning memory:
// invariant entries carry no intent-claim marker (their kind/source axes
// are security|...|liveness and documented|model; intent claims live in
// the separate IntentClaims view), so per the controller there is nothing
// to record — the rung field plus the harness_run event are the complete
// record.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"websec/internal/findings"
	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

import (
	"os/exec"

	"websec/internal/sandbox"
)

// harnessResultBind carries one --harness-result bind's shared context;
// the extracted stages below are its methods, called by the orchestrator
// in the original body's order.
type harnessResultBind struct {
	c *state.Campaign
	a *verifyArgs
	r *Runner

	links    validation.Value
	entry    validation.Value
	kind     harness.Kind
	rec      validation.Value
	execDir  string
	raw      []byte
	scaffold []byte

	pin                string
	pinSource          string
	pinNamedUnresolved string
	reported           []string

	timedOut   bool
	exitStatus int
	k          int
	ruleName   string
	inv        validation.Value
	rung       string
	summary    string
	proof      validation.Value
	boundedK   *int
	hrunData   validation.Value
}

// verifyHarnessResult is cmd_verify's --harness-result branch.
func verifyHarnessResult(c *state.Campaign, a *verifyArgs, r *Runner) error {
	s := &harnessResultBind{c: c, a: a, r: r}
	if err := s.harnessResultCheckExec(); err != nil {
		return err
	}
	if err := s.harnessResultLoadEntry(); err != nil {
		return err
	}
	if err := s.harnessResultResolveKind(); err != nil {
		return err
	}
	if err := s.harnessResultLoadStdout(); err != nil {
		return err
	}
	if err := s.harnessResultLoadScaffold(); err != nil {
		return err
	}
	if err := s.harnessResultCheckCompiler(); err != nil {
		return err
	}
	s.harnessResultMapRung()
	s.harnessResultStampProof()
	s.harnessResultStageBind()
	if err := s.harnessResultCommit(); err != nil {
		return err
	}
	if err := s.harnessResultWritePoc(); err != nil {
		return err
	}
	s.harnessResultPrint()
	return nil
}

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

// harnessLayoutFile is the operator-provided storage-layout sidecar's
// basename: artifacts/harness/<INV>/layout.json beside the PoC it grounds.
const harnessLayoutFile = "layout.json"

// harnessPocFile is the bridged PoC's basename inside the invariant's
// harness dir. It names the invariant, not the exec: the file is a view of
// the invariant's latest counterexample rung, so a newer run replaces it
// rather than accumulating one file per run.
func harnessPocFile(invID string) string {
	return "poc-" + invID + ".json"
}

// pocSpecID is the sequence_poc `spec_id` a bridged PoC carries:
// "SEQ-<slug>-POC", where the slug is the invariant id uppercased with
// every non-alphanumeric byte dropped ("INV-1" -> "SEQ-INV1-POC"). The
// schema pins spec_id to ^SEQ-[A-Z0-9]+-[A-Za-z0-9]+$, and the id is a
// function of the INVARIANT alone — never of the exec or the witness — so
// the same invariant always claims the same spec_id and a re-verify
// overwrites one artifact instead of minting a second identity. (A
// hand-edited invariant id whose slug is empty yields an id the schema
// refuses; harnessWriteBridgedPoc validates the document before writing,
// so that lands as a named refusal, never as a schema-invalid file.)
func pocSpecID(invID string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(invID) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return "SEQ-" + b.String() + "-POC"
}

// harnessWriteBridgedPoc is the L4 consumption seam on the run path: on a
// minicertora counterexample rung, bridge the run's witness into a
// sequence_poc and land it as artifacts/harness/<INV>/poc-<INV>.json.
//
// It is total and never fails a mappable run: every refusal lane prints ONE
// stderr note and returns nil — the run's rung is already recorded and the
// derived artifact simply does not exist. The lanes:
//
//   - the layout sidecar (harnessLayoutSidecar) is malformed -> one note,
//     bridge layoutless;
//   - the bridge refuses the witness (no calls, an unbridgable step, a
//     symbolic sender, a non-wei value) -> "verify: poc for '<INV>' not
//     written: <the bridge's own refusal>";
//   - the bridged document fails the sequence_poc schema (a defect in the
//     bridge, or an invariant id with no alphanumerics) -> the same note
//     shape with the schema error, because a schema-invalid artifact under
//     artifacts/ is worse than no artifact.
//
// A clean bridge is SILENT: the harness-result print line is pinned, so the
// success record is the artifact registry row (kind sequence-poc) plus the
// file itself. A failed writer (I/O, registry) is a real error and does
// propagate.
func harnessWriteBridgedPoc(c *state.Campaign, invID string, raw []byte,
	ruleName string, r *Runner) error {
	layout, layoutNote := harnessLayoutSidecar(c, invID)
	if layoutNote != "" {
		fmt.Fprintln(r.Err, layoutNote)
	}
	doc, refusal := harness.BridgeWitnessLine(raw, ruleName, pocSpecID(invID),
		invID, layout)
	if refusal != "" {
		fmt.Fprintf(r.Err, "verify: poc for %s not written: %s\n",
			validation.PyReprStr(invID), refusal)
		return nil
	}
	if err := validation.Validate(doc, "sequence_poc", 1); err != nil {
		fmt.Fprintf(r.Err, "verify: poc for %s not written: bridged "+
			"document is not a sequence_poc: %s\n",
			validation.PyReprStr(invID), err)
		return nil
	}
	regNote := fmt.Sprintf("bridged counterexample witness for %s (%s)",
		invID, pocSpecID(invID))
	_, _, err := harnessArtifactWrite(c, invID, harnessPocFile(invID),
		[]byte(validation.CanonCompact(doc)), "sequence-poc", regNote,
		"bridged witness regenerated")
	return err
}

// harnessLayoutSidecar loads the operator's storage-layout sidecar for one
// invariant and reports why it was ignored, if it was. The shape is
// deliberately narrow: a JSON OBJECT whose every value is a STRING —
// "<Contract>.<var>" -> decimal slot, plus optional "<Contract>" -> 0x
// address companions (see the file comment). Anything else (absent-but-
// unreadable, not JSON, an array or scalar, a numeric slot) is malformed:
// the map is dropped and the note says which rule broke, so the operator
// sees a typo instead of silently losing final_assertions. A file that is
// merely absent — the normal case — is not a note: no sidecar is not a
// mistake, and a well-shaped sidecar that grounds nothing (an unknown
// contract, a symbolic reading) stays the BRIDGE's quiet skip, never this
// loader's complaint.
func harnessLayoutSidecar(c *state.Campaign, invID string) (map[string]string,
	string) {
	p := harnessArtifactFile(c, invID, harnessLayoutFile)
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ""
		}
		return nil, harnessLayoutNote(c, p,
			fmt.Sprintf("unreadable: %s", err))
	}
	v, err := validation.ParseOrdered(raw)
	if err != nil {
		return nil, harnessLayoutNote(c, p,
			fmt.Sprintf("not JSON: %s", err))
	}
	if v.Kind != validation.Obj {
		return nil, harnessLayoutNote(c, p, "top level must be an object "+
			"mapping \"<Contract>.<var>\" to a decimal slot string")
	}
	out := make(map[string]string, len(v.O))
	for _, kv := range v.O {
		if kv.V.Kind != validation.Str {
			return nil, harnessLayoutNote(c, p, fmt.Sprintf("key %s must "+
				"map to a string, got %s", validation.PyReprStr(kv.K),
				validation.CanonCompact(kv.V)))
		}
		out[kv.K] = kv.V.S
	}
	return out, ""
}

// harnessLayoutNote is the one-line stderr note for an ignored sidecar: the
// campaign-relative path (the spelling verifyScaffold prints for artifacts
// under the same dir) plus the reason.
func harnessLayoutNote(c *state.Campaign, p, why string) string {
	rel, err := filepath.Rel(c.Dir, p)
	if err != nil {
		rel = p
	}
	return fmt.Sprintf("verify: layout sidecar %s ignored: %s", rel, why)
}

// harnessField builds the verification.harness object in the brief's key
// order (kind, rung, exec, bounded_k int-or-null, summary, proof). The
// proof key rides ONLY when a sidecar object exists (an attributed
// minicertora line): every other kind — and every unattributed minicertora
// refusal — omits the key entirely rather than writing null.
func harnessField(kind harness.Kind, rung, exec string,
	boundedK *int, summary string, proof validation.Value) validation.KV {
	var bk validation.Value = validation.VNull()
	if boundedK != nil {
		bk = validation.VInt(int64(*boundedK))
	}
	kvs := []validation.KV{
		{K: "kind", V: validation.VStr(string(kind))},
		{K: "rung", V: validation.VStr(rung)},
		{K: "exec", V: validation.VStr(exec)},
		{K: "bounded_k", V: bk},
		{K: "summary", V: validation.VStr(summary)},
	}
	if proof.Kind == validation.Obj {
		kvs = append(kvs, validation.KV{K: "proof", V: proof})
	}
	return validation.KV{K: "harness", V: validation.VObj(kvs...)}
}

// harnessInvValue is the invariant value harness.Scaffold renders from: the
// registry entry plus the id the registry carries as its map KEY (Scaffold
// reads "id" off the record, so the key is passed in as that field). Both
// the scaffold command (verifyScaffold) and the Validate arm go through
// here on purpose: if the two inputs could drift, every bound run would be
// refused for bytes that never moved.
//
// r28b F3: the implementation moved to harness.InvValue so the audit's
// re-derivation builds the claim value the SAME way (one implementation,
// two callers); this is the package-local spelling its other call sites use.
func harnessInvValue(invID string, entry validation.Value) validation.Value {
	return harness.InvValue(invID, entry)
}

// harnessInvEntry is links["invariants"][invID] with presence.
func harnessInvEntry(links validation.Value, invID string) (validation.Value,
	bool) {
	if reg := validation.ObjAt(links, "invariants"); reg.Kind == validation.Obj {
		for _, kv := range reg.O {
			if kv.K == invID {
				return kv.V, true
			}
		}
	}
	return validation.VNull(), false
}

// harnessSaveEntry writes one entry back through the links store.
func harnessSaveEntry(c *state.Campaign, links validation.Value, invID string,
	entry validation.Value) error {
	reg := validation.ObjAt(links, "invariants")
	reg.O = validation.SetOrAppend(reg.O, invID, entry)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	_, err := invariants.SaveLinks(c, links)
	return err
}

// harnessKindFor resolves the harness kind: --kind wins; otherwise the
// scaffold artifact id HARNESS-<INV>-<kind> read off the harness_scaffold
// events. Zero scaffolds (or two, one per skeleton) without --kind is
// exit 2 — the operator disambiguates, the tool never guesses.
func harnessKindFor(c *state.Campaign, invID, flag string) (harness.Kind,
	error) {
	if flag != "" {
		// r29b F1(c): the kind is CANONICALIZED at the source, so the ledger
		// cannot hold a spelling no mapper knows. argparse already refuses
		// any --kind outside {halmos, forge-fuzz, minicertora} (parseVerifyArgs,
		// byte-identical message), so this resolution is the belt to that
		// brace: should a caller reach here without that validation, an
		// unknown or mis-cased kind is refused instead of stored verbatim
		// (the audit would then have to burn the bind's own rung).
		k, ok := harness.NormalizeScaffoldKind(flag)
		if !ok {
			return "", t14ExitErr(2, "verify: unknown harness kind %s\n",
				validation.PyReprStr(flag))
		}
		return k, nil
	}
	events, err := c.Events()
	if err != nil {
		return "", err
	}
	prefix := "HARNESS-" + invID + "-"
	var kinds []string
	for _, ev := range events {
		if validation.ObjStr(validation.ObjAt(ev, "data"), "artifact_id") == "" ||
			validation.ObjStr(ev, "type") != "harness_scaffold" {
			continue
		}
		aid := validation.ObjStr(validation.ObjAt(ev, "data"), "artifact_id")
		if !strings.HasPrefix(aid, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(aid, prefix)
		if (suffix == string(harness.Halmos) ||
			suffix == string(harness.ForgeFuzz) ||
			suffix == string(harness.MiniCertora)) &&
			!containsStrCLI(kinds, suffix) {
			kinds = append(kinds, suffix)
		}
	}
	switch len(kinds) {
	case 1:
		return harness.Kind(kinds[0]), nil
	case 0:
		return "", t14ExitErr(2, "verify: no harness scaffold for %s "+
			"(scaffold it first with verify --scaffold "+
			"{halmos|forge-fuzz|minicertora} --invariant %s, or pass "+
			"--kind)\n",
			validation.PyReprStr(invID), validation.PyReprStr(invID))
	default:
		return "", t14ExitErr(2, "verify: %s has multiple harness "+
			"scaffolds; pass --kind {halmos|forge-fuzz|minicertora}\n",
			validation.PyReprStr(invID))
	}
}

// harnessExecRecord loads execs/<execID>/exec_record.json (state.AllExecs,
// the reader cmd_execs uses) and reports the exec dir for relative
// stdout_path resolution.
func harnessExecRecord(c *state.Campaign, execID string) (validation.Value,
	string, error) {
	execs, err := state.AllExecs(c)
	if err != nil {
		return validation.VNull(), "", err
	}
	for _, e := range execs {
		if validation.ObjStr(e, "exec_id") == execID {
			return e, filepath.Join(c.ExecsDir, execID), nil
		}
	}
	return validation.VNull(), "", t14ExitErr(2,
		"verify: no exec %s in this campaign's exec ledger\n",
		validation.PyReprStr(execID))
}

// harnessExecStdout reads the run's captured stdout through the ONE reader
// the audit uses too (harness.ReadExecStdout — the r13 candidate order, the
// 1MB cap and the truncation semantics live there; r29b F2), and keeps this
// command's own refusal text for the two failure shapes it distinguishes:
// an empty record field means nothing was captured, an open failure says
// unreadable with the errno (r13).
//
// r13: a record written under `--root .` stores a CWD-relative stdout_path;
// joining it back against execDir double-nests the path and a
// plainly-present capture was reported as "no captured stdout to map". The
// canonical location — <execDir>/stdout.log — is the audit's law (execs.go
// derives it the same way); the reader prefers an ABSOLUTE stored path and
// falls back to the canonical one, exactly as this command always has.
func harnessExecStdout(execDir string, rec validation.Value) ([]byte, error) {
	raw, err := harness.ReadExecStdout(execDir, rec)
	if err == nil {
		return raw, nil
	}
	if errors.Is(err, harness.ErrNoCapturedStdout) {
		return nil, t14ExitErr(2,
			"verify: exec %s has no captured stdout to map\n",
			validation.PyReprStr(validation.ObjStr(rec, "exec_id")))
	}
	var ue *harness.StdoutUnreadableError
	if errors.As(err, &ue) {
		return nil, t14ExitErr(2,
			"verify: exec %s stdout file unreadable (%v)\n",
			validation.PyReprStr(validation.ObjStr(rec, "exec_id")), ue.Err)
	}
	return nil, err
}

// harnessScaffoldBytes loads the T17 scaffold artifact bytes: the latest
// harness_scaffold event for HARNESS-<INV>-<kind> names the registered
// artifact as its ref; the bytes come back through the artifacts API.
func harnessScaffoldBytes(c *state.Campaign, invID string,
	kind harness.Kind) ([]byte, error) {
	events, err := c.Events()
	if err != nil {
		return nil, err
	}
	want := "HARNESS-" + invID + "-" + string(kind)
	ref := ""
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_scaffold" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(ev, "data"), "artifact_id") != want {
			continue
		}
		ref = validation.ObjStr(ev, "ref")
	}
	if ref == "" {
		return nil, t14ExitErr(2, "verify: no harness scaffold for %s "+
			"(scaffold it first with verify --scaffold %s --invariant %s)\n",
			validation.PyReprStr(invID), string(kind),
			validation.PyReprStr(invID))
	}
	art, err := c.Artifact(ref)
	if err != nil {
		return nil, t14ExitErr(2,
			"verify: harness scaffold artifact %s is not registered\n",
			validation.PyReprStr(ref))
	}
	// r29b F3(c): the read itself is harness.ArtifactFileBytes — the row's
	// recorded path joined against the campaign root and read raw (no sha
	// re-check: the bind does not make one). Section 11's unbound arm reads
	// the same file the same way, so the bytes the bind Validated and the
	// bytes the audit Validates cannot be two different artifacts.
	raw, err := harness.ArtifactFileBytes(c.Root, validation.ObjStr(art, "path"))
	if err != nil {
		return nil, t14ExitErr(2,
			"verify: harness scaffold artifact %s has no readable file\n",
			validation.PyReprStr(ref))
	}
	return raw, nil
}

// harnessTimedOut is the MapRun timedOut bit: the sandbox records exit
// -1 both when the timeout kills the run and when the process never
// started, and a signal death (128+N, the shell's convention) means the
// process was killed rather than completed. Either way the run did not
// complete, so its bytes map to inconclusive, never to a rung — a
// "killed by signal" status is exactly as much a non-result as -1.
//
// r28b F2: the reading itself lives in package harness
// (harness.RecordTimedOut over harness.RecordExitStatus) so the bind and
// section 11 can never disagree about an absent exit_status — the audit
// arm read `es := 0` while this bit read "not timed out", and the two
// together blessed a record that named no exit at all.
func harnessTimedOut(rec validation.Value) bool {
	return harness.RecordTimedOut(rec)
}

// harnessCommand is the exec record's command string ("" when absent).
func harnessCommand(rec validation.Value) string {
	return validation.ObjStr(rec, "command")
}

// invocationBound parses the invocation bound out of an exec command —
// harness.InvocationBoundKind owns the parse, and the KIND is part of it.
//
// r32 F1/F2: this wrapper used to take the kind and throw it away
// (`_ = kind`), so ONE Python-flavoured reading was applied to three tools
// with three command-line languages: `forge test --fuzz-runs 4_000` (real
// forge: "error: invalid value '4_000' … invalid digit found in string")
// read as 4000, a repeated --fuzz-runs read last-wins although clap
// refuses it, and a LONE foreign bound flag (`forge test --loop 3`) was
// bound as if forge had a --loop. Carrying the kind makes the value
// semantics the owning tool's and floors a foreign bound flag as the
// invocation the tool would refuse.
//
// The production call site reads the record through
// harness.RecordInvocationBound instead of composing this with
// harnessCommand, because the record's command field must be read with its
// SHAPE (r32 F8: a `command` that is an ARRAY or a NUMBER is a stated
// invocation, not an absent one). This wrapper stays for callers that hold
// a command string (and for the S2 regression table), and it is the
// string-level half of exactly that reader.
func invocationBound(command string, kind harness.Kind) int {
	return harness.InvocationBoundKind(kind, command)
}

// harnessMapBound is the bind's rung decision, delegated to the ONE home in
// package harness (r28b F3). The bind keeps only its IO — harnessScaffoldBytes
// read the scaffold artifact bytes, harnessInvValue built the claim value,
// harness.RecordExitStatus / RecordTimedOut / InvocationBound read the
// record — and harness.DecideBound decides, in the bind's own order:
//
//   - the recorded-hash arm: a matching sha binds the run and
//     harness.Validate then re-renders the scaffold from the CURRENT claim,
//     refusing "scaffold-degraded: <reason>" when anything outside the body
//     window moved;
//   - the harness-named-different-sha arm: "scaffold-bound violation";
//   - the unbound arm (no hash info): Validate still judges the bytes on
//     record against the CURRENT claim, and a surviving file maps normally
//     with the "(unbound: harness file hash not recorded)" suffix — the
//     honest limitation.
//
// Only then does the kind mapper run: an untimed minicertora run through
// MapMinicertoraInvoc, everything else through MapRun.
//
// bounded_k is set only for proved-bounded (parsed k=<n> else the invocation
// k); every other rung carries null. The proof sidecar is non-null exactly
// when a mapper attributed a verdict line; the bound-violation and
// scaffold-degraded refusals never map, so they never carry one.
//
// Section 11 calls harness.DecideBound with these very inputs (kind, the
// claim value it builds with harness.InvValue, the exec stdout, the record,
// the scaffold artifact bytes, the record's own timedOut/exit status/k and
// the scaffold-pinned rule name), so the audit re-derives every decision
// this function makes instead of only the last step.
func harnessMapBound(kind harness.Kind, inv validation.Value, raw []byte,
	rec validation.Value, scaffold []byte, timedOut bool, k, exitStatus int,
	ruleName string) (rung, summary string, proof validation.Value,
	boundedK *int) {
	return harness.DecideBound(kind, inv, raw, rec, scaffold, timedOut, k,
		exitStatus, ruleName)
}

// harnessRecordedHashes is the package-local spelling of
// harness.RecordedHashes. r28b F3 moved the implementation into package
// harness so the audit's re-derivation asks the SAME question ("does this
// record carry hash evidence?") the hash arm answers; this delegate has no
// caller left in package cli and is kept on purpose, because
// cmd_artifact_prune.go re-reads the function BY NAME in its own comment
// about agreeing with the bind instead of holding a second opinion.
func harnessRecordedHashes(rec validation.Value) (hashes []string,
	harnessNamed bool) {
	return harness.RecordedHashes(rec)
}

// harnessCompilerPin resolves the compiler version the EXEC pinned: the
// binary its own --solc-path names (probed at verify time — asking the
// pin what version it IS), else the record's tool_versions["solc"]
// row. "" means no visible pin; a non-nil error means the pinned path
// exists but refuses to answer, which is NOT silently unchecked.
func harnessCompilerPin(rec validation.Value) (version, source,
	pinNamedUnresolved string, err error) {
	cmd := harnessCommand(rec)
	pinNamedUnresolved = ""
	if i := strings.Index(cmd, "--solc-path"); i >= 0 {
		// r19 P2: `--solc-path=PATH` is the same flag; one Fields() parse
		// silently DROPPED the named binary for it (and for relatives),
		// then labelled the record-pin "checked" anyway. Parse both
		// forms; when the mention cannot be resolved, SAY so on the
		// proof instead of pretending the flag wasn't there.
		token := cmd[i+len("--solc-path"):]
		path := ""
		if strings.HasPrefix(token, "=") {
			path = strings.Fields(token[1:])[0]
		} else if rest := strings.Fields(token); len(rest) > 0 {
			path = rest[0]
		}
		switch {
		case path == "":
			pinNamedUnresolved = "(no argument)"
		case !strings.HasPrefix(path, "/"):
			pinNamedUnresolved = path + " (relative: the exec's cwd is not " +
				"reconstructible here)"
		}
		if strings.HasPrefix(path, "/") {
			// r21 F6: a HANGING named compiler must not hang verify;
			// 10s bounded probe, timeout refused as an unanswerable pin.
			ctxP, cancelP := context.WithTimeout(context.Background(),
				10*time.Second)
			defer cancelP()
			cmdP := exec.CommandContext(ctxP, path, "--version")
			cmdP.WaitDelay = 2 * time.Second
			out, perr := cmdP.Output()
			if ctxP.Err() != nil {
				return "", "", "", t14ExitErr(2, "verify: probing the "+
					"pinned compiler %s TIMED OUT — provenance cannot be "+
					"checked, and a hanging pin is refused, not skipped\n",
					path)
			}
			if perr != nil {
				return "", "", "", t14ExitErr(2, "verify: cannot probe the "+
					"pinned compiler %s: %v — the run's provenance "+
					"cannot be checked, so it is not mapped", path,
					perr)
			}
			if v := sandbox.SolcVersionFromText(string(out)); v != "" {
				return v, "--solc-path " + path, "", nil
			}
			return "", "", "", t14ExitErr(2, "verify: pinned compiler %s "+
				"reported no parseable version — provenance cannot be "+
				"checked", path)
		} else if pinNamedUnresolved != "" {
			// fall through to the record pin WITH the note attached
			tv0 := validation.ObjAt(validation.ObjAt(rec, "environment"), "tool_versions")
			if v0 := validation.ObjStr(tv0, "solc"); v0 == "" {
				return "", "", pinNamedUnresolved, nil
			}
			return "", "", pinNamedUnresolved, t14ExitErr(2, "verify: the "+
				"run names --solc-path %s this check cannot resolve, and "+
				"enforcement of a NAMED compiler is not silently downgraded "+
				"to the record row — rerun recording a resolvable "+
				"--solc-path (absolute) or pin via tool_versions"+
				"\n", pinNamedUnresolved)
		}
	}
	tv := validation.ObjAt(validation.ObjAt(rec, "environment"), "tool_versions")
	if v := validation.ObjStr(tv, "solc"); v != "" && strings.ContainsAny(v, "0123456789") {
		return v, "record tool_versions.solc", pinNamedUnresolved, nil
	}
	return "", "", pinNamedUnresolved, nil
}

// harnessReportedCompilers collects the DISTINCT non-null solc_version
// strings the report lines carry (a run that mixed compilers shows as
// two values — every one is then compared against the pin).
func harnessReportedCompilers(raw []byte) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		v, perr := validation.ParseOrdered([]byte(line))
		if perr != nil || v.Kind != validation.Obj {
			continue
		}
		sv := validation.ObjAt(v, "solc_version")
		if sv.Kind != validation.Str || sv.S == "" || seen[sv.S] {
			continue
		}
		seen[sv.S] = true
		out = append(out, sv.S)
	}
	return out
}

// linksThenLog is the cli-side FORWARDING door onto the one implementation of
// the r20 F3 law for the INVARIANT_LINKS surface, invariants.LinksThenLog
// (r42 P3-b): the rung is campaign STATE (artifacts/invariant_links.json)
// exactly like a finding file is — a save that lands while its event is
// refused leaves the ledger asserting a verification nobody logged, and the
// half-landed rung is invisible to audit. The law's discipline (snapshot the
// file pre-write, hold the campaign process lock across the
// snapshot→save→log→restore window — the r21 F9 reason — and restore
// together on refusal) lives in the invariants package now. This name stays
// because this file's harness rungs and cmd_verify_autoprove.go's rung call
// it; it must remain a forwarder, never a second copy of the body.
func linksThenLog(c *state.Campaign, save func() error, log func() error) error {
	return invariants.LinksThenLog(c, save, log)
}
