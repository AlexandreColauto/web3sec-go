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
	"websec/internal/harness"
	"websec/internal/state"
	"websec/internal/validation"
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
