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
//     MapMinicertora(raw, exit_status, MspecRuleName(inv)) — which also
//     captures the proof sidecar for every attributed verdict line
//     (UNKNOWN included) — and every other run through
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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

import (
	"os/exec"

	"websec/internal/sandbox"
)

// harnessStdoutCap is the 1MB read cap on exec stdout files.
const harnessStdoutCap = 1 << 20

// verifyHarnessResult is cmd_verify's --harness-result branch.
func verifyHarnessResult(c *state.Campaign, a *verifyArgs, r *Runner) error {
	if a.execID == "" {
		return t14ExitErr(2,
			"verify --harness-result needs --exec EXEC-...\n")
	}
	links, err := invariants.LoadLinks(c)
	if err != nil {
		return err
	}
	entry, found := harnessInvEntry(links, a.harnessResult)
	if !found {
		return t14ExitErr(2, "verify: unknown invariant %s\n",
			validation.PyReprStr(a.harnessResult))
	}
	kind, err := harnessKindFor(c, a.harnessResult, a.kind)
	if err != nil {
		return err
	}
	rec, execDir, err := harnessExecRecord(c, a.execID)
	if err != nil {
		return err
	}
	raw, err := harnessExecStdout(execDir, rec)
	if err != nil {
		return err
	}
	scaffold, err := harnessScaffoldBytes(c, a.harnessResult, kind)
	if err != nil {
		return err
	}
	// r18 (A2, §6.2 of the integration doc): provenance was RECORDED but
	// never ENFORCED — a run compiled by a different solc than the
	// campaign's exec record pins bound its rung today. Now the mapper
	// compares the report lines' solc_version against the pinned
	// compiler (the --solc-path the command itself named, else the
	// record's tool_versions row) and REFUSES a mismatch. When no pin
	// is visible from either source the run proceeds, marked UNCHECKED
	// in the proof — honest, not silent.
	pin, pinSource, pinNamedUnresolved, pinErr := harnessCompilerPin(rec)
	if pinErr != nil {
		return pinErr
	}
	reported := harnessReportedCompilers(raw)
	if pin != "" && len(reported) > 0 {
		for _, v := range reported {
			if v != pin {
				return t14ExitErr(2,
					"verify: toolchain-mismatch for %s — the harness "+
						"reports solc %s, the exec pinned solc %s (%s); "+
						"rerun with a matching compiler (the provenance "+
						"is recorded, now it is also enforced)\n",
					a.harnessResult, v, pin, pinSource)
			}
		}
	}
	timedOut := harnessTimedOut(rec)
	// The minicertora mapper is exit-status aware: an int exit_status is
	// the run's own report, anything else (absent/null/big) is "unknown"
	// (-2), and MapMinicertora's negative floor refuses it — a run that
	// never reported a clean exit is never promoted. timedOut covers
	// -1 and the 128+N signal deaths, so -2 is the fail-open remainder.
	exitStatus := -2
	if v := objAt(rec, "exit_status"); v.Kind == validation.Int &&
		v.Big == "" {
		exitStatus = int(v.I)
	}
	k := invocationBound(harnessCommand(rec), kind)
	_ = pinSource
	ruleName := harness.MspecRuleName(a.harnessResult)
	// Validate renders from the same value the scaffold command rendered
	// from, so the re-render can only differ where the bytes really moved.
	inv := harnessInvValue(a.harnessResult, entry)
	rung, summary, proof, boundedK := harnessMapBound(kind, inv, raw, rec,
		scaffold, timedOut, k, exitStatus, ruleName)
	if proof.Kind == validation.Obj {
		// r19 P1 #3: there are THREE states, not two. A pin with NO
		// report lines carrying solc_version compared NOTHING — stamping
		// "checked against pinned" there was the same lie in reverse
		// (law 3: an unmade comparison is never reported as made).
		state := "unchecked (no compiler pin visible on this record)"
		// r20 F4: "checked" must mean the ATTRIBUTED line's own
		// solc_version agreed with the pin — a foreign rule line's
		// version checked the RUN, not this proof.
		avOK := false
		if proof.Kind == validation.Obj {
			// r21 F4: an EMPTY solc_version is exactly "carries no
			// version" — Kind alone resurrected the "checked" lie.
			if v := objAt(proof, "solc_version"); v.Kind == validation.Str &&
				v.S != "" {
				avOK = true
			}
		}
		switch {
		case pin != "" && len(reported) > 0 && avOK:
			state = "checked against pinned solc " + pin
		case pin != "" && len(reported) > 0 && !avOK:
			state = "checked at run level against pinned solc " + pin +
				" (the attributed line carries no solc_version of its own)"
		case pin != "":
			state = "unchecked (pin " + pin + " from " + pinSource +
				"; the attributed report lines carry no solc_version to " +
				"compare — nothing was verified)"
		}
		if pinNamedUnresolved != "" {
			state += " [note: the exec names --solc-path " +
				pinNamedUnresolved + " in a form this check could not " +
				"resolve; the pin above is NOT that binary]"
		}
		proof.O = validation.SetOrAppend(proof.O, "compiler_pin",
			validation.VStr(state))
	}
	entry.O = validation.SetOrAppend(entry.O, "verification",
		validation.VObj(harnessField(kind, rung, a.execID, boundedK,
			summary, proof)))
	hrunData := validation.VObj(
		// r21: kind rides the event so the audit backstop can back-check
		// the slot's kind too (additive to the event payload).
		validation.KV{K: "kind", V: validation.VStr(string(kind))},
		validation.KV{K: "rung", V: validation.VStr(rung)},
		validation.KV{K: "exec", V: validation.VStr(a.execID)},
		validation.KV{K: "invariant", V: validation.VStr(a.harnessResult)},
		validation.KV{K: "summary", V: validation.VStr(summary)},
		// r22 F3: the backstop can only back-check what the event
		// carries — k rides too (null = the run stated no bound).
		validation.KV{K: "bounded_k", V: func() validation.Value {
			if boundedK != nil {
				return validation.VInt(int64(*boundedK))
			}
			return validation.VNull()
		}()},
	)
	if err := linksThenLog(c, func() error {
		return harnessSaveEntry(c, links, a.harnessResult, entry)
	}, func() error {
		_, lerr := c.Log("harness_run", &a.harnessResult, &hrunData)
		return lerr
	}); err != nil {
		return err
	}
	// The rung (entry + event) is on record before the derived artifact is
	// attempted: the PoC is a view of the rung, so a refusal to bridge must
	// never cost the record of the run, and an I/O error here leaves a
	// campaign whose re-verify reproduces the file byte-for-byte.
	if kind == harness.MiniCertora && rung == harness.RungCounterexample {
		if err := harnessWriteBridgedPoc(c, a.harnessResult, raw, ruleName,
			r); err != nil {
			return err
		}
	}
	switch {
	case rung == harness.RungProvedBounded && boundedK != nil:
		fmt.Fprintf(r.Out, "%s: %s (%s, k=%d, %s)\n", a.harnessResult,
			rung, string(kind), *boundedK, a.execID)
	case rung == harness.RungProvedBounded:
		// The display k is sidecar-first: proved-bounded with a nil
		// bounded_k is a *valid* outcome (bounds.loop_bound absent,
		// non-int or too large for int64 — the mapper keeps its own
		// copy in proof.bounds), so read it from there instead of
		// dereferencing the convenience pointer. The k-less form below
		// is the last resort: same print shape as every other rung.
		if k, ok := proofLoopBoundText(proof); ok {
			fmt.Fprintf(r.Out, "%s: %s (%s, k=%s, %s)\n",
				a.harnessResult, rung, string(kind), k, a.execID)
		} else {
			fmt.Fprintf(r.Out, "%s: %s (%s, %s)\n", a.harnessResult,
				rung, string(kind), a.execID)
		}
	default:
		fmt.Fprintf(r.Out, "%s: %s (%s, %s)\n", a.harnessResult, rung,
			string(kind), a.execID)
	}
	return nil
}

// proofLoopBoundText is the proved-bounded display k read off the proof
// sidecar: proof.bounds.loop_bound when it is an integer (the exact
// decimal text, so a bound beyond int64 renders verbatim rather than
// losing digits). ok=false for a missing sidecar, a null/malformed
// bounds object, or a non-integer loop_bound.
func proofLoopBoundText(proof validation.Value) (string, bool) {
	lb := objAt(objAt(proof, "bounds"), "loop_bound")
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
func harnessInvValue(invID string, entry validation.Value) validation.Value {
	inv := entry
	inv.O = validation.SetOrAppend(
		append([]validation.KV(nil), entry.O...), "id",
		validation.VStr(invID))
	return inv
}

// harnessInvEntry is links["invariants"][invID] with presence.
func harnessInvEntry(links validation.Value, invID string) (validation.Value,
	bool) {
	if reg := objAt(links, "invariants"); reg.Kind == validation.Obj {
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
	reg := objAt(links, "invariants")
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
		return harness.Kind(flag), nil
	}
	events, err := c.Events()
	if err != nil {
		return "", err
	}
	prefix := "HARNESS-" + invID + "-"
	var kinds []string
	for _, ev := range events {
		if objStr(objAt(ev, "data"), "artifact_id") == "" ||
			objStr(ev, "type") != "harness_scaffold" {
			continue
		}
		aid := objStr(objAt(ev, "data"), "artifact_id")
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
		if objStr(e, "exec_id") == execID {
			return e, filepath.Join(c.ExecsDir, execID), nil
		}
	}
	return validation.VNull(), "", t14ExitErr(2,
		"verify: no exec %s in this campaign's exec ledger\n",
		validation.PyReprStr(execID))
}

// harnessExecStdout reads the run's captured stdout, capping the read at
// 1MB. r13: a record written under `--root .` stores a CWD-relative
// stdout_path; joining it back against execDir double-nests the path and
// a plainly-present capture was reported as "no captured stdout to map".
// The canonical location — <execDir>/stdout.log — is the audit's law
// (execs.go derives it the same way) and wins; the stored string is only
// a fallback. An unreadable file now says unreadable(path: errno), an
// empty record field still says nothing was captured.
func harnessExecStdout(execDir string, rec validation.Value) ([]byte, error) {
	p := objStr(rec, "stdout_path")
	candidates := []string{filepath.Join(execDir, "stdout.log")}
	if p != "" {
		if filepath.IsAbs(p) {
			candidates = []string{p, candidates[0]}
		} else {
			candidates = append(candidates, filepath.Join(execDir, p))
		}
	}
	var openErr error
	for _, cand := range candidates {
		fh, err := os.Open(cand)
		if err != nil {
			openErr = err
			continue
		}
		defer fh.Close()
		return io.ReadAll(io.LimitReader(fh, harnessStdoutCap))
	}
	if p == "" {
		return nil, t14ExitErr(2,
			"verify: exec %s has no captured stdout to map\n",
			validation.PyReprStr(objStr(rec, "exec_id")))
	}
	return nil, t14ExitErr(2,
		"verify: exec %s stdout file unreadable (%v)\n",
		validation.PyReprStr(objStr(rec, "exec_id")), openErr)
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
		if objStr(ev, "type") != "harness_scaffold" {
			continue
		}
		if objStr(objAt(ev, "data"), "artifact_id") != want {
			continue
		}
		ref = objStr(ev, "ref")
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
	p := objStr(art, "path")
	if !filepath.IsAbs(p) {
		p = filepath.Join(c.Root, p)
	}
	raw, err := os.ReadFile(p)
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
func harnessTimedOut(rec validation.Value) bool {
	if v := objAt(rec, "exit_status"); v.Kind == validation.Int &&
		v.Big == "" {
		return v.I == -1 || v.I >= 128
	}
	return false
}

// harnessCommand is the exec record's command string ("" when absent).
func harnessCommand(rec validation.Value) string {
	return objStr(rec, "command")
}

// boundFlagRe parses the invocation bound out of an exec command:
// halmos's --loop N, forge's --fuzz-runs N (both `--flag N` and
// `--flag=N`) and minicertora's --loop-bound N. Absent flags mean 0
// ("unstated"): the number only feeds display summaries, a minicertora
// timeout summary and forge's bounded_k fallback — the rung never depends
// on it, so a missed parse degrades to inconclusive-safe text, never to a
// wrong verdict. The boundary classes matter: `--loop` alone must not
// swallow `--loop-bound`'s digits as a separate flag, and `--loopx` must
// not parse at all.
var boundFlagRe = regexp.MustCompile(
	`--(?:loop(?:-bound)?|fuzz-runs)[= ](\d+)`)

// invocationBound is the MapRun k: the bound flag from the exec command,
// or 0 when the command names none.
func invocationBound(command string, kind harness.Kind) int {
	_ = kind
	m := boundFlagRe.FindStringSubmatch(command)
	if m == nil {
		return 0
	}
	n := 0
	for _, c := range []byte(m[1]) {
		n = n*10 + int(c-'0')
		if n > 1<<62 {
			return 0
		}
	}
	return n
}

// harnessMapBound runs the Decision 2b bound check around MapRun:
//
//   - a recorded hash (input_hashes or artifact_hashes) equal to the
//     stored scaffold's sha256 binds the run: harness.Validate re-renders
//     the scaffold from the CURRENT invariant claim and refuses with
//     "scaffold-degraded: <reason>" when anything outside the body window
//     moved — otherwise MapRun normally;
//   - a harness-named hash entry (H.t.sol / F.t.sol, T17's filenames, or
//     anything harness-named) with a different sha is a scaffold-bound
//     violation: rung inconclusive, the run's output is NOT used;
//   - no hash info at all: the run is unbound, so nothing can be bound to
//     it — Validate still judges the ON-DISK harness file against the
//     CURRENT claim (that file is the only artifact left) and drift
//     refuses with the same "scaffold-degraded: <reason>" arm; a file that
//     still matches maps normally with an "(unbound: harness file hash not
//     recorded)" summary suffix — the honest limitation.
//
// The failure ORDER is deliberate and pinned: the hash check runs first,
// then Validate, on BOTH arms. A hash proves WHICH bytes ran (a foreign
// hash refutes the run outright); Validate proves the bytes still match the
// CURRENT claim (the statement may be edited long after the run). Both are
// needed, they refuse differently, and each refusal names the step that
// stopped it. Unbound means no hash proved which bytes ran, so the
// validation is a claim about the FILE, not about the run — which is
// exactly why it must still fire: the file is the only artifact left to
// check, and without the re-render a drifted claim or a damaged frame would
// land a rung on bytes nobody can vouch for. Validate's input is the same
// file harnessScaffoldBytes read before the rail, so an unreadable or
// missing file never reaches either arm: that stays the exit-2 path it
// always was, unchanged.
//
// bounded_k is set only for proved-bounded (parsed k=<n> else the
// invocation k); every other rung carries null.
//
// The three G8 kinds share the bound check above the mapping seam. Below
// it the decision belongs to the kind: halmos/forge-fuzz go through
// MapRun (minicertora included, for the timedOut branch only), while an
// untimed minicertora run goes through MapMinicertora — its exit status
// and scaffold-pinned rule name are the mapper's business, not the
// dispatcher's. The proof sidecar is non-null exactly when a mapper
// attributed a verdict line; the bound-violation and scaffold-degraded
// refusals below never map, so they never carry one.
func harnessMapBound(kind harness.Kind, inv validation.Value, raw []byte,
	rec validation.Value, scaffold []byte, timedOut bool, k, exitStatus int,
	ruleName string) (rung, summary string, proof validation.Value,
	boundedK *int) {
	sum := sha256.Sum256(scaffold)
	hexSum := hex.EncodeToString(sum[:])
	hashes, harnessNamed := harnessRecordedHashes(rec)
	for _, h := range hashes {
		if h == hexSum {
			// The run is bound to these bytes; Validate now re-renders
			// the scaffold from the CURRENT claim and compares everything
			// outside the body window. A claim that drifted away from
			// the bytes that ran must never be attributed a rung: the
			// output proved a claim nobody is making any more.
			if err := harness.Validate(kind, inv, scaffold); err != nil {
				return harness.RungInconclusive,
					"scaffold-degraded: " + scaffoldDegradedReason(err),
					validation.VNull(), nil
			}
			return harnessMappedKind(kind, raw, timedOut, k, exitStatus,
				ruleName, "")
		}
	}
	if harnessNamed {
		return harness.RungInconclusive,
			"scaffold-bound violation: harness file hash differs " +
				"from stored scaffold", validation.VNull(), nil
	}
	// Unbound: no recorded hash proved WHICH bytes ran, so no run can be
	// refuted on its hash — but the on-disk harness file is still an
	// artifact this rail can judge, and here it is the ONLY one. Validate
	// re-renders it from the CURRENT claim and refuses with the very same
	// "scaffold-degraded:" wording the bound arm uses: a file that no
	// longer matches the claim on record must never be attributed a rung,
	// hash proof or not. The bytes were read by harnessScaffoldBytes
	// before this rail runs, so an unreadable or missing file is still the
	// exit-2 path it always was (both arms, unchanged); Validate only ever
	// judges bytes that were read.
	if err := harness.Validate(kind, inv, scaffold); err != nil {
		return harness.RungInconclusive,
			"scaffold-degraded: " + scaffoldDegradedReason(err),
			validation.VNull(), nil
	}
	return harnessMappedKind(kind, raw, timedOut, k, exitStatus, ruleName,
		" (unbound: harness file hash not recorded)")
}

// scaffoldDegradedReason reduces a harness.Validate error to the
// scaffold-line reason the refusal text carries. Validate's messages have
// two fixed shapes — lineDiffErr's "harness: scaffold-bound: <reason>
// (<region> line <n>: want <q> got <q>)" and BodyRegion's "harness:
// scaffold-bound: missing BODY start marker" (plus its siblings) — so the
// drift CLASS is what sits between the prefix and the first region detail;
// the quoted want/got bytes are diagnostics, not the refusal. Anything
// unrecognized rides whole: a refusal must never lose its reason.
func scaffoldDegradedReason(err error) string {
	msg := strings.TrimPrefix(err.Error(), "harness: ")
	msg = strings.TrimPrefix(msg, "scaffold-bound: ")
	for _, anchor := range []string{" (pre-body line ", " (post-body line "} {
		if i := strings.Index(msg, anchor); i >= 0 {
			return msg[:i]
		}
	}
	return msg
}

// harnessMappedKind dispatches one bound run to its kind's mapper: an
// untimed minicertora run through MapMinicertora (exit status + rule
// name), everything else — including a timed-out minicertora run, which
// must never reach the JSONL mapper — through MapRun.
//
// The timed-out minicertora run is the one kind whose MapRun summary would
// lie: MapRun renders "timeout after <k>s", but the caller-passed k is the
// loop bound, not a number of seconds. Step 0 gives it its own wording,
// produced here BEFORE the MapRun call: "inconclusive (no clean completion;
// loop bound was N)" when the invocation names a bound, the clause-free
// "inconclusive (no clean completion)" otherwise. halmos/forge-fuzz keep
// MapRun's byte-pinned "timeout after %ds".
func harnessMappedKind(kind harness.Kind, raw []byte, timedOut bool, k,
	exitStatus int, ruleName, suffix string) (string, string,
	validation.Value, *int) {
	if kind == harness.MiniCertora && timedOut {
		summary := "inconclusive (no clean completion)"
		if k > 0 {
			summary = fmt.Sprintf(
				"inconclusive (no clean completion; loop bound was %d)",
				k)
		}
		return harness.RungInconclusive, summary + suffix,
			validation.VNull(), nil
	}
	if kind == harness.MiniCertora && !timedOut {
		rung, summary, proof, bk := harness.MapMinicertora(raw, exitStatus,
			ruleName)
		return rung, summary + suffix, proof, bk
	}
	rung, summary, bk := harnessMapped(kind, raw, timedOut, k, suffix)
	return rung, summary, validation.VNull(), bk
}

// harnessMapped runs MapRun and attaches bounded_k for proved-bounded.
func harnessMapped(kind harness.Kind, raw []byte, timedOut bool, k int,
	suffix string) (string, string, *int) {
	rung, summary := harness.MapRun(kind, raw, timedOut, k)
	summary += suffix
	if rung != harness.RungProvedBounded {
		return rung, summary, nil
	}
	bk := harness.BoundK(kind, raw, k)
	return rung, summary, &bk
}

// harnessRecordedHashes collects every recorded file hash from the exec
// record (input_hashes plus artifact_hashes values) and whether any key
// names the harness file (T17's H.t.sol / F.t.sol, the third kind's
// INV.mspec, or anything harness-named — the runs that hashed the file
// they actually executed). The .mspec suffix matters: without it a
// minicertora run that hashed a foreign spec file would read as "no hash
// info" and map normally, which is exactly the bind Decision 2b refuses.
func harnessRecordedHashes(rec validation.Value) (hashes []string,
	harnessNamed bool) {
	for _, key := range []string{"input_hashes", "artifact_hashes"} {
		m := objAt(rec, key)
		if m.Kind != validation.Obj {
			continue
		}
		for _, kv := range m.O {
			if kv.V.Kind == validation.Str && kv.V.S != "" {
				hashes = append(hashes, kv.V.S)
			}
			base := strings.ToLower(filepath.Base(kv.K))
			if base == "h.t.sol" || base == "f.t.sol" ||
				strings.HasSuffix(base, ".mspec") ||
				strings.Contains(base, "harness") {
				harnessNamed = true
			}
		}
	}
	return hashes, harnessNamed
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
			tv0 := objAt(objAt(rec, "environment"), "tool_versions")
			if v0 := objStr(tv0, "solc"); v0 == "" {
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
	tv := objAt(objAt(rec, "environment"), "tool_versions")
	if v := objStr(tv, "solc"); v != "" && strings.ContainsAny(v, "0123456789") {
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
		sv := objAt(v, "solc_version")
		if sv.Kind != validation.Str || sv.S == "" || seen[sv.S] {
			continue
		}
		seen[sv.S] = true
		out = append(out, sv.S)
	}
	return out
}

// linksThenLog is the r20 F3 law for the INVARIANT_LINKS surface: the
// rung is campaign STATE (artifacts/invariant_links.json) exactly like
// a finding file is — a save that lands while its event is refused
// leaves the ledger asserting a verification nobody logged, and the
// half-landed rung is invisible to audit. Same discipline as
// findings.SaveThenLog: snapshot the file pre-write, restore together
// on refusal. (SaveThenLogMany's sibling, one fewer package import.)
func linksThenLog(c *state.Campaign, save func() error, log func() error) error {
	path := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	// r21 F9: the links file is a SHARED multi-key registry — a
	// whole-file restore over a sibling writer's concurrent change would
	// revert its rung while its event stands. Hold the campaign process
	// lock across the snapshot→save→log→restore window (the same lock
	// Log itself takes, re-entrant by depth).
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	prevRaw, perr := os.ReadFile(path)
	had := perr == nil
	if perr != nil && !os.IsNotExist(perr) {
		return perr
	}
	if err := save(); err != nil {
		return err
	}
	if err := log(); err != nil {
		rerr := error(nil)
		if had {
			rerr = os.WriteFile(path, prevRaw, 0o644)
		} else {
			rerr = os.Remove(path)
		}
		if rerr != nil {
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — the links "+
				"file holds a rung with no event; repair by hand)", err,
				rerr)
		}
		return err
	}
	return nil
}
