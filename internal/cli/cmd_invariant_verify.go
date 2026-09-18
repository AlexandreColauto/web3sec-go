package cli

// cmd_invariant_verify: `webv2 invariant-verify <campaign> <inv_id>
// (--artifact ART-... | --exec EXEC-...)` — record an OPERATOR ATTESTATION
// that a registered artifact attributes a model-derived invariant, moving the
// verification axis to CHECKED_AGAINST_CODE (cli.py cmd_invariant_verify
// verbatim: two ways to name the recording artifact; --exec registers the
// exec's captured output through the same register_or_refresh seam, so "write
// one test that asserts the invariant" is one command).
//
// What this command does and does not establish: it records that an operator
// cited an artifact whose BYTES name the invariant or one of its applies_to
// targets. That textual reference is ATTRIBUTION ONLY — it is not mechanical
// proof of the statement, and CHECKED_AGAINST_CODE is kept as the stored
// status for compatibility with the existing gates. The provenance is written
// explicitly (verification_method "operator-attestation" on the registry
// entry and on the invariant.verified event), and a successful run appends a
// stderr disclosure saying so. The stdout summary is unchanged.
//
// Error rendering: Python's cmd prints its own messages and exits 2, and
// the final verify's KeyError is rendered by str(exc) = repr(message) — the
// Go errors carry the bare message, so the CLI applies PyReprStr.

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// unknownArtifactReason reports whether err is state's unknown-artifact
// refusal (B6a). It is a TYPE test, not a copy match: the pinned text
// ("unknown artifact '<id>'") is owned by the Python-parity tests in
// internal/state, and this heal pointer must not break the day that copy is
// ever reworded. errors.As walks the chain, so a future wrapper that %w's the
// refusal still lands here.
func unknownArtifactReason(err error) bool {
	var uae *state.UnknownArtifactError
	return errors.As(err, &uae)
}

// artifactRegistered reports whether the campaign's registry already holds a
// row for id — B6a's second condition: the heal line tells the operator to
// register a PATH, which is advice only for a value that is not already a
// registered id. Today VerifyInvariantStatement probes c.Artifact FIRST
// (internal/invariants/verify.go:78), so an unknown-artifact failure and an
// unregistered id are one event; the check is kept as the belt-and-braces
// half so a future reordering of that function cannot turn this line into
// "register the artifact you already registered". A read failure answers
// false, i.e. keeps the advice — that cannot be an unreadable store, since
// the reason test above only fires for a refusal c.Artifact itself produced;
// a failure here is a concurrent prune, and the advice is right for it.
func artifactRegistered(c *state.Campaign, id string) bool {
	_, err := c.Artifact(id)
	return err == nil
}

func runInvariantVerify(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "invariant-verify", args) {
		return 0
	}

	ensureSeams()
	artifact, execID := "", ""
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--artifact" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			artifact = args[i+1]
			i++
		case strings.HasPrefix(a, "--artifact="):
			artifact = strings.TrimPrefix(a, "--artifact=")
		case a == "--exec" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			execID = args[i+1]
			i++
		case strings.HasPrefix(a, "--exec="):
			execID = strings.TrimPrefix(a, "--exec=")
		case a == "--artifact":
			return r.fail(root, argErrf("invariant-verify",
				"argument --artifact: expected one argument"))
		case a == "--exec":
			return r.fail(root, argErrf("invariant-verify",
				"argument --exec: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 2 {
		missing := []string{}
		if len(pos) < 1 {
			missing = append(missing, "campaign")
		}
		if len(pos) < 2 {
			missing = append(missing, "inv_id")
		}
		return r.fail(root, requiredErrf("invariant-verify", missing...))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	invID := pos[1]
	if artifact != "" && execID != "" {
		fmt.Fprintf(r.Err, "invariant-verify: pass exactly one of --artifact "+
			"or --exec (got both: %s and %s)\n", artifact, execID)
		return 2
	}
	if artifact == "" && execID == "" {
		fmt.Fprintln(r.Err, "invariant-verify: pass --artifact ART-... or "+
			"--exec EXEC-... (one is required)")
		return 2
	}
	if execID != "" {
		var code int
		artifact, code = resolveExecArtifact(c, invID, execID, r)
		if code != 0 {
			return code
		}
	}
	entry, err := invariants.VerifyInvariantStatement(c, invID, artifact)
	if err != nil {
		// Byte-discipline: this line and its inner text are EXACT-pinned
		// (state's KeyError copy, artifacts_test.go:339/:497/:612) — the
		// heal pointer below is an APPENDED stderr line, never a reword.
		fmt.Fprintf(r.Err, "invariant verify failed: %s\n",
			validation.PyReprStr(err.Error()))
		// B6a heal pointer: the operator named an artifact the registry does
		// not hold, and `artifact-register` is the only sanctioned mint —
		// the pin's own words ("unknown artifact 'X'") say what is wrong but
		// not what to run. Printed only for THAT reason: an unknown
		// invariant, a relevance refusal or an unreadable store is not a
		// missing registration, and telling its operator to register a path
		// would be advice about a different failure.
		if unknownArtifactReason(err) && !artifactRegistered(c, artifact) {
			// The value the operator passed is reproduced verbatim as the
			// path argument (PyReprStr quotes it, so a spaced path stays
			// copyable). The copy says "the artifact id it prints" and
			// never names a prefix: the minted id's prefix follows the
			// --kind (first3Upper(kind)+"-"+hex, state.RegisterArtifact),
			// so `--kind invariants` returns an INV- id — promising an
			// ART- shape here would have been a wrong copy (round-2
			// review). `--kind invariants` is a value of the schema's
			// closed kind enum (campaign_state.schema.json:75), which is
			// also the discoverability fix for the flag B2 validates early.
			fmt.Fprintf(r.Err, "invariant-verify: register it first — "+
				"`webv2 artifact-register %s %s --kind invariants` — then "+
				"pass the artifact id it prints\n", c.CampaignID,
				validation.PyReprStr(artifact))
		}
		return 2
	}
	fmt.Fprintf(r.Out, "%s: CHECKED_AGAINST_CODE (artifact %s)\n", invID,
		validation.ObjStr(entry, "verified_by"))
	// The verdict above is an attestation, not a mechanical proof: say so on
	// stderr so the summary line stays byte-compatible for existing callers.
	fmt.Fprintln(r.Err, "invariant-verify: operator attestation recorded; "+
		"artifact attribution is not mechanical proof")
	return 0
}

// resolveExecArtifact is the --exec half: validate the referenced exec and
// register (or refresh) its captured output as the check artifact.
func resolveExecArtifact(c *state.Campaign, invID, execID string,
	r *Runner) (string, int) {
	links, err := invariants.LoadLinks(c)
	if err != nil {
		return "", r.withErr(c.Root, func() error { return err })
	}
	reg := validation.ObjAt(links, "invariants")
	if reg.Kind != validation.Obj || !hasKeyCLI(reg, invID) {
		fmt.Fprintf(r.Err, "invariant verify failed: unknown invariant %s\n",
			validation.PyReprStr(invID))
		return "", 2
	}
	execs, err := state.AllExecs(c)
	if err != nil {
		return "", r.withErr(c.Root, func() error { return err })
	}
	var rec validation.Value
	found := false
	for _, e := range execs {
		if validation.ObjStr(e, "exec_id") == execID {
			rec, found = e, true
			break
		}
	}
	if !found {
		fmt.Fprintf(r.Err, "invariant-verify: no exec %s in this campaign's "+
			"exec ledger\n", validation.PyReprStr(execID))
		return "", 2
	}
	refused := containsStrCLI(strListCLI(validation.ObjAt(validation.ObjAt(rec, "policy_verdict"),
		"violations")), "execution-refused")
	if !pyTruthyCLI(validation.ObjAt(rec, "finished_at")) || refused {
		why := "no finished_at"
		if refused {
			why = "refused by policy"
		}
		fmt.Fprintf(r.Err, "invariant-verify: exec %s is incomplete (%s) — "+
			"only a run that finished can record a check\n",
			validation.PyReprStr(execID), why)
		return "", 2
	}
	outPath := validation.ObjStr(rec, "stdout_path")
	if !isFile(outPath) {
		if alt := validation.ObjStr(rec, "stderr_path"); isFile(alt) {
			outPath = alt
		}
	}
	if !isFile(outPath) {
		fmt.Fprintf(r.Err, "invariant-verify: exec %s has no captured output "+
			"to register\n", validation.PyReprStr(execID))
		return "", 2
	}
	// The exec-relevance gate: the cited exec must have RUN something bound to
	// this invariant's applies_to contracts. A full-suite log names every
	// contract it printed, so the recorded command decides — and the refusal
	// lands HERE, before RegisterOrRefresh, so a refused citation mints no
	// durable "checked against code" row asserting a verification that was
	// just refused (the defect-6 record class).
	if ok, reason := invariants.ExecTouchesInvariant(c, invID, execID); !ok {
		fmt.Fprintf(r.Err, "invariant verify failed: cited exec %s does not "+
			"target any applies_to contract of %s (%s)\n", execID, invID,
			reason)
		return "", 2
	}
	note := fmt.Sprintf("invariant %s checked against code (exec %s)", invID,
		execID)
	reason := fmt.Sprintf("exec %s output registered as the check artifact",
		execID)
	aid, err := c.RegisterOrRefresh("other", outPath, note, nil, reason)
	if err != nil {
		return "", r.withErr(c.Root, func() error { return err })
	}
	return aid, 0
}

func isFile(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// hasKeyCLI is dict membership for a JSON object value.
func hasKeyCLI(v validation.Value, key string) bool {
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}

// pyTruthyCLI is Python truthiness for the shapes the CLI inspects.
func pyTruthyCLI(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0 || v.Big != ""
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

// strListCLI is [str(x) for x in value] for a JSON array.
func strListCLI(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		out = append(out, scalarStr(e))
	}
	return out
}

// containsStrCLI is Python's `x in list`.
func containsStrCLI(items []string, want string) bool {
	for _, it := range items {
		if it == want {
			return true
		}
	}
	return false
}

func init() {
	register(command{ord: 22, name: "invariant-verify",
		line: "invariant-verify <campaign> <inv_id>  record an operator " +
			"attestation (attribution, not mechanical proof)",
		run: runInvariantVerify})
}
