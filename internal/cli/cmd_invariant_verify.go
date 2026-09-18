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
	"fmt"
	"os"
	"strings"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

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
		// The exec-relevance gate: the cited exec must have RUN something
		// bound to this invariant's applies_to contracts. A full-suite log
		// names every contract it printed, so the recorded command decides —
		// and the refusal lands before the verification axis can move.
		if ok, reason := invariants.ExecTouchesInvariant(c, invID, execID); !ok {
			fmt.Fprintf(r.Err, "invariant verify failed: cited exec %s does not "+
				"target any applies_to contract of %s (%s)\n", execID, invID,
				reason)
			return 2
		}
	}
	entry, err := invariants.VerifyInvariantStatement(c, invID, artifact)
	if err != nil {
		fmt.Fprintf(r.Err, "invariant verify failed: %s\n",
			validation.PyReprStr(err.Error()))
		return 2
	}
	fmt.Fprintf(r.Out, "%s: CHECKED_AGAINST_CODE (artifact %s)\n", invID,
		objStr(entry, "verified_by"))
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
	reg := objAt(links, "invariants")
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
		if objStr(e, "exec_id") == execID {
			rec, found = e, true
			break
		}
	}
	if !found {
		fmt.Fprintf(r.Err, "invariant-verify: no exec %s in this campaign's "+
			"exec ledger\n", validation.PyReprStr(execID))
		return "", 2
	}
	refused := containsStrCLI(strListCLI(objAt(objAt(rec, "policy_verdict"),
		"violations")), "execution-refused")
	if !pyTruthyCLI(objAt(rec, "finished_at")) || refused {
		why := "no finished_at"
		if refused {
			why = "refused by policy"
		}
		fmt.Fprintf(r.Err, "invariant-verify: exec %s is incomplete (%s) — "+
			"only a run that finished can record a check\n",
			validation.PyReprStr(execID), why)
		return "", 2
	}
	outPath := objStr(rec, "stdout_path")
	if !isFile(outPath) {
		if alt := objStr(rec, "stderr_path"); isFile(alt) {
			outPath = alt
		}
	}
	if !isFile(outPath) {
		fmt.Fprintf(r.Err, "invariant-verify: exec %s has no captured output "+
			"to register\n", validation.PyReprStr(execID))
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
