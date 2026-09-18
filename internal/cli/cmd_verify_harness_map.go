package cli

// cmd_verify_harness_map: the bind's rung decision and the compiler-pin
// provenance enforcement (moved verbatim from cmd_verify_harness.go).

import (
	"context"
	"os/exec"
	"strings"
	"time"
	"websec/internal/harness"
	"websec/internal/sandbox"
	"websec/internal/validation"
)

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
