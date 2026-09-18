package sequencepoc

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/reproduction"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// sandboxRun executes one command under a sandbox profile. It is the seam
// for tests (Python monkeypatches SB.Sandbox): NewSandbox performs the
// profile-availability check before any exec.
var sandboxRun = func(c *state.Campaign, profile, command string,
	opts sandbox.RunOpts) (validation.Value, error) {
	sb, err := sandbox.NewSandbox(c, profile)
	if err != nil {
		return validation.VNull(), err
	}
	return sb.Run(command, opts)
}

// RunSequenceFunc is the run_sequence indirection the CLI calls. It mirrors
// cli.py's `SEQ.run_sequence` module attribute, which the Python tests
// monkeypatch; Go tests swap it to assert the CLI's call shape without a
// docker daemon.
var RunSequenceFunc = RunSequence

// RunSequenceOpts mirrors run_sequence's keyword-only arguments.
type RunSequenceOpts struct {
	FindingID *string
	Workdir   *string
}

// RunSequence is run_sequence: validate the spec, execute it under
// fork-runner, stage the result artifacts into the exec output tree, log
// sequence.run, and (when a finding is given) record the T4 attempt.
// Returns the EXEC record.
func RunSequence(c *state.Campaign, specPath string,
	opts RunSequenceOpts) (validation.Value, error) {
	spec, err := LoadSequenceSpec(specPath)
	if err != nil {
		return validation.VNull(), err
	}
	// Pass-2 M1: the staged spec.json permanently claims
	// spec['finding_id'] while the attempt lands on `finding_id` — a
	// mismatch silently attributes A's PoC to B. Fail loud.
	claimed := validation.ObjStr(spec, "finding_id")
	if opts.FindingID != nil && claimed != "" && claimed != *opts.FindingID {
		return validation.VNull(), specErrf(
			"sequence spec claims finding %s but was run for finding %s — "+
				"refusing to attribute the attempt to the wrong finding (run "+
				"with --finding matching the spec's finding_id)",
			validation.PyReprStr(claimed),
			validation.PyReprStr(*opts.FindingID))
	}
	wd, err := sequenceWorkdir(c, spec, opts)
	if err != nil {
		return validation.VNull(), err
	}
	cmd, err := BuildCommand(spec, "/wd")
	if err != nil {
		return validation.VNull(), err
	}
	rec, err := sandboxRun(c, "fork-runner", cmd,
		sequenceRunOpts(wd, opts))
	if err != nil {
		return validation.VNull(), err
	}
	execID := validation.ObjStr(rec, "exec_id")
	ref := execID
	data := validation.VObj(
		validation.KV{K: "spec_id", V: validation.VStr(validation.ObjStr(spec, "spec_id"))},
		validation.KV{K: "steps", V: validation.VInt(
			int64(len(listOf(validation.ObjAt(spec, "steps")))))},
		validation.KV{K: "exit_status", V: validation.ObjAt(rec, "exit_status")},
	)
	if _, err := c.Log("sequence.run", &ref, &data); err != nil {
		return validation.VNull(), err
	}
	if err := stageSequenceArtifacts(wd,
		filepath.Dir(validation.ObjStr(rec, "stdout_path"))); err != nil {
		return validation.VNull(), err
	}
	if opts.FindingID != nil {
		if err := recordTier4(c, spec, rec, *opts.FindingID); err != nil {
			return validation.VNull(), err
		}
	}
	return rec, nil
}

// sequenceWorkdir resolves run_sequence's workdir (default:
// execs/seqwork-<spec_id>), creates it, and stages the canonical spec.json.
func sequenceWorkdir(c *state.Campaign, spec validation.Value,
	opts RunSequenceOpts) (string, error) {
	wd := ""
	explicit := opts.Workdir != nil
	if explicit {
		wd = *opts.Workdir
	} else {
		wd = filepath.Join(c.ExecsDir, "seqwork-"+validation.ObjStr(spec, "spec_id"))
	}
	// r5 (critic issue 7): a workdir the OPERATOR named is a promise about
	// an existing place — MkdirAll'ing a typo invents a directory, hides
	// the mistake, and runs the PoC somewhere unexpected. The campaign's
	// OWN default path keeps creating itself (it is derived, not typed).
	if explicit {
		if st, err := os.Stat(wd); err != nil || !st.IsDir() {
			return "", fmt.Errorf(
				"workdir %s does not exist — create it or drop the flag; "+
					"sequence run will not invent a directory the operator "+
					"typed", wd)
		}
	} else if err := os.MkdirAll(wd, 0o755); err != nil {
		return "", err
	}
	// provenance: input_hashes
	if err := os.WriteFile(filepath.Join(wd, "spec.json"),
		CanonicalJSON(spec), 0o644); err != nil {
		return "", err
	}
	return wd, nil
}

// sequenceRunOpts is run_sequence's sandbox options. The operator's fork
// endpoint is forwarded into the container; sandbox._container_argv applies
// setdefault, so an explicit value wins while an unset var preserves the
// historic default byte-identically. run_sequence passes no timeout, so the
// call takes Sandbox.run's default (300s) — spelled out here so the seam
// tests can see it.
func sequenceRunOpts(wd string, opts RunSequenceOpts) sandbox.RunOpts {
	runOpts := sandbox.RunOpts{Workdir: &wd, FindingID: opts.FindingID,
		Timeout: 300}
	if forkRPC, ok := os.LookupEnv("FORK_RPC_URL"); ok {
		runOpts.Env = []sandbox.EnvVar{{Key: "FORK_RPC_URL", Value: forkRPC}}
	}
	return runOpts
}

// stageSequenceArtifacts copies the result artifacts from the run workdir
// into the exec output tree.
func stageSequenceArtifacts(wd, outDir string) error {
	for _, name := range []string{"sequence_result.json", "spec.json"} {
		src := filepath.Join(wd, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		body, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outDir, name), body,
			0o644); err != nil {
			return err
		}
	}
	return nil
}

// recordTier4 is run_sequence's attempt/mint tail: exit 0 mints E5
// fork-test evidence, anything else records a failed logic attempt.
func recordTier4(c *state.Campaign, spec, rec validation.Value,
	findingID string) error {
	specID := validation.ObjStr(spec, "spec_id")
	nSteps := len(listOf(validation.ObjAt(spec, "steps")))
	tier, etype := "T4", "fork-test"
	if exitIsZero(validation.ObjAt(rec, "exit_status")) {
		_, err := reproduction.AttemptAndMint(c, findingID,
			validation.ObjStr(rec, "exec_id"), fmt.Sprintf(
				"sequence PoC %s (%d steps) on the pinned fork", specID,
				nSteps), &tier, &etype)
		return err
	}
	failure, t4 := "logic", "T4"
	execID := validation.ObjStr(rec, "exec_id")
	_, err := reproduction.RecordAttempt(c, findingID, "failed",
		reproduction.RecordOpts{FailureClass: &failure, Tier: &t4,
			ExecID: &execID, Notes: fmt.Sprintf(
				"sequence PoC %s exited %s", specID,
				validation.PyStr(validation.ObjAt(rec, "exit_status")))})
	return err
}

// exitIsZero is `rec.get("exit_status") == 0` with Python's None/False
// semantics (None == 0 is false; False == 0 is true).
func exitIsZero(v validation.Value) bool {
	switch v.Kind {
	case validation.Int:
		if v.Big != "" {
			return v.Big == "0"
		}
		return v.I == 0
	case validation.Flt:
		return v.F == 0
	case validation.Bool:
		return !v.B
	}
	return false
}

// resultForExec is _result_for_exec: load + schema-validate the result
// artifact staged in the exec output tree. Returns (data, "") or
// (Null, reason) — degrades, never raises.
func resultForExec(campaign *state.Campaign,
	execRec validation.Value) (validation.Value, string) {
	if execRec.Kind != validation.Obj {
		return validation.VNull(), "exec record is not an object"
	}
	sp := validation.ObjAt(execRec, "stdout_path")
	if sp.Kind != validation.Str || sp.S == "" {
		return validation.VNull(), "exec record has no stdout_path — cannot " +
			"locate the exec output dir"
	}
	outDir := filepath.Dir(sp.S)
	if !isRelativeTo(outDir, campaign.Dir) {
		return validation.VNull(), "exec output dir is outside the campaign " +
			"tree — refusing to honor it"
	}
	p := filepath.Join(outDir, "sequence_result.json")
	if _, err := os.Stat(p); err != nil {
		return validation.VNull(), "no sequence_result.json in the exec " +
			"output dir"
	}
	data, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull(), "sequence_result.json unreadable: " + err.Error()
	}
	if data.Kind != validation.Obj {
		return validation.VNull(), "sequence_result.json is not an object"
	}
	if err := validation.Validate(data, "sequence_result", 1); err != nil {
		return validation.VNull(), "sequence_result.json schema violation: " +
			err.Error()
	}
	return data, ""
}

// isRelativeTo is Path(child).resolve().is_relative_to(Path(parent).resolve()).
func isRelativeTo(child, parent string) bool {
	c, err1 := resolveResilient(child)
	p, err2 := resolveResilient(parent)
	if err1 != nil || err2 != nil {
		return false
	}
	if c == p {
		return true
	}
	return strings.HasPrefix(c, p+string(os.PathSeparator))
}

// resolveResilient is Path.resolve() with strict=False: resolve the longest
// existing prefix (following symlinks) and keep the rest verbatim.
func resolveResilient(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rest := []string{}
	cur := filepath.Clean(abs)
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(append([]string{resolved}, rest...)...), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = append([]string{filepath.Base(cur)}, rest...)
		cur = parent
	}
}

// VerifySequenceCoverage is verify_sequence_coverage: did the executed
// result cover the finding's declared exploit_sequence? Pure function of
// (finding, exec record); never raises on malformed artifacts. Vacuous pass
// for non-sequence-required findings.
func VerifySequenceCoverage(campaign *state.Campaign, finding,
	execRec validation.Value) (bool, []string) {
	if finding.Kind != validation.Obj {
		return false, []string{"finding is not an object"}
	}
	if seq := validation.ObjAt(finding, "exploit_sequence"); seq.Kind != validation.Null &&
		seq.Kind != validation.Arr {
		return false, []string{"declared exploit_sequence is not a list"}
	}
	if !IsSequenceRequired(finding) {
		return true, nil
	}
	result, errText := resultForExec(campaign, execRec)
	if errText != "" {
		return false, []string{errText}
	}
	outDir := filepath.Dir(validation.ObjStr(execRec, "stdout_path"))
	spec, readErr := validation.ReadJson(filepath.Join(outDir, "spec.json"))
	if readErr != nil {
		spec = validation.VNull()
	}
	if spec.Kind != validation.Obj {
		return false, []string{"no staged spec.json in the exec output dir " +
			"— cannot bind the result to an executed spec"}
	}
	reasons := coverageReasons(campaign, finding, result, spec)
	return len(reasons) == 0, reasons
}

// coverageReasons is verify_sequence_coverage's reason ladder once the
// result and the staged spec are both readable.
func coverageReasons(campaign *state.Campaign, finding, result,
	spec validation.Value) []string {
	var reasons []string
	actualHash := SpecHash(spec)
	if got := validation.ObjAt(result, "spec_hash"); got.Kind != validation.Str ||
		got.S != actualHash {
		reasons = append(reasons, fmt.Sprintf(
			"result does not bind to the executed spec (hash %s != %s)",
			validation.PyStr(validation.ObjAt(result, "spec_hash")), actualHash))
	}
	declared := listOf(validation.ObjAt(finding, "exploit_sequence"))
	rawSteps := validation.ObjAt(result, "steps")
	executed := listOf(rawSteps)
	if validation.PyTruthy(rawSteps) && rawSteps.Kind != validation.Arr {
		return []string{"executed steps in sequence_result.json is not a list"}
	}
	if len(executed) < len(declared) {
		reasons = append(reasons, fmt.Sprintf("executed %d steps but the "+
			"declared exploit_sequence has %d", len(executed),
			len(declared)))
	}
	declaredActors := actorSet(declared)
	executedActors := actorSet(executed)
	if len(executedActors) < len(declaredActors) {
		reason := fmt.Sprintf("executed steps use %d distinct "+
			"actor(s) but the declared exploit needs %d — a single-account "+
			"PoC cannot cover a multi-actor exploit", len(executedActors),
			len(declaredActors))
		if missing := missingActors(declared, executedActors); len(missing) > 0 {
			reason += "; missing: " + strings.Join(missing, ", ")
		}
		reasons = append(reasons, reason)
	}
	rawSpecSteps := validation.ObjAt(spec, "steps")
	specSteps := listOf(rawSpecSteps)
	if validation.PyTruthy(rawSpecSteps) && rawSpecSteps.Kind != validation.Arr {
		return []string{"staged spec.json steps is not a list"}
	}
	reasons = append(reasons, stepReasons(executed, specSteps)...)
	reasons = append(reasons, assertionReasons(result)...)
	if validation.ObjStr(result, "overall") != "pass" {
		reasons = append(reasons, "result overall is not 'pass'")
	}
	return reasons
}

// stepReasons checks each executed step against the staged spec's
// expect_revert expectation.
func stepReasons(executed, specSteps []validation.Value) []string {
	var reasons []string
	for i, s := range executed {
		if i >= len(specSteps) {
			break
		}
		if s.Kind != validation.Obj || specSteps[i].Kind != validation.Obj {
			reasons = append(reasons, fmt.Sprintf(
				"step %d record is malformed", i+1))
			continue
		}
		wantRevert := validation.PyTruthy(validation.ObjAt(specSteps[i], "expect_revert"))
		status := validation.ObjAt(s, "status")
		reverted := status.Kind == validation.Str && status.S == "revert"
		switch {
		case wantRevert && !reverted:
			reasons = append(reasons, fmt.Sprintf(
				"step %d was expected to revert but the result records "+
					"status %s", i+1, validation.PyRepr(status)))
		case wantRevert && !validation.PyTruthy(validation.ObjAt(s, "revert_reason")):
			reasons = append(reasons, fmt.Sprintf(
				"step %d reverted but records no revert reason", i+1))
		case !wantRevert && !(status.Kind == validation.Str &&
			status.S == "success"):
			reasons = append(reasons, fmt.Sprintf(
				"step %d failed in the result (status %s)", i+1,
				validation.PyRepr(status)))
		}
	}
	return reasons
}

// assertionReasons reports every final assertion that did not pass.
func assertionReasons(result validation.Value) []string {
	var reasons []string
	for _, a := range listOf(validation.ObjAt(result, "final_assertions")) {
		if a.Kind == validation.Obj && validation.ObjAt(a, "passed").Kind == validation.Bool &&
			validation.ObjAt(a, "passed").B {
			continue
		}
		reasons = append(reasons, fmt.Sprintf(
			"final assertion %s did not pass (observed %s, expected %s)",
			validation.PyStr(validation.ObjAt(a, "id")), validation.PyRepr(validation.ObjAt(a, "observed")),
			validation.PyRepr(validation.ObjAt(a, "expected"))))
	}
	return reasons
}

// actorSet is the Python set comprehension over dict entries with a truthy
// actor.
func actorSet(steps []validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range steps {
		if s.Kind != validation.Obj {
			continue
		}
		if actor := validation.ObjAt(s, "actor"); validation.PyTruthy(actor) {
			out[valueKey(actor)] = struct{}{}
		}
	}
	return out
}

// missingActors lists the declared actor labels absent from the executed
// set, sorted so the refusal sentence is deterministic. Labels are the
// finding's own actor values — never normalised or stripped of prose.
func missingActors(declared []validation.Value,
	executed map[string]struct{}) []string {
	seen := map[string]struct{}{}
	var missing []string
	for _, s := range declared {
		if s.Kind != validation.Obj {
			continue
		}
		actor := validation.ObjAt(s, "actor")
		if !validation.PyTruthy(actor) {
			continue
		}
		if _, ok := executed[valueKey(actor)]; ok {
			continue
		}
		label := validation.PyRepr(actor)
		if actor.Kind == validation.Str {
			label = actor.S
		}
		if _, dup := seen[label]; dup {
			continue
		}
		seen[label] = struct{}{}
		missing = append(missing, label)
	}
	sort.Strings(missing)
	return missing
}

// BenignActorAudit is benign_actor_audit: deterministic value-echo check
// over a declared multi-actor sequence. Pure function — no chain access, no
// campaign state. Advisory only.
func BenignActorAudit(exploitSequence validation.Value,
	cast map[string]string) []validation.Value {
	flags := []validation.Value{}
	if exploitSequence.Kind != validation.Arr {
		return flags
	}
	producer := map[string]int{} // stringified value -> first attacker step
	for idx, s := range exploitSequence.A {
		if s.Kind != validation.Obj {
			continue
		}
		actor := validation.ObjAt(s, "actor")
		cls := ""
		if actor.Kind == validation.Str {
			cls = cast[actor.S]
		}
		raw := validation.ObjAt(s, "args")
		values := raw.A
		if raw.Kind != validation.Arr {
			values = []validation.Value{raw}
		}
		for ai, v := range values {
			key := validation.PyStr(v)
			if cls == "adversarial" {
				if _, seen := producer[key]; !seen {
					producer[key] = idx + 1
				}
			} else if cls == "benign-rational" {
				if first, seen := producer[key]; seen {
					flags = append(flags, validation.VObj(
						validation.KV{K: "step", V: validation.VInt(
							int64(idx + 1))},
						validation.KV{K: "actor", V: actor},
						validation.KV{K: "arg_index", V: validation.VInt(
							int64(ai))},
						validation.KV{K: "value", V: v},
						validation.KV{K: "echoes_attacker_step",
							V: validation.VInt(int64(first))},
						validation.KV{K: "note", V: validation.VStr(
							"benign parameter equals a value first " +
								"produced by an attacker step — verify it " +
								"is public information a rational actor " +
								"would know; if it encodes " +
								"attacker-specific knowledge the PoC is " +
								"unrealistic")},
					))
				}
			}
		}
	}
	return flags
}
