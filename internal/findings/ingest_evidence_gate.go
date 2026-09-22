// ingest_evidence_gate.go: the shared evidence gates — per-item
// validation, the exec gate and its EXEC-reference verification, and the
// level-rise guardrail (webv2.findings).
package findings

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// pyStr is Python str() on a Value (scalars unquoted; containers repr —
// the f-string default formatting).

// fieldAt is (value, present) for an object key — the distinction between
// "absent" and "present as null" matters for Python .get(default).
func fieldAt(v validation.Value, key string) (validation.Value, bool) {
	for _, k := range v.O {
		if k.K == key {
			return k.V, true
		}
	}
	return validation.VNull(), false
}

// validateEvidenceItem is _validate_evidence_item: validate one item
// against the finding schema's evidence_item definition.
func validateEvidenceItem(item validation.Value) error {
	bad, err := validation.ValidateDefinition(item, "finding", "evidence_item")
	if err != nil {
		return err
	}
	if bad == nil {
		return nil
	}
	where := "<root>"
	if len(bad.Path) > 0 {
		where = strings.Join(bad.Path, "/")
	}
	return fmt.Errorf("evidence item invalid at %s: %s", where, bad.Message)
}

// checkExecGate is _check_exec_gate: the shared per-item evidence gate used
// by BOTH add_evidence and ingest_hypothesis.
func checkExecGate(campaign *state.Campaign, findingID string,
	item validation.Value, atIngest bool) error {
	level := validation.ObjStr(item, "level")
	if level == "E7" && !validation.PyTruthy(validation.ObjAt(item, "artifact_id")) {
		return fmt.Errorf("E7 (economic impact quantified) must reference " +
			"the artifact that carries the quantification (artifact_id)")
	}
	exec, err := IsExecutionLevel(level)
	if err != nil {
		return err
	}
	if !exec {
		return nil
	}
	if atIngest {
		return fmt.Errorf("ingest rejected: pre-loaded evidence %s at %s "+
			"is EXECUTION evidence — execution evidence must be attached "+
			"via add_evidence after an EXEC record exists in this campaign "+
			"(run the artifact through sandbox.Sandbox with finding_id set "+
			"and cite the exec)", validation.PyStr(validation.ObjAt(item, "evidence_id")), level)
	}
	profile := validation.ObjStr(item, "sandbox_profile")
	if !validation.PyTruthy(validation.VStr(profile)) {
		return fmt.Errorf("evidence %s at %s must name the sandbox_profile "+
			"it was produced under (see sandbox.py)",
			validation.PyStr(validation.ObjAt(item, "evidence_id")), level)
	}
	if _, ok := sandbox.E4_PROFILES[profile]; !ok {
		names := make([]string, 0, len(sandbox.E4_PROFILES))
		for p := range sandbox.E4_PROFILES {
			names = append(names, p)
		}
		sort.Strings(names)
		return fmt.Errorf("sandbox_profile %s is not an E4-capable profile "+
			"(one of %s); host-readonly and unknown profiles cannot back "+
			"execution evidence", validation.PyReprStr(profile), listRepr(names))
	}
	return verifyExecReference(campaign, item, profile, findingID)
}

// verifyExecReference is _verify_exec_reference: E4+ evidence must trace to
// a real EXEC record under the claimed profile.
func verifyExecReference(campaign *state.Campaign, item validation.Value,
	profile, findingID string) error {
	artifact := validation.ObjStr(item, "artifact_id")
	if strings.HasPrefix(artifact, "EXEC-") {
		recPath := filepath.Join(campaign.ExecsDir, artifact, "exec_record.json")
		if _, err := os.Stat(recPath); err != nil {
			return fmt.Errorf("evidence cites exec %s but no such EXEC "+
				"record exists", validation.PyReprStr(artifact))
		}
		rec, err := validation.ReadJson(recPath)
		if err != nil {
			return err
		}
		// v16 §4.1: the ledger's anchor is checked FIRST — before any
		// admission rule reads the record's own word. A record edited
		// after its event (exit_status flipped, expected_outcome and
		// expected_failure stamped in) is refused here, naming both
		// digests, instead of being blessed below. Absent anchor keys
		// are fail-open (exec_record_anchor.go).
		if err := sandbox.VerifyExecRecordAnchor(campaign, artifact, rec); err != nil {
			return err
		}
		if validation.ObjStr(rec, "profile") != profile {
			return fmt.Errorf("evidence claims profile %s but exec %s ran "+
				"under %s", validation.PyReprStr(profile), artifact,
				validation.PyRepr(validation.ObjAt(rec, "profile")))
		}
		if !execFindingMatch(rec, findingID) {
			return fmt.Errorf("exec %s was recorded for finding %s, not %s "+
				"— its output cannot back this finding's evidence",
				artifact, validation.PyRepr(validation.ObjAt(rec, "finding_id")),
				validation.PyReprStr(findingID))
		}
		// v16 §5.3: the record's declared expectation governs the exit
		// verdict here too — this trio runs AFTER mint's own gate on every
		// mint path, so without this branch an admitted expected-failure
		// record would still die on "must cite a run that succeeded" and
		// the new admission rule would have no end-to-end path. Under
		// "fail" the whole admission rule is ValidateExecRecord's (one
		// function, one opinion — this file must not fork a second one; it
		// also inherits the truncation and contradiction refusals). Under
		// "pass" (the default, absent keys included) today's trio runs
		// with its messages byte for byte.
		if err := checkExecExpectationShape(artifact, rec); err != nil {
			return err
		}
		if sandbox.ExecExpectedOutcome(rec) == sandbox.EXPECT_FAIL {
			return ValidateExecRecord(artifact, rec)
		}
		exit := validation.ObjAt(rec, "exit_status")
		if !isZero(exit) {
			return fmt.Errorf("exec %s exited with status %s; E4+ evidence "+
				"must cite a run that succeeded", artifact,
				validation.PyRepr(exit))
		}
		if strings.TrimSpace(sandbox.ExecOutput(rec)) == "" {
			return fmt.Errorf("exec %s has no captured output; a run that "+
				"printed nothing cannot demonstrate a reproduction", artifact)
		}
		if prob := sandbox.ExecOutputProblem(rec); prob != nil {
			return fmt.Errorf("exec %s: %s", artifact, *prob)
		}
		return nil
	}
	// No citation. Design law #4: E4+ evidence names its EXEC record.
	var matching []validation.Value
	// r43a: an absent execs/ directory means this campaign has no runs, so
	// the "no EXEC record ... exists" refusal below is true. An execs/
	// directory that cannot be listed is a different fact — the absence of a
	// matching record cannot be asserted — so it refuses here, naming the
	// store, instead of claiming the search came up empty.
	paths, err := validation.ListSubPrefixedOptional(campaign.ExecsDir,
		"EXEC-", "exec_record.json")
	if err != nil {
		return fmt.Errorf("the exec store %s cannot be listed, so this "+
			"evidence cannot be checked against the campaign's runs: %v",
			campaign.ExecsDir, err)
	}
	sort.Strings(paths)
	for _, p := range paths {
		rec, err := validation.ReadJson(p)
		if err != nil {
			return err
		}
		if validation.ObjStr(rec, "profile") == profile && execFindingMatch(rec, findingID) {
			matching = append(matching, rec)
		}
	}
	eid := validation.PyStr(validation.ObjAt(item, "evidence_id"))
	if len(matching) > 0 {
		return fmt.Errorf("E4+ evidence must cite its EXEC record "+
			"(artifact_id): evidence %s names no run, so its profile, exit "+
			"status, and output cannot be checked — an exec matching profile "+
			"%s exists (e.g. %s); set artifact_id to the exec that backed "+
			"the claim", eid, validation.PyReprStr(profile),
			validation.ObjStr(matching[0], "exec_id"))
	}
	return fmt.Errorf("no EXEC record under profile %s for this finding "+
		"exists in this campaign; sandbox_profile %s on evidence %s is "+
		"unverifiable — run the artifact through sandbox.Sandbox with "+
		"finding_id set (or generic) first and cite the exec",
		validation.PyReprStr(profile), validation.PyReprStr(profile), eid)
}

// isZero is (exit_status == 0) with Python None semantics (None != 0).
func isZero(v validation.Value) bool {
	switch v.Kind {
	case validation.Int:
		return v.Big == "" && v.I == 0
	case validation.Flt:
		return v.F == 0
	}
	return false
}

// enforceRiseGuardrail is _enforce_rise_guardrail: the shared level-rise
// decision. Level-neutral adds never trigger the guardrail.
func enforceRiseGuardrail(campaign *state.Campaign, finding validation.Value,
	level string, baseline string) error {
	base := baseline
	if base == "" {
		var err error
		base, err = FindingLevel(finding)
		if err != nil {
			return err
		}
	}
	li, err := LevelIndex(level)
	if err != nil {
		return err
	}
	bi, err := LevelIndex(base)
	if err != nil {
		return err
	}
	if li > bi {
		return assertInvariantsVerified(campaign, finding)
	}
	return nil
}
