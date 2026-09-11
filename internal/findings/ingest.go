// ingest.go: ingest_hypothesis / add_evidence and the shared evidence gates
// (webv2.findings). The gate set lives in ONE place per concern so the
// ingest and add paths cannot drift apart — the same law as Python.
package findings

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- seams into modules that land later (taxonomy: Task 3; invariants:
// ---- Task 8). Defaults are the safe no-ops; the real implementations are
// ---- wired with Set* once the module exists.

// classAdvisoryFunc is the taxonomy.class_advisory seam: one-line advisory
// for ingest output/logs, or "" when the class is known. Nil bugClass is
// Python's None (the message text for unknown classes shows it as such).
var classAdvisoryFunc = func(bugClass *string) string { return "" }

// SetClassAdvisory wires the real taxonomy.class_advisory (Task 3).
func SetClassAdvisory(f func(bugClass *string) string) {
	if f == nil {
		panic("findings: nil class advisory")
	}
	classAdvisoryFunc = f
}

// assertInvariantsVerified is the invariants 2.1 guardrail seam: a level
// rise on a finding hung off unverified invariants is refused.
var assertInvariantsVerified = func(*state.Campaign, validation.Value) error {
	return nil
}

// SetInvariantGuard wires the real invariants guardrail (Task 8).
func SetInvariantGuard(f func(*state.Campaign, validation.Value) error) {
	if f == nil {
		panic("findings: nil invariant guard")
	}
	assertInvariantsVerified = f
}

// pyTruthy is Python truthiness on a Value (0/empty/None are falsy; a
// bool is its own value).
func pyTruthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		if v.Big != "" {
			return v.Big != "0"
		}
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr, validation.Obj:
		return len(v.A) > 0 || len(v.O) > 0
	}
	return false
}

// pyStr is Python str() on a Value (scalars unquoted; containers repr —
// the f-string default formatting).
func pyStr(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "None"
	case validation.Str:
		return v.S
	case validation.Arr, validation.Obj:
		return validation.PyRepr(v)
	}
	return validation.PyRepr(v)
}

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
	level := objStr(item, "level")
	if level == "E7" && !pyTruthy(objAt(item, "artifact_id")) {
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
			"and cite the exec)", pyStr(objAt(item, "evidence_id")), level)
	}
	profile := objStr(item, "sandbox_profile")
	if !pyTruthy(validation.VStr(profile)) {
		return fmt.Errorf("evidence %s at %s must name the sandbox_profile "+
			"it was produced under (see sandbox.py)",
			pyStr(objAt(item, "evidence_id")), level)
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
	findingMatch := func(rec validation.Value) bool {
		f := objAt(rec, "finding_id")
		return f.Kind == validation.Null ||
			(f.Kind == validation.Str && f.S == findingID)
	}
	artifact := objStr(item, "artifact_id")
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
		if objStr(rec, "profile") != profile {
			return fmt.Errorf("evidence claims profile %s but exec %s ran "+
				"under %s", validation.PyReprStr(profile), artifact,
				validation.PyRepr(objAt(rec, "profile")))
		}
		if !findingMatch(rec) {
			return fmt.Errorf("exec %s was recorded for finding %s, not %s "+
				"— its output cannot back this finding's evidence",
				artifact, validation.PyRepr(objAt(rec, "finding_id")),
				validation.PyReprStr(findingID))
		}
		exit := objAt(rec, "exit_status")
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
	paths := validation.ListSubPrefixed(campaign.ExecsDir, "EXEC-",
		"exec_record.json")
	sort.Strings(paths)
	for _, p := range paths {
		rec, err := validation.ReadJson(p)
		if err != nil {
			return err
		}
		if objStr(rec, "profile") == profile && findingMatch(rec) {
			matching = append(matching, rec)
		}
	}
	eid := pyStr(objAt(item, "evidence_id"))
	if len(matching) > 0 {
		return fmt.Errorf("E4+ evidence must cite its EXEC record "+
			"(artifact_id): evidence %s names no run, so its profile, exit "+
			"status, and output cannot be checked — an exec matching profile "+
			"%s exists (e.g. %s); set artifact_id to the exec that backed "+
			"the claim", eid, validation.PyReprStr(profile),
			objStr(matching[0], "exec_id"))
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

// IngestHypothesis is ingest_hypothesis: create a finding from a specialist
// pass. stage/model are "" for None (both are falsy in every Python use).
func IngestHypothesis(campaign *state.Campaign, payload validation.Value,
	trajectory, stage, model string) (validation.Value, error) {
	budget, err := campaign.Budget()
	if err != nil {
		return validation.VNull(), err
	}
	if objAt(budget, "discovery_findings_so_far").I >=
		objAt(budget, "max_discovery_findings").I {
		return validation.VNull(), fmt.Errorf("%s",
			"discovery budget exhausted — raise the ceiling (webv2 budget "+
				campaign.CampaignID+" --set-discovery N --actor NAME) or plan a new pass")
	}

	fid := NewFindingID()
	ts := nowIso()
	p := validation.Value{Kind: validation.Obj,
		O: append([]validation.KV(nil), payload.O...)}
	p.O = validation.SetOrAppend(p.O, "finding_id", validation.VStr(fid))
	p.O = validation.SetOrAppend(p.O, "campaign_id", validation.VStr(campaign.CampaignID))
	p.O = validation.SetOrAppend(p.O, "snapshot_ids", validation.VObj(
		validation.KV{K: "source", V: sourcePinOrUnpinned(campaign)},
		validation.KV{K: "deployment", V: validation.VNull()},
		validation.KV{K: "chain", V: validation.VNull()},
	))
	p.O = validation.SetOrAppend(p.O, "created_at", validation.VStr(ts))
	p.O = validation.SetOrAppend(p.O, "updated_at", validation.VStr(ts))
	p.O = validation.SetOrAppend(p.O, "status", validation.VStr("HYPOTHESIS"))
	p.O = validation.SetOrAppend(p.O, "trajectory", validation.VStr(trajectory))
	for _, k := range []string{"evidence", "risk", "dedup"} {
		if _, ok := fieldAt(p, k); !ok {
			if k == "evidence" {
				p.O = append(p.O, validation.KV{K: k, V: validation.VArr()})
			} else {
				p.O = append(p.O, validation.KV{K: k, V: validation.VObj()})
			}
		}
	}
	reason := "ingested from " + orDefault(stage, "unknown stage")
	actor := orDefault(stage, "ingest")
	p.O = validation.SetOrAppend(p.O, "history", validation.VArr(validation.VObj(
		validation.KV{K: "at", V: validation.VStr(ts)},
		validation.KV{K: "from", V: validation.VStr("NEW")},
		validation.KV{K: "to", V: validation.VStr("HYPOTHESIS")},
		validation.KV{K: "reason", V: validation.VStr(reason)},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	)))

	rootClassV, hasClass := fieldAt(objAt(p, "root_cause"), "class")
	var rootClass *string
	if !hasClass {
		u := "unclassified"
		rootClass = &u
	} else if rootClassV.Kind == validation.Str {
		rootClass = &rootClassV.S
	}
	first := validation.VObj()
	if aff := objAt(p, "affected"); aff.Kind == validation.Arr &&
		len(aff.A) > 0 {
		first = aff.A[0]
	}
	sig := TechnicalSignature(classSig(rootClass), sigPath(first),
		sigOpt(first, "function"), sigOpt(objAt(p, "invariant"), "id"))
	dedup := objAt(p, "dedup")
	dedup.O = validation.SetOrAppend(dedup.O, "technical_signature", validation.VStr(sig))
	p.O = validation.SetOrAppend(p.O, "dedup", dedup)

	if err := validation.Validate(p, "finding", 5); err != nil {
		return validation.VNull(), err
	}
	// Ingest-path gates (shared helpers with add_evidence): pre-loaded
	// EXECUTION evidence is rejected outright, and any pre-loaded items
	// that rise above the HYPOTHESIS baseline run the invariant guardrail.
	for _, item := range objAt(p, "evidence").A {
		if err := checkExecGate(campaign, fid, item, true); err != nil {
			return validation.VNull(), err
		}
	}
	if len(objAt(p, "evidence").A) > 0 {
		top, err := FindingLevel(p)
		if err != nil {
			return validation.VNull(), err
		}
		if err := enforceRiseGuardrail(campaign, p, top, "E0"); err != nil {
			return validation.VNull(), err
		}
	}
	// The discovery slot is consumed BEFORE the finding is written: the slot
	// is a budget, and a crash between the two writes must cost the operator
	// a slot (recoverable, visible) rather than hand out a free one. Saving
	// first left an uncounted discovery behind any failure in this window.
	if err := campaign.ConsumeDiscoverySlot(); err != nil {
		return validation.VNull(), err
	}
	if err := SaveFinding(campaign, &p); err != nil {
		return validation.VNull(), err
	}
	advisory := classAdvisoryFunc(rootClass)
	warnings := IntakeCheckpoint(p, trajectory, campaign.CampaignID)
	if _, err := campaign.Log("finding.ingested", &fid,
		ingestLogData(trajectory, stage, model, rootClass, advisory,
			warnings)); err != nil {
		return validation.VNull(), err
	}
	// A2: scan the pinned source for in-code acknowledgements around the
	// finding's anchors, so the demotion flag is present from the moment the
	// finding is filed. Fail-open: a finding ingested against an unpinned or
	// missing source (or with no resolvable anchor) simply has no ack record.
	if _, err := RecordAckScan(campaign, fid); err != nil {
		// skipped — nothing to record
	}
	// G5: scan the pinned source for structural defenses covering the
	// flagged code, so the soundness flag is present from the moment the
	// finding is filed. Fail-open, same posture as the ack scan: a finding
	// ingested against an unpinned or missing source (or with no resolvable
	// anchor) simply has no mitigation record.
	if _, err := RecordMitigationScan(campaign, fid); err != nil {
		// skipped — nothing to record
	}
	if len(warnings) > 0 {
		if _, err := campaign.Log("finding.intake_warnings", &fid,
			warningsLogData(warnings)); err != nil {
			return validation.VNull(), err
		}
	}
	return p, nil
}

// sourcePinOrUnpinned is active_snapshot_id_or_none() or "unpinned".
func sourcePinOrUnpinned(campaign *state.Campaign) validation.Value {
	id, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil || id == nil {
		return validation.VStr("unpinned")
	}
	return validation.VStr(*id)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// sigPath is first.get("path", "unknown") under Python str() semantics.
func sigPath(first validation.Value) string {
	v, ok := fieldAt(first, "path")
	if !ok {
		return "unknown"
	}
	return pyStr(v)
}

// sigOpt is (block.get(key) or "") — absent, null, and "" all fold to "".
func sigOpt(block validation.Value, key string) string {
	v, _ := fieldAt(block, key)
	if v.Kind != validation.Str {
		return ""
	}
	return v.S
}

// classSig is the signature's class part: f"{bug_class}" (None -> "None").
func classSig(rootClass *string) string {
	if rootClass == nil {
		return "None"
	}
	return *rootClass
}

// rootClassValue is the log's bug_class: *string as a Value (nil -> null).
func rootClassValue(rootClass *string) validation.Value {
	if rootClass == nil {
		return validation.VNull()
	}
	return validation.VStr(*rootClass)
}

// rootClassPtr is (payload.get("root_cause") or {}).get("class") — the
// NO-DEFAULT flavor intake_checkpoint uses (missing -> nil, i.e. None).
func rootClassPtr(payload validation.Value) *string {
	v, ok := fieldAt(objAt(payload, "root_cause"), "class")
	if !ok || v.Kind != validation.Str {
		return nil
	}
	return &v.S
}

// ingestLogData is the finding.ingested data dict, in Python literal order.
func ingestLogData(trajectory, stage, model string, rootClass *string,
	advisory string, warnings []string) *validation.Value {
	stageV, modelV := validation.VNull(), validation.VNull()
	if stage != "" {
		stageV = validation.VStr(stage)
	}
	if model != "" {
		modelV = validation.VStr(model)
	}
	advV := validation.VNull()
	if advisory != "" {
		advV = validation.VStr(advisory)
	}
	data := validation.VObj(
		validation.KV{K: "trajectory", V: validation.VStr(trajectory)},
		validation.KV{K: "stage", V: stageV},
		validation.KV{K: "model", V: modelV},
		validation.KV{K: "bug_class", V: rootClassValue(rootClass)},
		validation.KV{K: "class_advisory", V: advV},
		validation.KV{K: "intake_warnings", V: warningsValue(warnings)},
	)
	return &data
}

func warningsValue(warnings []string) validation.Value {
	out := make([]validation.Value, len(warnings))
	for i, w := range warnings {
		out[i] = validation.VStr(w)
	}
	return validation.VArr(out...)
}

func warningsLogData(warnings []string) *validation.Value {
	data := validation.VObj(validation.KV{K: "warnings",
		V: warningsValue(warnings)})
	return &data
}

// AddEvidence is add_evidence: append one evidence item to a finding.
func AddEvidence(campaign *state.Campaign, findingID string,
	item validation.Value) (validation.Value, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if inSet(TERMINAL, objStr(finding, "status")) {
		return validation.VNull(), fmt.Errorf("finding %s is terminal (%s); "+
			"record post-mortem notes via learning.reflection_entry instead",
			findingID, objStr(finding, "status"))
	}
	if a, ok := fieldAt(item, "artifact_id"); ok &&
		a.Kind != validation.Null && a.Kind != validation.Str {
		return validation.VNull(), fmt.Errorf(
			"evidence artifact_id must be a string or omitted")
	}
	it := validation.Value{Kind: validation.Obj,
		O: append([]validation.KV(nil), item.O...)}
	if pa, ok := fieldAt(it, "produced_at"); !ok ||
		pa.Kind == validation.Null {
		it.O = validation.SetOrAppend(it.O, "produced_at", validation.VStr(nowIso()))
	}
	if err := validateEvidenceItem(it); err != nil {
		return validation.VNull(), err
	}
	level := objStr(it, "level")
	if err := checkExecGate(campaign, findingID, it, false); err != nil {
		return validation.VNull(), err
	}
	li, err := LevelIndex(level)
	if err != nil {
		return validation.VNull(), err
	}
	e4, _ := LevelIndex("E4")
	if li >= e4 {
		if _, err := snapshot.AssertSnapshotCompatible(campaign, finding,
			true); err != nil {
			return validation.VNull(), err
		}
	}
	if err := enforceRiseGuardrail(campaign, finding, level, ""); err != nil {
		return validation.VNull(), err
	}
	ev := objAt(finding, "evidence")
	ev.A = append(ev.A, it)
	finding.O = validation.SetOrAppend(finding.O, "evidence", ev)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "evidence_id", V: objAt(it, "evidence_id")},
		validation.KV{K: "level", V: validation.VStr(level)},
		validation.KV{K: "type", V: objAt(it, "type")},
	)
	if _, err := campaign.Log("finding.evidence_added", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// IntakeCheckpoint is intake_checkpoint: pre-admission sanity checks —
// WARNINGS, not rejections. campaignID names the campaign in the repair hint;
// an empty id (a direct call with no campaign in hand) keeps the documented
// metavariable rather than an empty hole.
func IntakeCheckpoint(payload validation.Value, trajectory,
	campaignID string) []string {
	if campaignID == "" {
		campaignID = "<campaign>"
	}
	var warnings []string
	if adv := classAdvisoryFunc(rootClassPtr(payload)); adv != "" {
		warnings = append(warnings, adv)
	}
	if trajectory == "economic" &&
		!pyTruthy(objAt(objAt(payload, "risk"), "economic")) {
		warnings = append(warnings,
			"trajectory 'economic' but no risk.economic block recorded yet — "+
				"the CONFIRMED gate for economic classes requires an E7 "+
				"quantification artifact (balance-delta or manual evidence), or "+
				"the NAMED DECISION that no figure is defensible "+
				"(`webv2 impact "+campaignID+" <finding> --unpriceable "+
				"--ceiling '<capacity basis>' --reason R --actor A`)")
	}
	return warnings
}

var (
	// claimPctRe is r"(\d+(?:\.\d+)?)\s*%" — the trailing class is
	// Python's str whitespace (Go \s + \v, NEL, file separators, and the
	// Unicode space separators). The control chars are embedded as real
	// characters because RE2 has no \u escape.
	claimPctRe = regexp.MustCompile(`(\d+(?:\.\d+)?)` +
		"[\\s\\v\u0085\u001c\u001d\u001e\u001f\\p{Z}]*%")
	// claimHalfRe is r"\bhalf\b" IGNORECASE with Unicode word boundaries.
	claimHalfRe = regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}\p{Pc}])half` +
		`(?:$|[^\p{L}\p{N}\p{Pc}])`)
)

// ClaimDriftProblems is claim_drift_problems: the claim-vs-measurement
// check (C).
func ClaimDriftProblems(finding validation.Value) ([]string, error) {
	ratio, ok := pyFloat(objAt(objAt(finding, "economic_impact"),
		"extraction_ratio"))
	if !ok || !(ratio > 0 && ratio <= 1) {
		return nil, nil
	}
	titleV := objAt(finding, "title")
	if titleV.Kind != validation.Str {
		return nil, nil
	}
	var claimed []float64
	for _, m := range claimPctRe.FindAllStringSubmatch(titleV.S, -1) {
		f, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return nil, err
		}
		claimed = append(claimed, f/100.0)
	}
	if len(claimed) == 0 && claimHalfRe.MatchString(titleV.S) {
		claimed = []float64{0.5}
	}
	if len(claimed) == 0 {
		return nil, nil
	}
	for _, c := range claimed {
		if math.Abs(c-ratio) <= 0.05 {
			return nil, nil
		}
	}
	closest := claimed[0]
	for _, c := range claimed[1:] {
		if math.Abs(c-ratio) < math.Abs(closest-ratio) {
			closest = c
		}
	}
	return []string{fmt.Sprintf(
		"claim says %.0f%% extraction (closest figure in the title) but "+
			"measured extraction_ratio is %.0f%% — make the claim and the "+
			"measurement agree", closest*100, ratio*100)}, nil
}

// pyFloat is isinstance(v, (int, float)) as a float64 (bool included, as in
// Python; a big-int can never satisfy 0 < x <= 1, so it is rejected).
func pyFloat(v validation.Value) (float64, bool) {
	switch v.Kind {
	case validation.Int:
		if v.Big != "" {
			return 0, false
		}
		return float64(v.I), true
	case validation.Flt:
		return v.F, true
	case validation.Bool:
		if v.B {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}
