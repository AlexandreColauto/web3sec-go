// Package boundary is the port of webv2/model_boundary.py — fail-closed
// validation of model traffic.
//
// Every model response is validated against its role's response contract
// (model_response.schema.json) HERE, before it is allowed to touch
// orchestrator state. The law: reject and re-request on schema failure —
// NEVER coerce a malformed response into a valid one, never partially apply
// it; a rejected generation is LOGGED (model.rejected) with the payload hash;
// citations are checked against the store, not trusted.
package boundary

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/roles"
	"websec/internal/sandbox"
	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/validation"
)

// BoundaryError is ModelBoundaryError: a model request record or response
// failed the boundary check.
type BoundaryError struct{ Msg string }

func (e *BoundaryError) Error() string { return e.Msg }

// ResponseKinds is RESPONSE_KINDS.
var ResponseKinds = []string{"hypothesis", "plan", "critic_verdict",
	"reproducer_request"}

// RoleResponses is ROLE_RESPONSES: role -> the response kinds that role may
// emit (structural role separation).
var RoleResponses = []struct {
	Role  string
	Kinds []string
}{
	{"proposer", []string{"hypothesis", "plan"}},
	{"critic", []string{"critic_verdict"}},
	{"reproducer", []string{"reproducer_request"}},
}

func roleKinds(role string) ([]string, bool) {
	for _, r := range RoleResponses {
		if r.Role == role {
			return r.Kinds, true
		}
	}
	return nil, false
}

// AnalysisTools is ANALYSIS_TOOLS: the analysis-tool vocabulary plans may
// reference.
var AnalysisTools = []string{
	"callgraph", "source-slice", "trace", "fork", "static-analysis",
	"invariant-check", "symbolic", "fuzzing", "balance-delta",
	"capability-coverage", "resemble",
}

// ToolRegistry is tool_registry(): sandbox execution profiles + the
// analysis-tool vocabulary.
func ToolRegistry() []string {
	set := map[string]bool{}
	for _, t := range AnalysisTools {
		set[t] = true
	}
	for _, p := range sandbox.Profiles {
		set[p] = true
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func inRegistry(id string) bool {
	for _, t := range AnalysisTools {
		if t == id {
			return true
		}
	}
	for _, p := range sandbox.Profiles {
		if p == id {
			return true
		}
	}
	return false
}

// PromptVersion is prompt_version(path): sha256[:16] of the prompt file.
func PromptVersion(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16], nil
}

// ContextHash is context_hash(bundle): sha256 of the canonical serialization
// of a context bundle — the exact-input stamp the request record carries.
func ContextHash(bundle validation.Value) string {
	sum := sha256.Sum256([]byte(validation.CanonSpaced(bundle)))
	return hex.EncodeToString(sum[:])
}

// schemaFailures is _schema_failures.
func schemaFailures(payload validation.Value, kind string) ([]string, error) {
	return validation.ValidateDefinitionFailures(payload, "model_response", kind)
}

// ValidateRequest is validate_request: validate a model request record (the
// version stamp the trajectory logs).
func ValidateRequest(request validation.Value) error {
	if err := validation.Validate(request, "model_request", 1); err != nil {
		return &BoundaryError{Msg: err.Error()}
	}
	return nil
}

// ValidateResponse is validate_response: fail-closed validation of one model
// response. campaign may be nil (the schema/cross-field rules that need
// campaign state are then skipped, exactly like Python).
func ValidateResponse(role, kind string, payload validation.Value,
	campaign *state.Campaign) error {
	if !contains(ResponseKinds, kind) {
		return &BoundaryError{Msg: fmt.Sprintf("unknown response kind %s",
			validation.PyReprStr(kind))}
	}
	allowed, ok := roleKinds(role)
	if !ok {
		return &BoundaryError{Msg: fmt.Sprintf("unknown role %s",
			validation.PyReprStr(role))}
	}
	if !contains(allowed, kind) {
		return &BoundaryError{Msg: fmt.Sprintf(
			"role %s may not emit a %s response (allowed: %s)",
			validation.PyReprStr(role), validation.PyReprStr(kind),
			pyListRepr(allowed))}
	}
	if payload.Kind != validation.Obj {
		return &BoundaryError{Msg: fmt.Sprintf(
			"%s response must be a JSON object, got %s", kind,
			pyTypeName(payload))}
	}
	failures, err := schemaFailures(payload, kind)
	if err != nil {
		return err
	}
	if len(failures) > 0 {
		n := len(failures)
		if n > 5 {
			n = 5
		}
		return &BoundaryError{Msg: fmt.Sprintf("%s contract failure: %s",
			kind, strings.Join(failures[:n], "; "))}
	}
	switch kind {
	case "hypothesis", "plan":
		return validatePlanKinds(kind, payload, campaign)
	case "critic_verdict":
		return validateCriticVerdict(payload, campaign)
	case "reproducer_request":
		return validateReproducerRequest(payload, campaign)
	}
	return nil
}

// validatePlanKinds is the hypothesis/plan cross-field block.
func validatePlanKinds(kind string, payload validation.Value,
	campaign *state.Campaign) error {
	stepsKey := "initial_plan"
	if kind == "plan" {
		stepsKey = "steps"
	}
	tools := map[string]bool{}
	if steps := objAt(payload, stepsKey); steps.Kind == validation.Arr {
		for _, s := range steps.A {
			if s.Kind == validation.Obj {
				tools[objStr(s, "tool_id")] = true
			}
		}
	}
	unknown := []string{}
	for t := range tools {
		if !inRegistry(t) {
			unknown = append(unknown, t)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		return &BoundaryError{Msg: fmt.Sprintf(
			"%s plan cites tool ids not in the registry: %s (registry: %s)",
			kind, pyListRepr(unknown), pyListRepr(ToolRegistry()))}
	}
	if campaign == nil {
		return nil
	}
	if kind == "plan" {
		fid := objStr(payload, "finding_id")
		if _, err := findings.LoadFinding(campaign, fid); err != nil {
			return &BoundaryError{Msg: fmt.Sprintf(
				"plan references unknown finding %s", validation.PyReprStr(fid))}
		}
		return nil
	}
	known := campaignMemoryIDs(campaign)
	if d := objAt(payload, "differs_from_memory"); d.Kind == validation.Arr {
		for _, item := range d.A {
			if item.Kind != validation.Obj {
				continue
			}
			mid := objStr(item, "memory_id")
			if !known[mid] {
				return &BoundaryError{Msg: fmt.Sprintf(
					"hypothesis override names unknown memory row %s — an "+
						"override must name a real surfacable prior",
					validation.PyReprStr(mid))}
			}
		}
	}
	return nil
}

// validateCriticVerdict is the critic cross-field block.
func validateCriticVerdict(payload validation.Value,
	campaign *state.Campaign) error {
	unknown := unknownRecommendedTools(payload)
	if len(unknown) > 0 {
		return &BoundaryError{Msg: fmt.Sprintf(
			"critic verdict recommends unknown tool ids: %s",
			pyListRepr(unknown))}
	}
	if campaign == nil {
		return nil
	}
	fid := objStr(payload, "finding_id")
	finding, err := findings.LoadFinding(campaign, fid)
	if err != nil {
		return &BoundaryError{Msg: fmt.Sprintf(
			"critic verdict references unknown finding %s",
			validation.PyReprStr(fid))}
	}
	cur := objAt(finding, "claim_version")
	claim := objAt(payload, "claim_version")
	if cur.Kind != validation.Null && claim.Kind != validation.Null &&
		!valueEq(claim, cur) {
		return &BoundaryError{Msg: fmt.Sprintf(
			"stale critic verdict: addresses claim_version %s but the "+
				"finding is at %s — re-run the critic against the current claim",
			scalarText(claim), scalarText(cur))}
	}
	curByID, ids := assumptionStatuses(finding)
	return validateCriticMoves(payload, campaign, finding, fid, curByID, ids)
}

// unknownRecommendedTools is the sorted distinct recommended_checks tool ids
// the registry does not know.
func unknownRecommendedTools(payload validation.Value) []string {
	unknown := []string{}
	checks := objAt(payload, "recommended_checks")
	if checks.Kind != validation.Arr {
		return unknown
	}
	seen := map[string]bool{}
	for _, c := range checks.A {
		if c.Kind != validation.Obj {
			continue
		}
		id := objStr(c, "tool_id")
		if !inRegistry(id) && !seen[id] {
			seen[id] = true
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// assumptionStatuses is the finding's current assumption statuses by id, plus
// the sorted id list (Python sorts for the error text).
func assumptionStatuses(finding validation.Value) (map[string]string, []string) {
	curByID := map[string]string{}
	ids := []string{}
	if as := objAt(finding, "assumptions"); as.Kind == validation.Arr {
		for _, a := range as.A {
			if a.Kind == validation.Obj {
				id := objStr(a, "id")
				curByID[id] = objStr(a, "status")
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return curByID, ids
}

// validateCriticMoves pre-validates every assumption move so apply cannot fail
// halfway (atomicity): unknown ids, illegal transitions, and uncited or
// unresolvable evidence are boundary rejections, not partial applications.
func validateCriticMoves(payload validation.Value, campaign *state.Campaign,
	finding validation.Value, fid string, curByID map[string]string,
	ids []string) error {
	legal := map[string][]string{
		"UNKNOWN":   {"SUPPORTED", "REFUTED"},
		"SUPPORTED": {"REFUTED"},
		"REFUTED":   {"SUPPORTED"},
	}
	per := objAt(payload, "per_assumption")
	if per.Kind != validation.Arr {
		return nil
	}
	for _, entry := range per.A {
		if entry.Kind != validation.Obj {
			continue
		}
		if err := validateCriticMove(entry, campaign, finding, fid, curByID,
			ids, legal); err != nil {
			return err
		}
	}
	return nil
}

// validateCriticMove is one per_assumption entry.
func validateCriticMove(entry validation.Value, campaign *state.Campaign,
	finding validation.Value, fid string, curByID map[string]string,
	ids []string, legal map[string][]string) error {
	aid := objStr(entry, "assumption_id")
	fromStatus, known := curByID[aid]
	if !known {
		return &BoundaryError{Msg: fmt.Sprintf(
			"critic entry names assumption %s which is not an "+
				"assumption of %s (ids: %s)", validation.PyReprStr(aid),
			fid, pyListRepr(ids))}
	}
	status := objStr(entry, "status")
	if status == fromStatus {
		return nil
	}
	if !contains(legal[fromStatus], status) {
		return &BoundaryError{Msg: fmt.Sprintf(
			"critic entry for %s: %s -> %s is not a legal assumption move",
			aid, fromStatus, status)}
	}
	cited := objAt(entry, "evidence_cited")
	if status == "UNKNOWN" {
		if cited.Kind == validation.Arr && len(cited.A) > 0 {
			return &BoundaryError{Msg: fmt.Sprintf(
				"critic entry for %s is UNKNOWN but cites evidence — "+
					"UNKNOWN is a claim of not-yet-checked, not a citation",
				aid)}
		}
		return nil
	}
	if cited.Kind != validation.Arr || len(cited.A) == 0 {
		return &BoundaryError{Msg: fmt.Sprintf(
			"critic entry for %s moves the assumption without citing "+
				"evidence — the boundary does not trust belief", aid)}
	}
	for _, ref := range cited.A {
		if ref.Kind != validation.Str {
			continue
		}
		if err := findings.ResolveEvidenceRef(campaign, finding,
			ref.S); err != nil {
			return &BoundaryError{Msg: fmt.Sprintf(
				"critic entry for %s cites evidence the store does "+
					"not have: %v", aid, err)}
		}
	}
	return nil
}

// validateReproducerRequest is the reproducer cross-field block.
func validateReproducerRequest(payload validation.Value,
	campaign *state.Campaign) error {
	if campaign == nil {
		return nil
	}
	profile := objStr(payload, "execution_profile")
	if !contains(sandbox.Profiles, profile) {
		return &BoundaryError{Msg: fmt.Sprintf(
			"reproducer request names unknown execution profile %s",
			validation.PyReprStr(profile))}
	}
	fid := objStr(payload, "finding_id")
	if _, err := findings.LoadFinding(campaign, fid); err != nil {
		return &BoundaryError{Msg: fmt.Sprintf(
			"reproducer request references unknown finding %s",
			validation.PyReprStr(fid))}
	}
	active, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return err
	}
	if active != nil && objStr(payload, "snapshot_id") != *active {
		return &BoundaryError{Msg: fmt.Sprintf(
			"reproducer request pins snapshot %s but the active pin is %s — "+
				"the request must not drift the deployment",
			validation.PyReprStr(objStr(payload, "snapshot_id")),
			validation.PyReprStr(*active))}
	}
	return nil
}

// campaignMemoryIDs is _campaign_memory_ids.
func campaignMemoryIDs(campaign *state.Campaign) map[string]bool {
	ids := map[string]bool{}
	entries, err := os.ReadDir(filepath.Join(campaign.Dir, "memory"))
	if err == nil {
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() && strings.HasPrefix(name, "MEM-") &&
				strings.HasSuffix(name, ".json") {
				ids[strings.TrimSuffix(name, ".json")] = true
			}
		}
	}
	if wrapped, err := sharedmem.LoadSharedMemory(campaign.Root); err == nil {
		for _, w := range wrapped {
			r := w
			if w.Kind == validation.Obj {
				if row := objAt(w, "row"); row.Kind != validation.Null {
					r = row
				}
			}
			if mid := objStr(r, "memory_id"); mid != "" {
				ids[mid] = true
			}
		}
	}
	return ids
}

// RecordRejection is record_rejection: log a rejected generation as a
// first-class event and return the re-request message. The payload is
// recorded by hash only.
func RecordRejection(campaign *state.Campaign, role, kind string,
	payload validation.Value, err error) (string, error) {
	blob := validation.CanonSpaced(payload)
	data := validation.VObj(
		validation.KV{K: "role", V: validation.VStr(role)},
		validation.KV{K: "kind", V: validation.VStr(kind)},
		validation.KV{K: "error", V: validation.VStr(pyTrunc(err.Error(), 1000))},
		validation.KV{K: "payload_sha256", V: validation.VStr(sha256Hex(blob))},
		validation.KV{K: "action", V: validation.VStr(
			"re-request against the response contract; do not coerce")})
	if _, logErr := campaign.Log("model.rejected", nil, &data); logErr != nil {
		return "", logErr
	}
	return fmt.Sprintf("REJECTED (%s/%s): %s — re-request against "+
		"model_response.schema.json#definitions/%s", role, kind,
		pyTrunc(err.Error(), 300), kind), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// statementOverlap is _statement_overlap: cheap normalized word overlap
// between two propositions.
func statementOverlap(a, b string) bool {
	wa := map[string]bool{}
	for _, w := range learning.ReSplit(a) {
		if len([]rune(w)) > 3 {
			wa[w] = true
		}
	}
	for _, w := range learning.ReSplit(b) {
		if len([]rune(w)) > 3 && wa[w] {
			return true
		}
	}
	return false
}

// memoryUtility is _memory_utility: the cheap utility signal on
// negative-memory injection.
func memoryUtility(campaign *state.Campaign, findingID string,
	raw validation.Value) error {
	block, err := roles.KnownNonIssues(campaign,
		strPtr(objStr(raw, "bug_class")), 12)
	if err != nil {
		return err
	}
	priors := objAt(block, "known_non_issues")
	if priors.Kind != validation.Arr || len(priors.A) == 0 {
		return nil
	}
	declared := map[string]bool{}
	if d := objAt(raw, "differs_from_memory"); d.Kind == validation.Arr {
		for _, item := range d.A {
			if item.Kind == validation.Obj {
				declared[objStr(item, "memory_id")] = true
			}
		}
	}
	hypAssumptions := []string{}
	if as := objAt(raw, "assumptions"); as.Kind == validation.Arr {
		for _, a := range as.A {
			if a.Kind == validation.Obj && truthy(objAt(a, "blocking")) {
				hypAssumptions = append(hypAssumptions, objStr(a, "claim"))
			}
		}
	}
	reRaised, overrideDeclared, notMatched := []string{}, []string{}, []string{}
	inContext := []string{}
	for _, prior := range priors.A {
		mid := objStr(prior, "memory_id")
		inContext = append(inContext, mid)
		if declared[mid] {
			overrideDeclared = append(overrideDeclared, mid)
			continue
		}
		props := objAt(prior, "deciding_propositions")
		hit := false
		if props.Kind == validation.Arr && len(props.A) > 0 {
			for _, h := range hypAssumptions {
				for _, p := range props.A {
					if p.Kind == validation.Obj &&
						statementOverlap(h, objStr(p, "statement")) {
						hit = true
						break
					}
				}
				if hit {
					break
				}
			}
		} else {
			hit = objStr(prior, "bug_class") == objStr(raw, "bug_class")
		}
		if hit {
			reRaised = append(reRaised, mid)
		} else {
			notMatched = append(notMatched, mid)
		}
	}
	data := validation.VObj(
		validation.KV{K: "bug_class", V: objAt(raw, "bug_class")},
		validation.KV{K: "memories_in_context", V: strArr(inContext)},
		validation.KV{K: "re_raised", V: strArr(reRaised)},
		validation.KV{K: "override_declared", V: strArr(overrideDeclared)},
		validation.KV{K: "not_matched", V: strArr(notMatched)})
	_, err = campaign.Log("memory.utility", &findingID, &data)
	return err
}

// ---- small helpers --------------------------------------------------------

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	x := objAt(v, key)
	if x.Kind == validation.Str {
		return x.S
	}
	return ""
}

func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Bool:
		return v.B
	case validation.Null:
		return false
	case validation.Str:
		return v.S != ""
	case validation.Int:
		return v.I != 0
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return true
}

func pyListRepr(xs []string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = validation.PyReprStr(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func pyTypeName(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return "str"
	case validation.Arr:
		return "list"
	case validation.Int:
		return "int"
	case validation.Flt:
		return "float"
	case validation.Bool:
		return "bool"
	case validation.Null:
		return "NoneType"
	}
	return "dict"
}

func pyTrunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func scalarText(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	}
	return ""
}

func valueEq(a, b validation.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Str:
		return a.S == b.S
	case validation.Int:
		return a.I == b.I && a.Big == b.Big
	case validation.Null:
		return true
	case validation.Bool:
		return a.B == b.B
	}
	return false
}

func strArr(xs []string) validation.Value {
	out := make([]validation.Value, len(xs))
	for i, x := range xs {
		out[i] = validation.VStr(x)
	}
	return validation.VArr(out...)
}

func strPtr(s string) *string { return &s }
