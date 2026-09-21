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
	"regexp"
	"slices"
	"sort"
	"strings"

	"websec/internal/sandbox"
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

// artifactKeyPattern matches the bundle keys that CARRY ids — the ones the
// role context builders actually emit (`internal/roles/context.go`,
// context_critic.go:163, context_reproducer.go:15).
var artifactKeyPattern = regexp.MustCompile(
	`^(artifact|evidence|finding|snapshot|exec|invariant|plan)_ids?$|^active_snapshot_id$`)

// saneArtifactID is the ONLY bound the derivation puts on a string under an
// id-bearing key: 3..64 bytes, no whitespace. The KEY is the scoping rule —
// it is what keeps an id quoted in prose out of the cited set — not the id's
// shape.
//
// An earlier revision filtered on a hardcoded prefix list (ART|EXEC|EV|F|INV|
// SNAP|PRC). That list was fiction: state.RegisterArtifact mints
// `<KIND-first-3-upper>-<8hex>` (internal/state/artifacts.go:56), snapshots
// are `src-content-<12hex>` (internal/snapshot/pin.go:334), so on a REAL
// bundle the derived cited set held only finding ids and the out-of-set
// refusal could never fire on the snapshot or artifact a stage actually
// consumed. The bounds mirror the item bounds model_request.schema.json puts
// on input_artifacts/context_artifacts, so an id the walk accepts can never
// make the record BuildRequest emits schema-invalid.
func saneArtifactID(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	return !strings.ContainsAny(s, " \t\r\n")
}

// BundleArtifacts returns every id the bundle carries under an id-bearing key,
// deduped in first-seen order. Derivation, not declaration: the set is read
// off the bytes that are actually sent, and a string under one of those keys
// IS an id — no shape is guessed, because guessing the shape is what made the
// cited set empty on real bundles.
//
// The walk is scoped to those keys on purpose. Scanning every leaf string
// would also match ids quoted in prose, diffs and pasted file contents — the
// bundle is full of them — and over-inclusion is not the safe direction it
// looks like: an operator who must declare everything the bundle happens to
// mention ends up declaring everything, and then the declaration means
// nothing. Over-inclusion trains the declaration out of existence.
func BundleArtifacts(bundle validation.Value) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		if saneArtifactID(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	var walk func(v validation.Value)
	walk = func(v validation.Value) {
		switch v.Kind {
		case validation.Obj:
			for _, kv := range v.O {
				if artifactKeyPattern.MatchString(kv.K) {
					collectIDs(kv.V, add)
					continue
				}
				walk(kv.V)
			}
		case validation.Arr:
			for _, x := range v.A {
				walk(x)
			}
		}
	}
	walk(bundle)
	return out
}

// collectIDs adds the id(s) under one id-bearing key: a bare string, an array
// of ids, or a mapping whose VALUES are ids — `snapshot_ids` is
// {source: <id>, deployment: <id>} (internal/findings/ingest.go:121), the
// shape the critic and reproducer bundles carry their pinned snapshot under.
func collectIDs(v validation.Value, add func(string)) {
	switch v.Kind {
	case validation.Str:
		add(v.S)
	case validation.Arr:
		for _, x := range v.A {
			collectIDs(x, add)
		}
	case validation.Obj:
		for _, kv := range v.O {
			collectIDs(kv.V, add)
		}
	}
}

// BuildRequest assembles a model_request from the bundle that is actually
// sent. context_hash pins the bytes; context_artifacts is DERIVED from those
// same bytes, so no caller can declare a narrow set and send a wide one.
func BuildRequest(bundle, declaration validation.Value, role, modelID,
	promptVersion, responseSchema string) validation.Value {
	return validation.VObj(
		validation.KV{K: "role", V: validation.VStr(role)},
		validation.KV{K: "model_id", V: validation.VStr(modelID)},
		validation.KV{K: "prompt_version", V: validation.VStr(promptVersion)},
		validation.KV{K: "response_schema", V: validation.VStr(responseSchema)},
		validation.KV{K: "context_hash", V: validation.VStr(ContextHash(bundle))},
		validation.KV{K: "input_artifacts", V: declaration},
		validation.KV{K: "context_artifacts", V: validation.VArr(
			strValues(BundleArtifacts(bundle))...)},
	)
}

// DeclaredInputArtifacts returns the ids in a request's declared input artifact
// set, in declaration order.
func DeclaredInputArtifacts(request validation.Value) []string {
	out := []string{}
	for _, a := range validation.ObjAt(request, "input_artifacts").A {
		if id := validation.ObjStr(a, "id"); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// InputArtifactsOutsideDeclaration returns every id the context cites that the
// stage did not declare, in first-seen order. The declaration is the whole
// point: a stage that reads an artifact it did not declare is the same class
// of fabrication as a ghost id (v1.6 Part 8, non-negotiable 4).
func InputArtifactsOutsideDeclaration(request validation.Value) []string {
	declared := map[string]bool{}
	for _, id := range DeclaredInputArtifacts(request) {
		declared[id] = true
	}
	seen := map[string]bool{}
	out := []string{}
	for _, c := range validation.ObjAt(request, "context_artifacts").A {
		id := c.S
		if id == "" || declared[id] || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// strValues is the []string -> []validation.Value bridge for VArr.
func strValues(ids []string) []validation.Value {
	out := make([]validation.Value, len(ids))
	for i, id := range ids {
		out[i] = validation.VStr(id)
	}
	return out
}

// RecordInputSetRefusal logs the model.rejected event for a request whose
// input set is undeclared or violated, so the refusal is a ledger fact and not
// just a returned error. The ref is nil: at request time there is no finding
// id yet, and a fabricated empty-string ref is a ghost id.
//
// The event data satisfies trajectory.schema.json#model_rejected — callers
// admit a request through InputSetRecordable first, so role and kind are the
// vocabulary that definition requires.
func RecordInputSetRefusal(c *state.Campaign, request validation.Value,
	why string) error {
	data := refusalData(request, why)
	_, err := c.Log("model.rejected", nil, &data)
	return err
}

// refusalData builds the model.rejected payload for a declared-input-set
// refusal, mirroring RecordRejection's event shape rather than inventing a
// second rejection vocabulary.
func refusalData(request validation.Value, why string) validation.Value {
	return validation.VObj(
		validation.KV{K: "role", V: validation.VStr(validation.ObjStr(request, "role"))},
		validation.KV{K: "kind", V: validation.VStr(validation.ObjStr(request, "response_schema"))},
		validation.KV{K: "error", V: validation.VStr(pyTrunc(why, 1000))},
		validation.KV{K: "payload_sha256", V: validation.VStr(
			sha256Hex(validation.CanonSpaced(request)))},
		validation.KV{K: "context_hash", V: validation.VStr(validation.ObjStr(request, "context_hash"))},
		validation.KV{K: "declared", V: validation.VArr(strValues(DeclaredInputArtifacts(request))...)},
		validation.KV{K: "outside", V: validation.VArr(strValues(InputArtifactsOutsideDeclaration(request))...)},
		validation.KV{K: "action", V: validation.VStr(
			"re-declare the stage's input artifact set, or stop consuming the artifact")})
}

// InputSetRecordable is the recorder's admission test. A refusal is written
// only when BOTH hold:
//
//  1. the record contract holds WITHOUT the input_artifacts key — so the
//     declared input set was the request's ONLY defect. The schema refuses the
//     EMPTY array (minItems 1) and an entry with no id before ValidateRequest's
//     own clause can see them; without this test those two refusals would be
//     returned to the caller and never reach the ledger, which is the orphan
//     Step 6 exists to prevent.
//  2. the event refusalData derives satisfies model_rejected's own contract
//     (trajectory.schema.json), so the framework never writes an event that
//     turns verify_trajectory red on a campaign it wrote itself.
//
// A request that fails the record contract anywhere else is still refused with
// no event: its role/kind may not be model_rejected's vocabulary at all, and
// writing it would violate that definition.
//
// EXPORTED for the file-drop transport (internal/feed): the feed refuses a
// drop file's own request record on the same ValidateRequest error and must
// draw this exact distinction — record the declared-input-set refusal, stay
// silent on a malformed record. Feed cannot reach the unexported predicate,
// and duplicating the rule would let the two transports drift apart, so the
// gate is shared rather than copied.
func InputSetRecordable(request validation.Value, why string) bool {
	if validation.Validate(withoutDeclaration(request), "model_request", 1) != nil {
		return false
	}
	violation, err := validation.ValidateDefinition(refusalData(request, why),
		"trajectory", "model_rejected")
	return err == nil && violation == nil
}

// withoutDeclaration is request minus its input_artifacts key (a copy: the
// caller's record is never modified).
func withoutDeclaration(request validation.Value) validation.Value {
	out := validation.VObj()
	for _, kv := range request.O {
		if kv.K != "input_artifacts" {
			out.O = append(out.O, kv)
		}
	}
	return out
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
	// The schema cannot see a MISSING key (the record is still valid without
	// it, which is what keeps historical requests validating); minItems covers
	// the empty array. This clause covers the absence.
	if len(DeclaredInputArtifacts(request)) == 0 {
		return &BoundaryError{Msg: "model request declares no input artifact set"}
	}
	if outside := InputArtifactsOutsideDeclaration(request); len(outside) > 0 {
		return &BoundaryError{Msg: fmt.Sprintf(
			"model request cites artifact %s outside its declared input set",
			outside[0])}
	}
	return nil
}

// ValidateResponse is validate_response: fail-closed validation of one model
// response. campaign may be nil (the schema/cross-field rules that need
// campaign state are then skipped, exactly like Python).
func ValidateResponse(role, kind string, payload validation.Value,
	campaign *state.Campaign) error {
	if !slices.Contains(ResponseKinds, kind) {
		return &BoundaryError{Msg: fmt.Sprintf("unknown response kind %s",
			validation.PyReprStr(kind))}
	}
	allowed, ok := roleKinds(role)
	if !ok {
		return &BoundaryError{Msg: fmt.Sprintf("unknown role %s",
			validation.PyReprStr(role))}
	}
	if !slices.Contains(allowed, kind) {
		return &BoundaryError{Msg: fmt.Sprintf(
			"role %s may not emit a %s response (allowed: %s)",
			validation.PyReprStr(role), validation.PyReprStr(kind),
			validation.PyListRepr(allowed))}
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
