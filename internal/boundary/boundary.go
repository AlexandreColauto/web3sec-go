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
