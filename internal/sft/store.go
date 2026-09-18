package sft

// store.go ports the SFT store operations: add (validate + lint + assign id +
// atomic append), list filters, get, the status-transition path, and the
// chat-format JSONL export. The store is committed data: every write is
// validated first, so a rejected example never leaves a partial file.

import (
	"fmt"
	"slices"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// transitions is _TRANSITIONS: the legal status moves.
var transitions = map[string][]string{
	"draft":    {"curated", "rejected"},
	"curated":  {"rejected"},
	"rejected": {"draft"},
}

// AddExample is add_example: validate (schema + lint), assign an id, append,
// persist atomically. The caller's value is never mutated.
func AddExample(example validation.Value, status string) (validation.Value, error) {
	if !slices.Contains(Statuses, status) {
		return validation.VNull(), fmt.Errorf("unknown status %s; known: %s",
			validation.PyReprStr(status), pyListRepr(Statuses))
	}
	store, err := LoadStore()
	if err != nil {
		return validation.VNull(), err
	}
	ex := cloneValue(example)
	idVal := validation.ObjAt(ex, "id")
	if truthy(idVal) {
		if findExample(store, pyStrValue(idVal)).Kind != validation.Null {
			return validation.VNull(), fmt.Errorf("example id %s already "+
				"exists in the store", pyStrValue(idVal))
		}
	} else {
		ex = delKey(ex, "id")
		ex = setKey(ex, "id", validation.VStr(NextExampleID(store)))
	}
	ex = setKey(ex, "status", validation.VStr(status))
	ex.O = validation.SetDefault(ex.O, "version", validation.VInt(1))
	ex.O = validation.SetDefault(ex.O, "rejection_reasons", validation.VArr())
	ex.O = validation.SetDefault(ex.O, "partition", validation.VNull())
	ex.O = validation.SetDefault(ex.O, "created_at", validation.VStr(state.NowIso()))
	ex.O = validation.SetDefault(ex.O, "curated_by", validation.VNull())
	if status == "rejected" && len(validation.ObjAt(ex, "rejection_reasons").A) == 0 {
		return validation.VNull(), fmt.Errorf("status=rejected requires " +
			"non-empty rejection_reasons")
	}
	if err := validation.Validate(ex, "sft_example", 1); err != nil {
		return validation.VNull(), fmt.Errorf("sft_example schema violation: %s",
			schemaMsg(err))
	}
	existing := curatedExcept(store, validation.ObjStr(ex, "id"))
	hard := hardReasons(LintExample(ex, existing, status))
	if len(hard) > 0 {
		return validation.VNull(), fmt.Errorf("sft lint failed: %s",
			strings.Join(hard, "; "))
	}
	examples := append([]validation.Value(nil), validation.ObjAt(store, "examples").A...)
	store = setKey(store, "examples",
		validation.VArr(append(examples, ex)...))
	if err := SaveStore(store); err != nil {
		return validation.VNull(), err
	}
	return ex, nil
}

// ListExamples is list_examples: the store rows matching the filters (nil =
// no filter, matching Python's None).
func ListExamples(status, partition, taxonomy *string) ([]validation.Value,
	error) {
	store, err := LoadStore()
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, e := range validation.ObjAt(store, "examples").A {
		if status != nil && validation.ObjStr(e, "status") != *status {
			continue
		}
		if partition != nil && validation.ObjStr(e, "partition") != *partition {
			continue
		}
		if taxonomy != nil && validation.ObjStr(e, "taxonomy") != *taxonomy {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// GetExample is get_example: the stored row, or the KeyError Python raises.
func GetExample(exampleID string) (validation.Value, error) {
	store, err := LoadStore()
	if err != nil {
		return validation.VNull(), err
	}
	got := findExample(store, exampleID)
	if got.Kind == validation.Null {
		return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(exampleID))
	}
	return got, nil
}

// UpdateExample is update_example: the status-transition path (no content
// edits — those happen in the file before add). draft->curated re-runs lint
// and bumps version. nil pointers mean "not supplied".
func UpdateExample(exampleID string, status, curatedBy *string,
	rejectionReasons []string) (validation.Value, error) {
	store, err := LoadStore()
	if err != nil {
		return validation.VNull(), err
	}
	examples := validation.ObjAt(store, "examples").A
	idx := -1
	for i, e := range examples {
		if validation.ObjStr(e, "id") == exampleID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(exampleID))
	}
	ex := cloneValue(examples[idx])
	old := validation.ObjStr(ex, "status")
	if status != nil {
		if !slices.Contains(Statuses, *status) {
			return validation.VNull(), fmt.Errorf("unknown status %s",
				validation.PyReprStr(*status))
		}
		if !slices.Contains(transitions[old], *status) {
			return validation.VNull(), fmt.Errorf("illegal transition %s -> %s",
				old, *status)
		}
		ex = setKey(ex, "status", validation.VStr(*status))
	}
	if curatedBy != nil {
		ex = setKey(ex, "curated_by", validation.VStr(*curatedBy))
	}
	if rejectionReasons != nil {
		ex = setKey(ex, "rejection_reasons", validation.StrArr(rejectionReasons))
	}
	if validation.ObjStr(ex, "status") == "rejected" &&
		len(validation.ObjAt(ex, "rejection_reasons").A) == 0 {
		return validation.VNull(), fmt.Errorf("status=rejected requires " +
			"non-empty rejection_reasons")
	}
	if validation.ObjStr(ex, "status") == "curated" {
		existing := curatedExcept(store, exampleID)
		hard := hardReasons(LintExample(ex, existing, "curated"))
		if len(hard) > 0 {
			return validation.VNull(), fmt.Errorf(
				"sft lint failed on curation: %s", strings.Join(hard, "; "))
		}
		ex = setKey(ex, "version", validation.VInt(int64(intOf(
			validation.ObjAt(ex, "version"))+1)))
	}
	if err := validation.Validate(ex, "sft_example", 1); err != nil {
		return validation.VNull(), fmt.Errorf("sft_example schema violation: %s",
			schemaMsg(err))
	}
	updated := append([]validation.Value(nil), examples...)
	updated[idx] = ex
	store = setKey(store, "examples", validation.VArr(updated...))
	if err := SaveStore(store); err != nil {
		return validation.VNull(), err
	}
	return ex, nil
}

// ExportJSONL is export_jsonl: chat-format lines for training pipelines,
// curated examples only, messages verbatim.
func ExportJSONL(partition *string) (string, error) {
	store, err := LoadStore()
	if err != nil {
		return "", err
	}
	lines := []string{}
	for _, e := range validation.ObjAt(store, "examples").A {
		if validation.ObjStr(e, "status") != "curated" {
			continue
		}
		if partition != nil && validation.ObjStr(e, "partition") != *partition {
			continue
		}
		lines = append(lines, validation.DumpsOrdered(validation.VObj(
			validation.KV{K: "messages", V: validation.ObjAt(e, "messages")}), false))
	}
	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// ---- helpers -------------------------------------------------------------

func findExample(store validation.Value, id string) validation.Value {
	for _, e := range validation.ObjAt(store, "examples").A {
		if validation.ObjStr(e, "id") == id {
			return e
		}
	}
	return validation.VNull()
}

func curatedExcept(store validation.Value, id string) []validation.Value {
	out := []validation.Value{}
	for _, e := range validation.ObjAt(store, "examples").A {
		if validation.ObjStr(e, "status") == "curated" && validation.ObjStr(e, "id") != id {
			out = append(out, e)
		}
	}
	return out
}

func hardReasons(reasons []string) []string {
	out := []string{}
	for _, r := range reasons {
		if !strings.HasPrefix(r, "warn:") {
			out = append(out, r)
		}
	}
	return out
}

func cloneValue(v validation.Value) validation.Value {
	out := v
	if v.Kind == validation.Arr {
		out.A = append([]validation.Value(nil), v.A...)
	}
	if v.Kind == validation.Obj {
		out.O = append([]validation.KV(nil), v.O...)
	}
	return out
}

func delKey(v validation.Value, key string) validation.Value {
	out := make([]validation.KV, 0, len(v.O))
	for _, kv := range v.O {
		if kv.K != key {
			out = append(out, kv)
		}
	}
	v.O = out
	return v
}

func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0
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

// pyListRepr is Python's list repr for the closed-vocabulary error text.
func pyListRepr(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, s := range items {
		quoted = append(quoted, validation.PyReprStr(s))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
