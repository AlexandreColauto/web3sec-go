package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// setField is a local setOrAppend: replace (or append) one key on an object,
// preserving key order.
func setField(f validation.Value, key string, v validation.Value) validation.Value {
	var out []validation.KV
	replaced := false
	for _, kv := range f.O {
		if kv.K == key {
			if !replaced {
				out = append(out, validation.KV{K: key, V: v})
				replaced = true
			}
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, validation.KV{K: key, V: v})
	}
	return validation.Value{Kind: validation.Obj, O: out}
}

func ingestedFinding(t *testing.T, camp *state.Campaign) validation.Value {
	t.Helper()
	f, err := findings.IngestHypothesis(camp, validation.VObj(
		kv("title", validation.VStr("Evidence-level finding")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("description", validation.VStr("the oracle round method is manipulable")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("round"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
	), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// A SINGLE evidence item with an unknown level must be rejected. Before the
// fix the level check lived only inside the sort comparator, which is never
// invoked on a 1-element slice, so the bad level rendered silently.
func TestEvidenceLevelSingleItemValidated(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Ev Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	f := ingestedFinding(t, camp)
	f = setField(f, "evidence", validation.VArr(
		validation.VObj(
			kv("level", validation.VStr("E99")),
			kv("type", validation.VStr("manual")),
			kv("description", validation.VStr("a single, badly-leveled item"))),
	))
	_, err = findingSection(camp, f, "CONFIRMED", []validation.Value{f})
	if err == nil {
		t.Fatal("findingSection with a single invalid evidence level must error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown evidence level") {
		t.Errorf("error = %q, want it to mention 'unknown evidence level'", err.Error())
	}
}

// A known level in a single-item array must still render (the upfront
// validation must not over-reject valid levels).
func TestEvidenceLevelSingleItemValidRenders(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Ev Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	f := ingestedFinding(t, camp)
	f = setField(f, "evidence", validation.VArr(
		validation.VObj(
			kv("level", validation.VStr("E4")),
			kv("type", validation.VStr("manual")),
			kv("description", validation.VStr("a single, well-leveled item"))),
	))
	sec, err := findingSection(camp, f, "CONFIRMED", []validation.Value{f})
	if err != nil {
		t.Fatalf("findingSection with a valid single evidence level must not error: %v", err)
	}
	joined := strings.Join(sec, "\n")
	if !strings.Contains(joined, "- E4 [manual]") {
		t.Errorf("evidence ladder line missing '- E4 [manual]': %q", joined)
	}
}

// An ANSWERED plan priority whose closed_ref is an EMPTY STRING (not just
// absent/null) must be flagged as having no evidence ref. Before the fix only
// a null ref was treated as "no ref", so an empty-string ref slipped through
// unflagged.
func TestClosedRefEmptyStringFlagged(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Ref Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	plan := `{
  "priorities": [
    {"id": "P-EMPTY", "question": "can the vault be drained?",
     "status": "answered", "closed_ref": "", "closed_reason": "closed it"},
    {"id": "P-NULL", "question": "is the oracle manipulable?",
     "status": "answered", "closed_reason": "closed it"}
  ]
}`
	if err := os.WriteFile(filepath.Join(camp.ArtifactsDir, "campaign_plan.json"),
		[]byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := Generate(camp)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	// The empty-string ref must be flagged.
	if !strings.Contains(text, "P-EMPTY** (answered, no evidence ref)") {
		t.Errorf("P-EMPTY (empty-string closed_ref) not flagged:\n%s", text)
	}
	// The null ref (P-NULL, no closed_ref key) must ALSO be flagged.
	if !strings.Contains(text, "P-NULL** (answered, no evidence ref)") {
		t.Errorf("P-NULL (null closed_ref) not flagged:\n%s", text)
	}
}
