package adapter

// Ported 1:1 from web3sec-final tests/test_adapter_prompts.py (adapter: the
// router and the prompt pack must never drift apart) plus the embedded-pack
// byte-identity acceptance check.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func TestEveryMappedPromptFileExists(t *testing.T) {
	inv, err := PromptInventory()
	if err != nil {
		t.Fatalf("prompt_inventory: %v", err)
	}
	if len(inv.O) == 0 {
		t.Fatal("router must not be empty")
	}
	for _, kv := range inv.O {
		if kv.V.Kind != validation.Str {
			continue
		}
		if _, err := os.Stat(kv.V.S); err == nil {
			continue
		}
		// no on-disk mirror (test cwd): the embedded pack is the source
		if _, err := PromptText(kv.V.S); err != nil {
			t.Errorf("router maps %s to a missing prompt file %s",
				kv.K, kv.V.S)
		}
	}
	// every STAGES row with a prompt resolves through the embedded pack too
	for _, s := range Stages {
		if s.Prompt == "" {
			continue
		}
		text, err := PromptText(s.Prompt)
		if err != nil {
			t.Errorf("stage %s: %v", s.ID, err)
			continue
		}
		if len(text) == 0 {
			t.Errorf("stage %s: embedded prompt %s is empty", s.ID, s.Prompt)
		}
	}
}

func TestNoUnmappedPromptFiles(t *testing.T) {
	loose, err := UnmappedPrompts()
	if err != nil {
		t.Fatalf("unmapped_prompts: %v", err)
	}
	if len(loose) != 0 {
		t.Fatalf("prompt files no stage routes to: %v", loose)
	}
}

func TestUnknownStageErrorListsKnownStages(t *testing.T) {
	_, err := Route(nil, "discovery-specialists")
	if err == nil {
		t.Fatal("expected an error for an unknown stage")
	}
	if !strings.Contains(err.Error(), "discovery-specialist") {
		t.Fatalf("error must list the known stages: %v", err)
	}
	if _, err := Route(nil, "Discovery"); err == nil ||
		!strings.Contains(err.Error(), "bad stage id") {
		t.Fatalf("malformed stage id must be a bad-stage-id error: %v", err)
	}
}

func TestDeterministicStageHasNoPrompt(t *testing.T) {
	det := []string{}
	for _, s := range Stages {
		if s.Prompt == "" {
			det = append(det, s.ID)
		}
	}
	if len(det) == 0 {
		t.Fatal("the deterministic stages should be declared with no prompt")
	}
	for _, stage := range det {
		_, err := PromptPath(stage)
		if err == nil {
			t.Fatalf("stage %s: expected a no-prompt error", stage)
		}
		if !strings.Contains(err.Error(), "deterministic") {
			t.Fatalf("stage %s: error must say deterministic: %v", stage, err)
		}
	}
}

func TestCampaignLocalRoutingOverrideWins(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(c.Dir, "routing.json"),
			[]byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"discovery-specialist": {"budget_class": "expensive"}}`)
	cls, err := Route(c, "discovery-specialist")
	if err != nil || cls != "expensive" {
		t.Fatalf("override lost: %q %v", cls, err)
	}
	// and a bare-string override shape works too
	write(`{"discovery-specialist": "cheap"}`)
	cls, err = Route(c, "discovery-specialist")
	if err != nil || cls != "cheap" {
		t.Fatalf("bare-string override lost: %q %v", cls, err)
	}
	// a non-string override is a loud error, not a silent default
	write(`{"discovery-specialist": 7}`)
	if _, err := Route(c, "discovery-specialist"); err == nil ||
		!strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("non-string override must fail loud: %v", err)
	}
}

func TestBudgetClassesAreTheDeclaredSet(t *testing.T) {
	if len(BudgetHints) != 4 {
		t.Fatalf("BUDGET_HINTS has %d classes, want 4", len(BudgetHints))
	}
	for _, s := range Stages {
		if _, ok := BudgetHintOf(s.BudgetClass); !ok {
			t.Errorf("stage %s has unknown budget class %s", s.ID, s.BudgetClass)
		}
	}
	// the error text uses sorted(BUDGET_HINTS)
	want := "cheap, deterministic, expensive, standard"
	if got := strings.Join(BudgetClassNames(), ", "); got != want {
		t.Errorf("sorted budget classes = %q, want %q", got, want)
	}
}

func TestBoundaryMatrixTextIsExact(t *testing.T) {
	m := BoundaryMatrix()
	if !strings.HasPrefix(m, "BOUNDARY MATRIX — trust boundary between you "+
		"and the deterministic core.\nYou may produce the left column; ONLY "+
		"code performs the right column:") {
		t.Fatalf("boundary matrix header drifted:\n%s", m)
	}
	if !strings.HasSuffix(m, "An evidence claim that names no real EXEC id, "+
		"or a status jump the\nstate machine forbids, is rejected — never "+
		"assumed true.") {
		t.Fatalf("boundary matrix footer drifted:\n%s", m)
	}
	if n := strings.Count(m, "\n  "); n != 9 {
		t.Fatalf("boundary matrix has %d rows, want 9", n)
	}
	if !strings.Contains(m, "  evidence E4+           | CANNOT claim — must "+
		"name a real EXEC id from THIS campaign | add_evidence() verifies "+
		"profile, exit 0, captured output") {
		t.Fatalf("E4+ row drifted:\n%s", m)
	}
}

func TestBuildContextCarriesBoundaryMatrixForBoundaryStages(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := BuildContext(c, "independent-verification", 60000, nil)
	if err != nil {
		t.Fatal(err)
	}
	titles := blockTitles(objAt(ctx, "blocks"))
	if !containsStr(titles, "boundary_matrix") {
		t.Fatalf("verification bundle lacks boundary_matrix: %v", titles)
	}
	if !containsStr(titles, "campaign") {
		t.Fatalf("bundle lacks the campaign block: %v", titles)
	}
	ctx2, err := BuildContext(c, "campaign-planning", 60000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(blockTitles(objAt(ctx2, "blocks")), "boundary_matrix") {
		t.Fatal("campaign-planning must NOT get the boundary matrix")
	}
	if objStr(ctx, "budget_class") != "expensive" {
		t.Fatalf("verification budget class = %q", objStr(ctx, "budget_class"))
	}
	if !strings.HasPrefix(objStr(ctx, "prompt"), "You are the discovery") &&
		len(objStr(ctx, "prompt")) == 0 {
		t.Fatal("prompt text is empty")
	}
	if objAt(ctx, "structured_outputs").Kind != validation.Obj {
		t.Fatal("structured_outputs missing")
	}
}

func TestEmbeddedPromptsByteIdenticalToPythonRepo(t *testing.T) {
	pyRoot := filepath.Join("..", "..", "..", "web3sec-final")
	for _, dir := range []string{"prompts", "prompts_legacy"} {
		pyDir := filepath.Join(pyRoot, dir)
		entries, err := os.ReadDir(pyDir)
		if err != nil {
			t.Skipf("reference prompt dir absent: %v", err)
		}
		n := 0
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			want, err := os.ReadFile(filepath.Join(pyDir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			got, err := PromptText(dir + "/" + e.Name())
			if err != nil {
				t.Fatalf("%s/%s: %v", dir, e.Name(), err)
			}
			if got != string(want) {
				t.Errorf("%s/%s is not byte-identical to the Python repo",
					dir, e.Name())
			}
			n++
		}
		if n == 0 {
			t.Fatalf("no prompt files found under %s", pyDir)
		}
	}
}

func blockTitles(blocks validation.Value) []string {
	out := []string{}
	for _, b := range blocks.A {
		out = append(out, objStr(b, "title"))
	}
	return out
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func objStr(v validation.Value, key string) string {
	x := objAt(v, key)
	if x.Kind == validation.Str {
		return x.S
	}
	return ""
}
