package report

// Task 6 (G9) report tests — the tracked-but-opaque component surfaces
// block. TDD: written BEFORE the componentSurfacesBlock hookup; must FAIL
// (undefined componentSurfacesBlock) until report.go renders it.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/protocolgraph"
	"websec/internal/validation"
)

func TestComponentSurfacesAbsentWithoutModel(t *testing.T) {
	camp := clusterCamp(t)
	if got := componentSurfacesBlock(camp); len(got) != 0 {
		t.Fatalf("no model must render no block, got %q", got)
	}
	text := mustGenerate(t, camp)
	if strings.Contains(text, "Tracked-but-opaque") {
		t.Fatal("components block rendered without a model")
	}
}

func TestComponentSurfacesRendersComponentLines(t *testing.T) {
	camp := clusterCamp(t)
	model := validation.VObj(
		kv("protocol_id", validation.VStr("p")),
		kv("name", validation.VStr("nn")),
		kv("contracts", validation.VArr()),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("relations", validation.VArr()),
		kv("components", validation.VArr(validation.VObj(
			kv("kind", validation.VStr("frontend")),
			kv("path", validation.VStr("app/")),
			kv("trust", validation.VStr("untrusted")),
			kv("in_scope", validation.VBool(true)),
			kv("paid_for", validation.VBool(true)),
		))),
	)
	if _, err := protocolgraph.SaveModel(camp, model, filepath.Join(
		camp.ArtifactsDir, "protocol_model.json")); err != nil {
		t.Fatal(err)
	}
	block := componentSurfacesBlock(camp)
	if len(block) == 0 {
		t.Fatal("components block missing with a component model")
	}
	joined := strings.Join(block, "\n")
	if !strings.Contains(joined, "- frontend app/: in_scope, paid") {
		t.Fatalf("block missing component line:\n%s", joined)
	}
	text := mustGenerate(t, camp)
	if !strings.Contains(text, "- frontend app/: in_scope, paid") {
		t.Fatal("generated report missing the component line")
	}
}
