// components_test.go: G9 opaque-surface projection — one display line per
// model component. TDD: written BEFORE components.go; must FAIL (undefined
// ComponentSurfaceLines) until the projection lands.
package protocolgraph

import (
	"testing"

	"websec/internal/validation"
)

// compModel wraps components in a minimal valid model shell.
func compModel(t *testing.T, comps ...validation.Value) validation.Value {
	t.Helper()
	return validation.VObj(
		validation.KV{K: "protocol_id", V: validation.VStr("p")},
		validation.KV{K: "name", V: validation.VStr("nn")},
		validation.KV{K: "contracts", V: validation.VArr()},
		validation.KV{K: "actors", V: validation.VArr()},
		validation.KV{K: "assets", V: validation.VArr()},
		validation.KV{K: "relations", V: validation.VArr()},
		validation.KV{K: "components", V: validation.VArr(comps...)},
	)
}

func comp(kind, path, url, trust string, inScope, paidFor bool) validation.Value {
	o := validation.VObj(
		validation.KV{K: "kind", V: validation.VStr(kind)},
		validation.KV{K: "trust", V: validation.VStr(trust)},
		validation.KV{K: "in_scope", V: validation.VBool(inScope)},
		validation.KV{K: "paid_for", V: validation.VBool(paidFor)},
	)
	if path != "" {
		o.O = append(o.O, validation.KV{K: "path", V: validation.VStr(path)})
	}
	if url != "" {
		o.O = append(o.O, validation.KV{K: "url", V: validation.VStr(url)})
	}
	return o
}

func TestComponentSurfaceLinesScopeAndPaid(t *testing.T) {
	m := compModel(t,
		comp("frontend", "app/", "", "untrusted", true, true),
		comp("relayer", "", "https://relay.example", "semi-trusted", false, false),
	)
	got := ComponentSurfaceLines(m)
	want := []string{
		"- frontend app/: in_scope, paid",
		"- relayer https://relay.example: out-of-scope",
	}
	if len(got) != len(want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestComponentSurfaceLinesPathBeatsURL(t *testing.T) {
	m := compModel(t,
		comp("keeper-service", "ops/keeper/", "https://keeper.example", "trusted", true, false),
	)
	got := ComponentSurfaceLines(m)
	if len(got) != 1 || got[0] != "- keeper-service ops/keeper/: in_scope" {
		t.Fatalf("lines = %q", got)
	}
}

func TestComponentSurfaceLinesAbsentOrEmptyIsNil(t *testing.T) {
	bare := validation.VObj(
		validation.KV{K: "protocol_id", V: validation.VStr("p")},
		validation.KV{K: "name", V: validation.VStr("nn")},
		validation.KV{K: "contracts", V: validation.VArr()},
		validation.KV{K: "actors", V: validation.VArr()},
		validation.KV{K: "assets", V: validation.VArr()},
		validation.KV{K: "relations", V: validation.VArr()},
	)
	if got := ComponentSurfaceLines(bare); len(got) != 0 {
		t.Fatalf("absent components must render nothing, got %q", got)
	}
	if got := ComponentSurfaceLines(compModel(t)); len(got) != 0 {
		t.Fatalf("empty components must render nothing, got %q", got)
	}
}
