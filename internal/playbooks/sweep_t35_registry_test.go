package playbooks_test

import (
	"strings"
	"testing"

	"websec/internal/boundary"
	"websec/internal/playbooks"
	"websec/internal/validation"
)

// Port of tests/test_playbooks.py::test_playbook_tool_ids_are_all_in_the_registry.
func TestPlaybookToolIDsAreAllInTheRegistry(t *testing.T) {
	reg := boundary.ToolRegistry()
	for _, cls := range shippedClassesExt {
		pb, found, err := playbooks.PlaybookForClass(cls)
		if err != nil || !found {
			t.Fatalf("playbook_for_class(%q) = %v, %v", cls, found, err)
		}
		for _, tool := range playbookTools(pb) {
			if !containsString(reg, tool) {
				t.Errorf("%s: tool id %q outside the registry", cls, tool)
			}
		}
	}
}

// Port of tests/test_outcome_events.py::test_new_playbook_tool_ids_are_in_the_registry.
func TestNewPlaybookToolIDsAreInTheRegistry(t *testing.T) {
	reg := boundary.ToolRegistry()
	for _, cls := range []string{"reentrancy", "upgrade-initializer",
		"bridge-message"} {
		pb, found, err := playbooks.PlaybookForClass(cls)
		if err != nil || !found {
			t.Fatalf("playbook_for_class(%q) = %v, %v", cls, found, err)
		}
		for _, tool := range playbookTools(pb) {
			if !containsString(reg, tool) {
				t.Errorf("%s: tool id %q outside the registry", cls, tool)
			}
		}
	}
}

// playbookTools is {step.tool_id} ∪ {template.preferred_tools}.
func playbookTools(pb validation.Value) []string {
	out := []string{}
	for _, step := range vObj(pb, "hunt_order").A {
		if id := vObj(step, "tool_id"); id.Kind == validation.Str {
			out = append(out, id.S)
		}
	}
	for _, at := range vObj(pb, "assumption_templates").A {
		for _, tool := range vObj(at, "preferred_tools").A {
			out = append(out, tool.S)
		}
	}
	return out
}

// playbookStrings reads a top-level array of strings.
func playbookStrings(pb validation.Value, key string) []string {
	out := []string{}
	for _, kv := range pb.O {
		if kv.K == key && kv.V.Kind == validation.Arr {
			for _, v := range kv.V.A {
				out = append(out, v.S)
			}
		}
	}
	return out
}

// containsString is a slice membership check.
func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// shippedClassesExt mirrors the in-package shippedClasses fixture — and,
// since H10, covers ALL TEN shipped playbooks: the eight original classes
// plus frontend-injection and infra-boundary, which landed later and were
// never widened here. The registry-completeness intent is the point: a tool
// id referenced ONLY by one of those two playbooks was outside this test's
// reach.
var shippedClassesExt = []string{
	"access-control", "bridge-message", "economic-invariant",
	"frontend-injection", "infra-boundary", "oracle-manipulation",
	"precision-rounding", "reentrancy", "share-price-inflation",
	"upgrade-initializer",
}

// vObj reads a key from an object value (objAt is unexported).
func vObj(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.Value{}
}

var _ = strings.Join
