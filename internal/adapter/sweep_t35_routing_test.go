package adapter

// Port of tests/test_history_learning.py::test_routing_table_and_adapter.

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func TestRoutingTableAndAdapter(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Route(c, "adversarial-critic"); err != nil ||
		got != "expensive" {
		t.Errorf("route(adversarial-critic) = %q %v, want expensive", got, err)
	}
	if got, err := Route(c, "hypothesis-triage"); err != nil || got != "cheap" {
		t.Errorf("route(hypothesis-triage) = %q %v, want cheap", got, err)
	}
	table, err := RoutingTable(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(table, "exploit-chaining"), "budget_class"); got != "expensive" {
		t.Errorf("routing_table[exploit-chaining].budget_class = %q", got)
	}
	if _, err := PromptPath("nonexistent-stage"); err == nil ||
		!strings.Contains(err.Error(), "unknown stage") {
		t.Errorf("resolve_prompt(unknown) err = %v, want a KeyError-like error",
			err)
	}
	// prompt resolution works for a mapped stage (file exists in repo)
	p, err := PromptPath("protocol-reconstruction")
	if err != nil {
		t.Fatal(err)
	}
	if p == "" {
		t.Fatal("resolved prompt path is empty")
	}
	_, rel, err := StageConfig("protocol-reconstruction")
	if err != nil {
		t.Fatal(err)
	}
	text, err := PromptText(rel)
	if err != nil {
		t.Fatalf("resolved prompt %s unreadable: %v", p, err)
	}
	head := text
	if len(head) > 200 {
		head = head[:200]
	}
	if !strings.Contains(head, "Stage 01") {
		t.Errorf("prompt head = %q, want Stage 01", head)
	}
	_ = validation.VNull()
}
