package cli

// D1: the embedded prompts are servable without a framework checkout.

import (
	"strings"
	"testing"
)

func TestPromptsListNamesTheEvalPrompt(t *testing.T) {
	code, out, errS := run(t, "prompts", "list")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "37_protocol_knowledge_graph.md\n") {
		t.Fatalf("list lacks the protocol-model prompt:\n%s", out)
	}
	if !strings.Contains(out, "39_trajectory_dispatch.md\n") {
		t.Fatalf("list lacks the dispatch prompt:\n%s", out)
	}
}

func TestPromptsShowAcceptsEveryNameShape(t *testing.T) {
	for _, name := range []string{"37_protocol_knowledge_graph.md",
		"37_protocol_knowledge_graph", "protocol_knowledge_graph", "37"} {
		code, out, errS := run(t, "prompts", "show", name)
		if code != 0 {
			t.Fatalf("show %q exit %d: %q", name, code, errS)
		}
		if !strings.Contains(out, "protocol") {
			t.Fatalf("show %q output does not read like the prompt: %.80q",
				name, out)
		}
	}
}

func TestPromptsShowUnknownFailsLoud(t *testing.T) {
	code, _, errS := run(t, "prompts", "show", "no-such-prompt")
	if code == 0 {
		t.Fatal("unknown prompt must fail")
	}
	if !strings.Contains(errS, "no prompt matching") ||
		!strings.Contains(errS, "prompts list") {
		t.Fatalf("error does not route to list: %q", errS)
	}
}
