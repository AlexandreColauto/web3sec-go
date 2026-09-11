package report

// G15 PoC quality gate at mint (Task 23): the evidence ladder renders the
// reruns/fork_stale advisories presence-gated — an item without the keys
// renders exactly as before.

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func g15Section(t *testing.T, items ...validation.Value) string {
	t.Helper()
	root := t.TempDir()
	camp, err := state.Init(root, "G15 Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	f := ingestedFinding(t, camp)
	f = setField(f, "evidence", validation.VArr(items...))
	sec, err := findingSection(camp, f, "CONFIRMED", []validation.Value{f})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(sec, "\n")
}

func g15Item(extra ...validation.KV) validation.Value {
	base := []validation.KV{
		kv("evidence_id", validation.VStr("EV-abc123")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("unit PoC drains")),
		kv("sandbox_profile", validation.VStr("docker-networkless")),
	}
	return validation.VObj(append(base, extra...)...)
}

// Both advisories present: the line carries both suffixes.
func TestG15EvidenceAdvisoriesRender(t *testing.T) {
	joined := g15Section(t, g15Item(
		kv("reruns", validation.VStr("3/3")),
		kv("fork_stale", validation.VStr("snapshot pinned x — re-pin")),
	))
	want := "- E4 [foundry-test] unit PoC drains " +
		"(sandbox: docker-networkless) [reruns 3/3] [fork stale]"
	if !strings.Contains(joined, want) {
		t.Fatalf("ladder line missing %q:\n%s", want, joined)
	}
}

// Flaky value renders verbatim.
func TestG15EvidenceFlakyRenders(t *testing.T) {
	joined := g15Section(t, g15Item(
		kv("reruns", validation.VStr("flaky 2/3")),
	))
	if !strings.Contains(joined, "[reruns flaky 2/3]") {
		t.Fatalf("ladder line missing flaky suffix:\n%s", joined)
	}
	if strings.Contains(joined, "[fork stale]") {
		t.Fatalf("ladder line gained a fork suffix it should not have:\n%s",
			joined)
	}
}

// The evidence join renders verbatim inside the reruns suffix.
func TestG15EvidenceJoinRenders(t *testing.T) {
	joined := g15Section(t, g15Item(
		kv("reruns", validation.VStr(
			"3/3 (execs EXEC-a,EXEC-b,EXEC-c)")),
	))
	want := "[reruns 3/3 (execs EXEC-a,EXEC-b,EXEC-c)]"
	if !strings.Contains(joined, want) {
		t.Fatalf("ladder line missing %q:\n%s", want, joined)
	}
}

// Neither key: the line is byte-identical to the pre-G15 shape.
func TestG15EvidenceSilentRendersUnchanged(t *testing.T) {
	joined := g15Section(t, g15Item())
	want := "- E4 [foundry-test] unit PoC drains " +
		"(sandbox: docker-networkless)"
	if !strings.Contains(joined, want) {
		t.Fatalf("ladder line missing %q:\n%s", want, joined)
	}
	if strings.Contains(joined, "[reruns") ||
		strings.Contains(joined, "[fork stale]") {
		t.Fatalf("silent item gained an advisory suffix:\n%s", joined)
	}
}
