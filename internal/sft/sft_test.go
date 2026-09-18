package sft

// Shared fixtures for the SFT tests: the isolated tmp store (Python's
// `sft_store` fixture) and the record shapes the ported tests mutate.

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

// promptText is PROPOSER_PROMPT_FILE.read_text().
func promptText(t *testing.T) string {
	t.Helper()
	text, err := proposerPromptText()
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// useStore is the `sft_store` fixture: an isolated tmp store dir, restored
// after the test (the real repo file is never touched).
func useStore(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(root, "sft"), 0o755); err != nil {
		t.Fatal(err)
	}
	SetStorePath(filepath.Join(root, "sft", ExamplesName))
	t.Cleanup(func() { SetStorePath("") })
	return root
}

// repoStore points the store at the committed repo file (the seed tests read
// it; nothing writes it).
func repoStore(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(wd, "..", "..", SFTDirName, ExamplesName)
	SetStorePath(p)
	t.Cleanup(func() { SetStorePath("") })
	return p
}

// baseExample is the Python `_base_example` fixture.
func baseExample(t *testing.T, over ...validation.KV) validation.Value {
	t.Helper()
	base := []validation.KV{
		kv("source", validation.VObj(
			kv("kind", validation.VStr("historical")),
			kv("ref", validation.VStr("doc-worked-example-1")),
			kv("cluster", validation.VStr("doc-worked-example-1")))),
		kv("taxonomy", validation.VStr("confirmed-critical")),
		kv("status", validation.VStr("draft")),
		kv("rejection_reasons", validation.VArr()),
		kv("partition", validation.VNull()),
		kv("messages", validation.VArr(
			validation.VObj(
				kv("role", validation.VStr("system")),
				kv("content", validation.VStr(promptText(t)))),
			validation.VObj(
				kv("role", validation.VStr("user")),
				kv("content", validation.VStr("<bundle>"))),
			validation.VObj(
				kv("role", validation.VStr("assistant")),
				kv("content", validation.VStr(
					"OBSERVATION: deposit() mints shares against totalAssets.\n"+
						"INITIAL FRAMING: inflation hypothesis.\n"+
						"A1 (x): does y hold?\n  -> CONFIRMED. because z\n"+
						"INVARIANT: shares proportional to value contributed.\n"+
						"IMPACT: attacker extracts 50,000 tokens from the victim deposit."))))),
		kv("structured", validation.VObj(
			kv("bug_class", validation.VStr("first-depositor-inflation")),
			kv("claim", validation.VStr(
				"attacker inflates share price before victim deposit")),
			kv("assumptions", validation.VArr(validation.VObj(
				kv("id", validation.VStr("A1")),
				kv("text", validation.VStr("direct transfer bypasses deposit()")),
				kv("status", validation.VStr("CONFIRMED")),
				kv("reason", validation.VStr(
					"ERC20 transfer is open to anyone; no guard"))))),
			kv("invariants", validation.VArr(validation.VObj(
				kv("statement", validation.VStr(
					"shares minted proportional to value contributed")),
				kv("status", validation.VStr("VIOLATED"))))),
			kv("expected_impact", validation.VStr(
				"victim receives zero shares; attacker drains pool")),
			kv("next_test", validation.VStr(
				"fork PoC: deposit 1 wei, transfer N, victim deposits M")),
			kv("pivot_count", validation.VInt(0)))),
		kv("provenance", validation.VObj(
			kv("bundle_provenance", validation.VStr("hand-written")))),
		kv("created_at", validation.VStr("2026-07-15T00:00:00Z")),
	}
	return validation.VObj(mergeKV(base, over)...)
}

// invalidExample is the Python `b` example in test_list_filters: an
// invalid-hypothesis whose REFUTED assumption names the misreading.
func invalidExample(t *testing.T) validation.Value {
	t.Helper()
	trace := "OBSERVATION: deposit() mints shares against totalAssets.\n" +
		"INITIAL FRAMING: inflation hypothesis.\n" +
		"A1 (x): does y hold?\n" +
		"  -> REFUTED. I misread the mint math; actually the division " +
		"rounds in the depositor's favor on this path.\n" +
		"INVARIANT: shares proportional to value contributed.\n" +
		"IMPACT: no loss on this path; 0 tokens leave the pool."
	structured := validation.VObj(
		kv("bug_class", validation.VStr("first-depositor-inflation")),
		kv("claim", validation.VStr(
			"attacker inflates share price before victim deposit")),
		kv("assumptions", validation.VArr(validation.VObj(
			kv("id", validation.VStr("A1")),
			kv("text", validation.VStr("direct transfer bypasses deposit()")),
			kv("status", validation.VStr("REFUTED")),
			kv("reason", validation.VStr("I misread the mint math; actually "+
				"the division is safe on this path"))))),
		kv("invariants", validation.VArr(validation.VObj(
			kv("statement", validation.VStr(
				"shares minted proportional to value contributed")),
			kv("status", validation.VStr("HOLDS"))))),
		kv("expected_impact", validation.VStr("no loss; the deposit path is safe")),
		kv("next_test", validation.VStr(
			"fork PoC: deposit and assert shares match")),
		kv("pivot_count", validation.VInt(0)))
	return baseExample(t,
		kv("taxonomy", validation.VStr("invalid-hypothesis")),
		kv("messages", validation.VArr(
			validation.VObj(
				kv("role", validation.VStr("system")),
				kv("content", validation.VStr(promptText(t)))),
			validation.VObj(
				kv("role", validation.VStr("user")),
				kv("content", validation.VStr("<bundle>"))),
			validation.VObj(
				kv("role", validation.VStr("assistant")),
				kv("content", validation.VStr(trace))))),
		kv("structured", structured))
}

func mergeKV(base, over []validation.KV) []validation.KV {
	out := append([]validation.KV(nil), base...)
	for _, o := range over {
		replaced := false
		for i := range out {
			if out[i].K == o.K {
				out[i].V = o.V
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, o)
		}
	}
	return out
}

// setAt writes val at a nested path (test mutation helper: Python mutates
// dicts in place; the port's values are copied by setKey).
func setAt(v, val validation.Value, path ...string) validation.Value {
	if len(path) == 1 {
		return setKey(v, path[0], val)
	}
	return setKey(v, path[0], setAt(validation.ObjAt(v, path[0]), val, path[1:]...))
}

// atPath reads a nested key.
func atPath(v validation.Value, path ...string) validation.Value {
	cur := v
	for _, p := range path {
		cur = validation.ObjAt(cur, p)
	}
	return cur
}
