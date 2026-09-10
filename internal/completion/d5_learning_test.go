package completion

// d5_learning_test.go — D5: the reflection half of the learning proof. Before
// the `memory --reflect` flag, learning.ReflectionEntry had no caller outside
// its own test, so this proof item could never be cleared by any command. The
// test pins the reachability, not the file format: with a reflection entry
// appended through the same call the CLI makes, the item disappears.

import (
	"strings"
	"testing"

	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

func TestLearningProofDemandsReflectionUntilOneIsRecorded(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Reflection Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := ProofStatus(camp, "learning")
	if err != nil {
		t.Fatal(err)
	}
	if !learningProofMentions(before, "no reflection entry") {
		t.Fatalf("fresh campaign does not ask for a reflection entry: %v",
			validation.DumpsOrdered(before, true))
	}
	// The CLI's `--reflect` path, called directly.
	if _, err := learning.ReflectionEntry(camp, learning.ReflectionOpts{
		Round:               1,
		ProcessImprovements: []string{"the fork fixture needed an explicit block number"},
	}); err != nil {
		t.Fatal(err)
	}
	after, err := ProofStatus(camp, "learning")
	if err != nil {
		t.Fatal(err)
	}
	if learningProofMentions(after, "no reflection entry") {
		t.Fatalf("reflection entry did not clear the item: %v",
			validation.DumpsOrdered(after, true))
	}
}

// learningProofMentions reports whether the proof's serialized form contains s
// (the missing-item messages survive serialization verbatim).
func learningProofMentions(proof validation.Value, s string) bool {
	return strings.Contains(validation.DumpsOrdered(proof, false), s)
}
