package state

import "websec/internal/validation"

import "testing"

// Re-Completing must REPLACE completed_by/completed_reason, not append a
// second copy — duplicate keys corrupt the projection.
func TestCompleteReplacesNotDuplicatesKeys(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete("op", "all findings reviewed and closed"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete("op2", "second closure decision recorded"); err != nil {
		t.Fatal(err)
	}
	st, _ := c.State()
	count := func(key string) int {
		n := 0
		for _, kv := range st.O {
			if kv.K == key {
				n++
			}
		}
		return n
	}
	if n := count("completed_by"); n != 1 {
		t.Errorf("completed_by appears %d times, want 1", n)
	}
	if n := count("completed_reason"); n != 1 {
		t.Errorf("completed_reason appears %d times, want 1", n)
	}
	if got := validation.ObjStr(st, "completed_by"); got != "op2" {
		t.Errorf("completed_by = %q, want op2 (replaced on re-Complete)", got)
	}
}
