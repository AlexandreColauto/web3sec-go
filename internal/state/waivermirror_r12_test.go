package state

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

// TestWaiverMirrorIsPoliced pins r12 issue 5: waivers.jsonl rows were
// recorded outside every integrity check — delete the file and audit
// stayed green while `waive` claimed dispositions the ledger had no
// memory of (or vice versa). The file and the completion.waived events
// are one projection pair now.
func TestWaiverMirrorIsPoliced(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "C-waivepol001", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Write a waiver the normal way (row + event) — still green.
	wp := filepath.Join(c.Dir, "waivers.jsonl")
	row := validation.VObj(
		kv("stage", validation.VStr("discovery")),
		kv("subject", validation.VStr("*")),
		kv("actor", validation.VStr("alice")),
		kv("reason", validation.VStr("plan-free campaign")),
		kv("at", validation.VStr(NowIso())),
	)
	if err := validation.AppendJsonlAscii(wp, validation.DumpsOrdered(row, false)); err != nil {
		t.Fatal(err)
	}
	ref := "discovery"
	data := validation.VObj(
		kv("subject", validation.VStr("*")),
		kv("actor", validation.VStr("alice")),
		kv("reason", validation.VStr("plan-free campaign")),
	)
	if _, err := c.Log("completion.waived", &ref, &data); err != nil {
		t.Fatal(err)
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Fatalf("paired waiver must verify: %v %v", v.Problems, err)
	}
	// Delete the file only: the events now name missing rows -> red.
	if err := os.Remove(wp); err != nil {
		t.Fatal(err)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK || len(v.Problems) == 0 {
		t.Fatalf("deleted waiver file must burn red: %v", v.Problems)
	}
	found := false
	for _, p := range v.Problems {
		if containsR12(p, "completion.waived") {
			found = true
		}
	}
	if !found {
		t.Fatalf("problem must name the waiver event gap: %v", v.Problems)
	}
}

func containsR12(h, n string) bool {
	return len(h) > 0 && n != "" &&
		(len(n) <= len(h) && (func() bool {
			for i := 0; i+len(n) <= len(h); i++ {
				if h[i:i+len(n)] == n {
					return true
				}
			}
			return false
		})())
}
