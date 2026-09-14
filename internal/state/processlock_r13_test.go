package state

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"websec/internal/validation"
)

// TestConcurrentLoggersKeepOneLedger is the r13 issue-1 law: two
// PROCESSES appending events must never mint duplicate seqs or drop a
// record while both report success. The critical path is
// read-tail→append→mirror-save; the campaign lock makes it atomic
// across processes.
func TestConcurrentLoggersKeepOneLedger(t *testing.T) {
	if os.Getenv("WEBV2_LOCKWORKER") != "" {
		lockWorker() // never returns
	}
	root := t.TempDir()
	c, err := Init(root, "Lock Race Program",
		InitOpts{CampaignID: "C-lockrace001"})
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	codes := make([]int, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(self, "-test.run=TestConcurrentLoggersKeepOneLedger")
			cmd.Env = append(os.Environ(),
				"WEBV2_LOCKWORKER=1",
				"WEBV2_LOCKROOT="+root,
				"WEBV2_LOCKID=C-lockrace001",
				"WEBV2_LOCKTEXT=worker event "+strings.Repeat("x", i+1))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("worker %d: %v\n%s", i, err, out)
				codes[i] = 1
				return
			}
			codes[i] = 0
		}(i)
	}
	wg.Wait()
	for i, code := range codes {
		if code != 0 {
			t.Fatalf("worker %d failed", i)
		}
	}
	// The ledger: contiguous seqs, every worker's event present once.
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	seqs := []int{}
	texts := map[string]int{}
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("ledger line does not parse: %v", err)
		}
		seqs = append(seqs, int(e["seq"].(float64)))
		if e["type"] == "note.added" {
			d, _ := e["data"].(map[string]any)
			texts[d["text"].(string)]++
		}
	}
	if len(seqs) != 7 { // campaign.created + 6 workers
		t.Fatalf("events = %d, want 7: %v", len(seqs), seqs)
	}
	for i, s := range seqs {
		if s != i {
			t.Fatalf("seq gap/duplicate: %v", seqs)
		}
	}
	for i := 0; i < 6; i++ {
		want := "worker event " + strings.Repeat("x", i+1)
		if texts[want] != 1 {
			t.Fatalf("event %q recorded %d times: %v", want, texts[want], texts)
		}
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("verify red after race: %v", v.Problems)
	}
}

// lockWorker appends exactly one event, as a separate process.
func lockWorker() {
	root := os.Getenv("WEBV2_LOCKROOT")
	text := os.Getenv("WEBV2_LOCKTEXT")
	c, err := Open(root, os.Getenv("WEBV2_LOCKID"))
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	data := validation.VObj(
		validation.KV{K: "text", V: validation.VStr(text)})
	if _, err := c.Log("note.added", nil, &data); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}

var _ = filepath.Join
