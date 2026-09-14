package state

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

// TestConcurrentLoadModifyWritesLoseNothing pins r14's P0: r13 locked
// the WRITE (SaveState) but the twin floors path loads State() in a
// SEPARATE window, so two processes could still interleave
// read-A/write-A/read-B/write-B and the last state agreed with neither
// ledger (state said 39, ledger said 34 — both exit 0). The law now:
// the load-modify-write window holds the lock end to end. Workers here
// imitate floors.SetFloorPolicy's exact shape (State -> edit -> SaveState
// -> Log) against the same campaign.
func TestConcurrentLoadModifyWritesLoseNothing(t *testing.T) {
	if os.Getenv("WEBV2_LMWWORKER") != "" {
		lmwWorker()
	}
	root := t.TempDir()
	if _, err := Init(root, "Lock Race Program",
		InitOpts{CampaignID: "C-lmwrace001"}); err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(self, "-test.run=TestConcurrentLoadModifyWritesLoseNothing")
			cmd.Env = append(os.Environ(),
				"WEBV2_LMWWORKER=1", "WEBV2_LOCKROOT="+root,
				"WEBV2_LOCKID=C-lmwrace001",
				fmt.Sprintf("WEBV2_WORKER=%d", i))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("worker %d: %v\n%s", i, err, out)
			}
		}(i)
	}
	wg.Wait()
	c, err := Open(root, "C-lmwrace001")
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	// Each worker appended one entry to the projection-backed list
	// via a raw projection edit; the final state must contain EVERY class
	// exactly once and its winner per class must equal the LAST event for
	// that class — a lost update shows as a missing class or a mismatch.
	byClassLedger := map[string]validation.Value{}
	for _, e := range evts {
		if objStr(e, "type") != "floor_policy.set" {
			continue
		}
		byClassLedger[objStr(e, "ref")] = objAt(e, "data")
	}
	if len(byClassLedger) != 6 {
		t.Fatalf("ledger lost a class: %d of 6", len(byClassLedger))
	}
	rows := objAt(st, "floor_policy")
	if len(rows.A) != 6 {
		t.Fatalf("state lost an update: %d rows, want 6", len(rows.A))
	}
	for _, r := range rows.A {
		d := byClassLedger[objStr(r, "class")]
		if objStr(d, "reason") != objStr(r, "reason") {
			t.Fatalf("state and ledger disagree for %s: %q vs %q",
				objStr(r, "class"), objStr(r, "reason"), objStr(d, "reason"))
		}
	}
}

// lmwWorker mirrors floors.SetFloorPolicy's window: READ, edit, WRITE,
// LOG — with the lock taken at entry exactly like the production fix.
func lmwWorker() {
	i := os.Getenv("WEBV2_WORKER")
	c, err := Open(os.Getenv("WEBV2_LOCKROOT"), os.Getenv("WEBV2_LOCKID"))
	if err != nil {
		os.Exit(1)
	}
	if err := c.LockProcess(); err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
	defer c.UnlockProcess()
	st, err := c.State()
	if err != nil {
		os.Exit(1)
	}
	cls := "class-" + i
	policy := objAt(st, "floor_policy")
	var kept []validation.Value
	for _, e := range policy.A {
		if objStr(e, "class") == cls {
			continue
		}
		kept = append(kept, e)
	}
	entry := validation.VObj(
		validation.KV{K: "class", V: validation.VStr(cls)},
		validation.KV{K: "floor", V: validation.VStr("E4")},
		validation.KV{K: "actor", V: validation.VStr("worker")},
		validation.KV{K: "reason", V: validation.VStr("worker reason " + i + " xxxx")},
		validation.KV{K: "at", V: validation.VStr("2026-01-01T00:00:00+00:00")},
	)
	st.O = validation.SetOrAppend(st.O, "floor_policy", validation.VArr(append(kept, entry)...))
	if err := c.SaveState(st); err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
	ref := cls
	data := validation.VObj(
		validation.KV{K: "floor", V: validation.VStr("E4")},
		validation.KV{K: "actor", V: validation.VStr("worker")},
		validation.KV{K: "reason", V: validation.VStr("worker reason " + i + " xxxx")},
		validation.KV{K: "replaced", V: validation.VBool(false)},
	)
	if _, err := c.Log("floor_policy.set", &ref, &data); err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

// TestConcurrentMethodRacesLoseNothing pins r15 P0-1 directly: the
// state package's OWN methods (SetCostCeiling etc.) used to load state
// outside the lock and write inside it, so racing a locked verb
// (floors-style) against them still lost logged decisions. Workers
// here race both shapes — ceiling sets and floor-style RMW — and every
// decision must survive in state AND agree with the ledger.
func TestConcurrentMethodRacesLoseNothing(t *testing.T) {
	if os.Getenv("WEBV2_MWWORKER") != "" {
		mwWorker()
	}
	root := t.TempDir()
	if _, err := Init(root, "Method Race Program",
		InitOpts{CampaignID: "C-mwrace0001"}); err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(self, "-test.run=TestConcurrentMethodRacesLoseNothing")
			cmd.Env = append(os.Environ(),
				"WEBV2_MWWORKER=1", "WEBV2_LOCKROOT="+root,
				"WEBV2_LOCKID=C-mwrace0001",
				fmt.Sprintf("WEBV2_WORKER=%d", i))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("worker %d: %v\n%s", i, err, out)
			}
		}(i)
	}
	wg.Wait()
	c, err := Open(root, "C-mwrace0001")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := c.State()
	evts, _ := c.Events()
	byRef := map[string]validation.Value{}
	for _, e := range evts {
		if objStr(e, "type") == "floor_policy.set" {
			byRef[objStr(e, "ref")] = objAt(e, "data")
		}
	}
	if len(byRef) != 4 {
		t.Fatalf("floor events lost: %d/4", len(byRef))
	}
	rows := objAt(st, "floor_policy")
	if len(rows.A) != 4 {
		t.Fatalf("floor state rows lost: %d/4", len(rows.A))
	}
	for _, r := range rows.A {
		d := byRef[objStr(r, "class")]
		if objStr(d, "reason") != objStr(r, "reason") {
			t.Fatalf("state/ledger disagree for %s", objStr(r, "class"))
		}
	}
	// Ceilings: each of 4 workers set a distinct value; the LAST writer
	// wins but must agree with ITS event — and no floor decision may be
	// lost meanwhile.
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("verify red after method race: %v", v.Problems)
	}
}

func mwWorker() {
	i := os.Getenv("WEBV2_WORKER")
	c, err := Open(os.Getenv("WEBV2_LOCKROOT"), os.Getenv("WEBV2_LOCKID"))
	if err != nil {
		os.Exit(1)
	}
	n, _ := strconv.Atoi(i)
	if n%2 == 0 { // floor-style RMW through locked methods
		cls := "mclass-" + i
		reason := "method race decision " + i + " xyz"
		if err := c.LockProcess(); err != nil {
			os.Exit(1)
		}
		st, err := c.State()
		if err != nil {
			os.Exit(1)
		}
		pol := objAt(st, "floor_policy")
		var kept []validation.Value
		for _, e := range pol.A {
			if objStr(e, "class") != cls {
				kept = append(kept, e)
			}
		}
		entry := validation.VObj(
			validation.KV{K: "class", V: validation.VStr(cls)},
			validation.KV{K: "floor", V: validation.VStr("E5")},
			validation.KV{K: "actor", V: validation.VStr("w")},
			validation.KV{K: "reason", V: validation.VStr(reason)},
			validation.KV{K: "at", V: validation.VStr("2026-01-01T00:00:00+00:00")})
		st.O = validation.SetOrAppend(st.O, "floor_policy", validation.VArr(append(kept, entry)...))
		if err := c.SaveState(st); err != nil {
			os.Exit(1)
		}
		ref := cls
		data := validation.VObj(
			validation.KV{K: "floor", V: validation.VStr("E5")},
			validation.KV{K: "actor", V: validation.VStr("w")},
			validation.KV{K: "reason", V: validation.VStr(reason)},
			validation.KV{K: "replaced", V: validation.VBool(false)})
		if _, err := c.Log("floor_policy.set", &ref, &data); err != nil {
			os.Exit(1)
		}
		c.UnlockProcess()
	} else { // pure method call (SetCostCeiling owns its lock now)
		v := validation.VFloat(float64(n) + 0.5)
		if _, err := c.SetCostCeiling(&v, "worker"); err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(1)
		}
	}
	os.Exit(0)
}
