package boundary

// R44C at the boundary package: campaignMemoryIDs was a SECOND implementation
// of the memory listing — its own os.ReadDir over memory/, folding every
// listing error into "no ids", with the shared tier's error swallowed the
// same way. The check itself is fail-closed, so the fold never admitted a bad
// hypothesis; it turned a store that could not be read into a FALSE
// ACCUSATION ("hypothesis override names unknown memory row") and gave one law
// two readers with different tolerances. The listing now goes through
// learning.AllMemory and sharedmem.LoadSharedMemory, and a read failure
// refuses as a plain error (not a BoundaryError), so the caller can no longer
// confuse an unreadable store with a defect in the model's payload.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

func r44cCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r44c", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// r44cChmod makes path unreadable and PROVES it (ReadDir for a directory,
// ReadFile for a file); under a uid that ignores mode bits the test skips.
func r44cChmod(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	mode := os.FileMode(0o600)
	if fi.IsDir() {
		mode = 0o755
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 000 %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, mode) })
	if fi.IsDir() {
		if _, err := os.ReadDir(path); err == nil {
			t.Skipf("cannot create an unreadable directory here (%s stayed readable)", path)
		}
		return
	}
	if _, err := os.ReadFile(path); err == nil {
		t.Skipf("cannot create an unreadable file here (%s stayed readable)", path)
	}
}

// r44cQueuePrior queues one negative-memory row through the real store writer.
func r44cQueuePrior(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	cls := "reentrancy"
	row, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind:     "disproved",
		Status:   "DISPROVED",
		Pattern:  "a prior observation of the reentrancy guard",
		BugClass: &cls})
	if err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	return row
}

// r44cHypothesis is a valid hypothesis citing the given memory row as the
// prior it overrides.
func r44cHypothesis(mid string) validation.Value {
	return setKV(validHypothesis(), "differs_from_memory", validation.VArr(
		validation.VObj(
			kv("memory_id", validation.VStr(mid)),
			kv("assumption_id", validation.VStr("A1")),
			kv("how_it_differs", validation.VStr("the prior assumed the "+
				"guard could not be re-entered within one block; here the "+
				"callback re-enters before the balance update lands")))))
}

// TestR44cMemoryCitationRefusesUnreadableStore: `chmod 000 <c>/memory/` must
// NOT be judged as "unknown memory row" — the store, not the payload, is what
// failed.
func TestR44cMemoryCitationRefusesUnreadableStore(t *testing.T) {
	c := r44cCampaign(t, "C-r44cbidr1")
	row := r44cQueuePrior(t, c)
	r44cChmod(t, c.MemoryDir)

	err := ValidateResponse("proposer", "hypothesis",
		r44cHypothesis(objStr(row, "memory_id")), c)
	if err == nil {
		t.Fatal("a citation was resolved against an unreadable memory store")
	}
	if strings.Contains(err.Error(), "unknown memory row") {
		t.Fatalf("a read failure was reported as an unknown row: %v", err)
	}
	var be *BoundaryError
	if errors.As(err, &be) {
		t.Fatalf("a store read failure must not be a BoundaryError "+
			"(the payload is not the defect): %v", err)
	}
	if !strings.Contains(err.Error(), c.MemoryDir) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the memory store and the errno: %v", err)
	}
}

// TestR44cMemoryCitationRefusesUnreadableRow: a listed store with one
// unreadable row cannot answer the citation either.
func TestR44cMemoryCitationRefusesUnreadableRow(t *testing.T) {
	c := r44cCampaign(t, "C-r44cbidr2")
	row := r44cQueuePrior(t, c)
	mid := objStr(row, "memory_id")
	r44cChmod(t, filepath.Join(c.MemoryDir, mid+".json"))

	err := ValidateResponse("proposer", "hypothesis", r44cHypothesis(mid), c)
	if err == nil {
		t.Fatal("a citation was resolved over an unreadable row")
	}
	if !strings.Contains(err.Error(), mid) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the unreadable row and the errno: %v", err)
	}
}

// TestR44cMemoryCitationHonestShapesStayGreen: a real row still passes, an
// unknown id still burns as "unknown memory row" (fail-closed unchanged), and
// an ABSENT store is still an empty id set — not a refusal — so a campaign
// with no memory/ keeps today's answer.
func TestR44cMemoryCitationHonestShapesStayGreen(t *testing.T) {
	c := r44cCampaign(t, "C-r44cbidg1")
	row := r44cQueuePrior(t, c)
	mid := objStr(row, "memory_id")

	if err := ValidateResponse("proposer", "hypothesis",
		r44cHypothesis(mid), c); err != nil {
		t.Fatalf("a citation of a real row refused: %v", err)
	}

	err := ValidateResponse("proposer", "hypothesis",
		r44cHypothesis("MEM-nonexistent"), c)
	if err == nil || !strings.Contains(err.Error(), "unknown memory row") {
		t.Fatalf("unknown id: err = %v, want unknown memory row", err)
	}

	if err := os.RemoveAll(c.MemoryDir); err != nil {
		t.Fatal(err)
	}
	err = ValidateResponse("proposer", "hypothesis",
		r44cHypothesis("MEM-nonexistent"), c)
	if err == nil || !strings.Contains(err.Error(), "unknown memory row") {
		t.Fatalf("absent store: err = %v, want unknown memory row (absence "+
			"is a fact, not a refusal)", err)
	}
	if err := ValidateResponse("proposer", "hypothesis",
		r44cHypothesis(mid), c); err == nil ||
		!strings.Contains(err.Error(), "unknown memory row") {
		t.Fatalf("absent store: err = %v, want unknown memory row", err)
	}
}
