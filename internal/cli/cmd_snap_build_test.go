package cli

// DEFECT-2 follow-up: the snapshot pin records the framework build that
// produced it, so a later brief on a different binary can warn instead of
// silently trusting changed probe semantics.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapPinRecordsFrameworkBuild(t *testing.T) {
	// The override stands in for a stamped release build (test binaries
	// never carry a VCS stamp): the pin must record the running build,
	// truncated to 12 chars like a commit sha.
	t.Setenv("WEBV2_BUILD", "snap-test-build")
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	code, _, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}
	raw, err := os.ReadFile(filepath.Join(root, "campaigns", cid,
		"events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e["type"] != "snapshot.pinned" {
			continue
		}
		found = true
		data, ok := e["data"].(map[string]any)
		if !ok {
			t.Fatalf("snapshot.pinned has no data object: %v", e)
		}
		if data["framework_build"] != "snap-test-bu" {
			t.Fatalf("framework_build = %v, want the running build "+
				"truncated to 12 chars", data["framework_build"])
		}
	}
	if !found {
		t.Fatal("no snapshot.pinned event logged")
	}
}
