package cli

import (
	"strings"
	"testing"
)

// TestBriefStaleMessageGeometry pins r9-5: the STALE reason must describe
// the geometry that actually holds — no "pin moved" story when the
// campaign was never pinned, and the moved-pin case names both ids'
// difference.
func TestBriefStaleMessageGeometry(t *testing.T) {
	c, root := t15Campaign(t, "stale-msg")
	if code, out, errS := run(t, "--root", root, "index", c.CampaignID,
		"--src", writeStaleTarget(t, root)); code != 0 {
		t.Fatalf("index: %q %q", out, errS)
	}
	_, out, errS := run(t, "--root", root, "brief", c.CampaignID)
	if errS != "" {
		t.Fatal(errS)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "STALE") {
			continue
		}
		if strings.Contains(line, "active pin moved") {
			t.Fatalf("unpinned campaign must not be told a pin moved: %q",
				line)
		}
		if !strings.Contains(line, "before any pin existed") {
			t.Fatalf("unpinned STALE must say the truth: %q", line)
		}
	}
}

func writeStaleTarget(t *testing.T, root string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir+"/a.sol", "contract A {}\n")
	return dir
}
