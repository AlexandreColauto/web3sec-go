package cli

// cmd_init tests: `webv2 init` drops the two operating docs (RUNBOOK.md,
// AGENT_BOOTSTRAP.md) into the campaign directory, byte-identical to the
// embedded copies, and says so.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/assets"
)

func TestInitWritesRunbookDocs(t *testing.T) {
	root := mkroot(t)
	code, out, errS := run(t, "--root", root, "init", "--program", "Docs Test")
	if code != 0 {
		t.Fatalf("init exit %d: out=%q err=%q", code, out, errS)
	}
	m := initIDRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("init output missing id: %q", out)
	}
	campDir := filepath.Join(root, "campaigns", m[1])
	for _, d := range assets.RunbookNames {
		dst := filepath.Join(campDir, d.Name)
		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("init did not write %s: %v", d.Name, err)
		}
		want, err := assets.RunbookFS.ReadFile(d.Embed)
		if err != nil {
			t.Fatalf("embedded %s unreadable: %v", d.Embed, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s in campaign != embedded copy (len %d vs %d)",
				d.Name, len(got), len(want))
		}
		if len(got) == 0 {
			t.Fatalf("%s is empty", d.Name)
		}
	}
	for _, name := range []string{"RUNBOOK.md", "AGENT_BOOTSTRAP.md"} {
		if !strings.Contains(out, name) {
			t.Fatalf("init output must name %s: %q", name, out)
		}
	}
}
