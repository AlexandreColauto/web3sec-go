package assets

import "embed"

// RunbookFS holds the two operating docs that `webv2 init` drops into every
// new campaign: the operator runbook and the agent bootstrap. A working
// campaign therefore carries its own docs even in a fresh workspace with no
// repo in sight (the single-binary distribution goal).
//
//go:embed runbook/RUNBOOK.md runbook/AGENT_BOOTSTRAP.md
var RunbookFS embed.FS

// RunbookNames is the (embedded-path, campaign-file-name) pairs that init
// copies into the campaign directory, in the order they are written.
var RunbookNames = []struct{ Embed, Name string }{
	{"runbook/RUNBOOK.md", "RUNBOOK.md"},
	{"runbook/AGENT_BOOTSTRAP.md", "AGENT_BOOTSTRAP.md"},
}
