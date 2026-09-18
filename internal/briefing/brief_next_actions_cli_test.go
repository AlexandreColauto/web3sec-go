package briefing

// brief_next_actions_cli_test.go: Task 7 at the brief boundary — the rendered
// next-actions list is copyable.
//
// The minting site is the work-queue assembly (orchestrator.NextActions); this
// test pins what the OPERATOR sees: `webv2 brief` on a fixture campaign emits
// next actions that are all runnable `webv2 …` commands, none of them a
// parenthesised Python-API pseudo-call, and — for the fresh-campaign fixture —
// exactly the two commands the SCOPE phase needs.

import (
	"strings"
	"testing"
	"websec/internal/validation"
)

func TestBriefNextActionsAreCopyableCommands(t *testing.T) {
	c := newCamp(t, "Acme")
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatalf("build brief: %v", err)
	}
	lines := strListOf(validation.ObjAt(b, "next_actions"))
	if len(lines) == 0 {
		t.Fatal("fixture brief rendered no next actions")
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "webv2 ") {
			t.Errorf("brief next action %q is not a runnable `webv2 …` "+
				"command", line)
		}
		if strings.ContainsAny(line, "()") {
			t.Errorf("brief next action %q carries a parenthesis — that is a "+
				"Python-API pseudo-call, not a command an operator can paste",
				line)
		}
	}
	want := []string{
		"webv2 scope " + c.CampaignID + " --policy <policy.json>",
		"webv2 snap " + c.CampaignID + " <target>",
	}
	if strings.Join(lines, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("fresh-campaign brief next actions:\n got: %q\nwant: %q",
			lines, want)
	}
}
