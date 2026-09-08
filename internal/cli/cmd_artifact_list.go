package cli

// cmd_artifact_list: `webv2 artifact-list <campaign> [--kind K]` — list the
// registered artifacts (cli.py cmd_artifact_list verbatim: the row is
// `{artifact_id}  {kind}  {path}` plus two spaces and the 60-char note).

import (
	"fmt"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

func runArtifactList(root string, args []string, r *Runner) int {
	ensureSeams()
	kind := ""
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--kind" && i+1 < len(args):
			kind = args[i+1]
			i++
		case strings.HasPrefix(a, "--kind="):
			kind = strings.TrimPrefix(a, "--kind=")
		case a == "--kind":
			return r.fail(root, argErrf("artifact-list",
				"argument --kind: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return r.fail(root, requiredErrf("artifact-list", "campaign"))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	st, err := c.State()
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	rows := objAt(st, "artifacts").A
	shown := make([]validation.Value, 0, len(rows))
	for _, row := range rows {
		if kind != "" && objStr(row, "kind") != kind {
			continue
		}
		shown = append(shown, row)
	}
	if len(shown) == 0 {
		if kind != "" {
			fmt.Fprintf(r.Out, "no artifacts of kind %s\n", kind)
		} else {
			fmt.Fprintln(r.Out, "no artifacts")
		}
		return 0
	}
	for _, row := range shown {
		note := ""
		if n := objStr(row, "note"); n != "" {
			note = "  " + pyHead(n, 60)
		}
		fmt.Fprintf(r.Out, "%s  %s  %s%s\n", objStr(row, "artifact_id"),
			objStr(row, "kind"), objStr(row, "path"), note)
	}
	return 0
}

func init() {
	register(command{ord: 24, name: "artifact-list",
		line: "artifact-list <campaign> [--kind K]  list registered artifacts",
		run:  runArtifactList})
}
