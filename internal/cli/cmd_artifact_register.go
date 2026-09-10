package cli

// cmd_artifact_register: `webv2 artifact-register <campaign> <path>
// [--kind K] [--note N]` — register an artifact by path (cli.py
// cmd_artifact_register verbatim, including its own exit-2 error line).

import (
	"fmt"
	"os"
	"strings"

	"websec/internal/state"
)

func runArtifactRegister(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "artifact-register", args) {
		return 0
	}

	ensureSeams()
	var pos []string
	kind, note := "other", ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--kind" && i+1 < len(args):
			kind = args[i+1]
			i++
		case strings.HasPrefix(a, "--kind="):
			kind = strings.TrimPrefix(a, "--kind=")
		case a == "--kind":
			return r.fail(root, argErrf("artifact-register",
				"argument --kind: expected one argument"))
		case a == "--note" && i+1 < len(args):
			note = args[i+1]
			i++
		case strings.HasPrefix(a, "--note="):
			note = strings.TrimPrefix(a, "--note=")
		case a == "--note":
			return r.fail(root, argErrf("artifact-register",
				"argument --note: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 2 {
		missing := []string{}
		if len(pos) < 1 {
			missing = append(missing, "campaign")
		}
		if len(pos) < 2 {
			missing = append(missing, "path")
		}
		return r.fail(root, requiredErrf("artifact-register", missing...))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	path := pos[1]
	if _, statErr := os.Stat(path); statErr != nil {
		fmt.Fprintf(r.Err, "artifact register failed: no such file: %s\n", path)
		return 2
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	aid, err := c.RegisterArtifact(kind, path, note, snap)
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	fmt.Fprintf(r.Out, "%s: kind=%s path=%s\n", aid, kind, path)
	return 0
}

func init() {
	register(command{ord: 23, name: "artifact-register",
		line: "artifact-register <campaign> <path>  register an artifact",
		run:  runArtifactRegister})
}
