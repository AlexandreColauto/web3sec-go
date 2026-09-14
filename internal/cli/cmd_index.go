package cli

// cmd_index: `webv2 index <campaign> --src SRC [--json]` — rebuild the
// structural index for the active pin (cli.py cmd_index verbatim). The index
// is the root artifact every derived hunt report copies its snapshot_id from.

import (
	"fmt"
	"os"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

const indexUsage = "usage: webv2 index [-h] --src SRC [--json] campaign\n"

func runIndex(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		cid, src, asJSON, help, err := parseSrcArgs(args, "index")
		if err != nil {
			return err
		}
		if help {
			fmt.Fprint(r.Out, indexHelp)
			return nil
		}
		// cli.py checks the source tree BEFORE opening the campaign, so a
		// bad --src wins over a malformed campaign id.
		if !isDirPath(src) {
			return t14ExitErr(1, "source tree not found: %s\n", src)
		}
		c, err := t14Open(root, cid)
		if err != nil {
			return err
		}
		idx, err := structidx.IndexSnapshot(c, src, structidx.DefaultBackend)
		if err != nil {
			return err
		}
		idxPath, err := structidx.SaveIndex(c, idx)
		if err != nil {
			return err
		}
		// r11: REGISTER the index like the orchestrator's own path does
		// (internal/orchestrator/index.go). An unregistered derived
		// artifact is a trust boundary the audit cannot see: a hand-edited
		// structural_index.json — a forged payable withdraw node — fed
		// prescreen and sinks while every ledger check stayed green,
		// because the Artifacts section hashes REGISTERED files only.
		// Registration re-hashes on every audit and artifact-reconcile.
		snapID := objStr(idx, "snapshot_id")
		var snapRef *string
		if snapID != "" && snapID != "unpinned" {
			snapRef = &snapID
		}
		if _, err := c.RegisterOrRefresh("structural-index", idxPath, "",
			snapRef, "structural index rebuilt"); err != nil {
			return err
		}
		if asJSON {
			fmt.Fprintln(r.Out, validation.DumpIndentedASCII(validation.VObj(
				validation.KV{K: "snapshot_id", V: objAt(idx, "snapshot_id")},
				validation.KV{K: "entry_count", V: objAt(idx, "entry_count")},
				validation.KV{K: "stats", V: objAt(idx, "stats")},
			)))
			return nil
		}
		fmt.Fprintf(r.Out, "index: %s entries (snapshot %s)\n",
			pyIntText(objAt(idx, "entry_count")), objStr(idx, "snapshot_id"))
		return nil
	})
}

// parseSrcArgs parses the shared `[--src SRC] [--json] campaign` shape of
// index/sinks/forkdiff with argparse's error precedence and help action.
func parseSrcArgs(args []string, cmd string) (campaign, src string, asJSON, help bool, err error) {
	sp := &argSpec{
		prog:  cmd,
		usage: srcUsage(cmd),
		vals:  []*valOpt{{name: "--src", required: true}},
		flags: []*boolOpt{{name: "--json"}},
		pos:   []*posOpt{{name: "campaign"}},
	}
	if err := sp.parse(args); err != nil {
		return "", "", false, false, err
	}
	if sp.helpSeen {
		return "", "", false, true, nil
	}
	return sp.pos[0].val, pyPathText(sp.vals[0].val),
		sp.flags[0].set, false, nil
}

// srcUsage is the pinned argparse usage block for the --src commands.
func srcUsage(cmd string) string {
	switch cmd {
	case "index":
		return indexUsage
	case "sinks":
		return sinksUsage
	case "forkdiff":
		return forkdiffUsage
	}
	return "usage: webv2 " + cmd + " [-h] --src SRC [--json] campaign\n"
}

// isDirPath is Path.is_dir(): a missing path is false, a symlink to a
// directory is true. CPython's Path("") is Path(".").
func isDirPath(p string) bool {
	if p == "" {
		p = "."
	}
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// pyPathText is str(PurePosixPath(p)): pathlib drops empty and "." segments
// (and keeps ".."), which is what an argparse-fed path looks like in cli.py's
// error messages (""./x" prints as "x", "" as ".").
func pyPathText(p string) string {
	abs := strings.HasPrefix(p, "/")
	var out []string
	for _, part := range strings.Split(p, "/") {
		if part != "" && part != "." {
			out = append(out, part)
		}
	}
	body := strings.Join(out, "/")
	switch {
	case abs:
		return "/" + body
	case body == "":
		return "."
	}
	return body
}

func init() {
	register(command{ord: 15, name: "index",
		line: "index <campaign> --src SRC          rebuild the structural index",
		run:  runIndex})
}
