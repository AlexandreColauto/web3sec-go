package cli

// cmd_snap: `webv2 snap <campaign> <target> [--deployment F] [--chain F]
// [--exclude GLOB...]` — pin a source snapshot (cli.py cmd_snap
// verbatim, P0 flags only).

import (
	"fmt"
	"io"
	"os"
	"strings"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func runSnap(root string, args []string, stdout io.Writer) error {
	var pos []string
	var deployment, chain string
	var excludes []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--deployment" && i+1 < len(args):
			deployment = args[i+1]
			i++
		case strings.HasPrefix(a, "--deployment="):
			deployment = strings.TrimPrefix(a, "--deployment=")
		case a == "--chain" && i+1 < len(args):
			chain = args[i+1]
			i++
		case strings.HasPrefix(a, "--chain="):
			chain = strings.TrimPrefix(a, "--chain=")
		case a == "--exclude" && i+1 < len(args):
			excludes = append(excludes, args[i+1])
			i++
		case strings.HasPrefix(a, "--exclude="):
			excludes = append(excludes, strings.TrimPrefix(a, "--exclude="))
		case strings.HasPrefix(a, "-"):
			return usageErrf("unrecognized arguments: %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 2 {
		return usageErrf("snap requires <campaign> <target> arguments")
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	var extra []string
	for _, spec := range excludes {
		for _, s := range strings.Split(spec, ",") {
			if s = strings.TrimSpace(s); s != "" {
				extra = append(extra, s)
			}
		}
	}
	snap, err := snapshot.PinSourceSnapshot(c, pos[1], nil, extra)
	if err != nil {
		return err
	}
	src := objAt(snap, "source")
	fmt.Fprintf(stdout, "pinned %s (%s, %d files)\n",
		objStr(snap, "snapshot_id"), objStr(src, "ladder"), objInt(src, "file_count"))
	if cfg := objAt(snap, "config"); cfg.Kind == validation.Obj && len(cfg.O) > 0 {
		fmt.Fprintf(stdout, "  toolchain: %s — solc %s (detected from the pinned tree)\n",
			objStr(cfg, "build_system"), objStr(cfg, "compiler"))
	}
	if excl := objAt(src, "excluded"); excl.Kind == validation.Arr && len(excl.A) > 0 {
		var names []string
		for _, e := range excl.A {
			if e.Kind == validation.Str {
				names = append(names, e.S)
			}
		}
		fmt.Fprintf(stdout, "  EXCLUDED from the pin (bulk defaults + --exclude): %s — the pin does NOT cover these; "+
			"re-pin without the prune if any of them is in scope\n", strings.Join(names, ", "))
	}
	if deployment != "" {
		snap, err = attachDeployment(c, snap, deployment)
		if err != nil {
			return err
		}
		dep := objAt(snap, "deployment")
		n := 0
		if contracts := objAt(dep, "contracts"); contracts.Kind == validation.Arr {
			n = len(contracts.A)
		}
		fmt.Fprintf(stdout, "  deployment: %s (%d contracts)\n", objStr(dep, "network"), n)
	}
	if chain != "" {
		snap, err = attachChain(c, snap, chain)
		if err != nil {
			return err
		}
		ch := objAt(snap, "chain")
		fmt.Fprintf(stdout, "  chain: %s @ %s\n", scalarStr(objAt(ch, "chain_id")), scalarStr(objAt(ch, "fork_block")))
	}
	return nil
}

func attachDeployment(c *state.Campaign, snap validation.Value, path string) (validation.Value, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return validation.VNull(), err
	}
	dep, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.VNull(), err
	}
	return snapshot.AttachDeploymentPin(c, objStr(snap, "snapshot_id"), dep)
}

func attachChain(c *state.Campaign, snap validation.Value, path string) (validation.Value, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return validation.VNull(), err
	}
	ch, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.VNull(), err
	}
	return snapshot.AttachChainPin(c, objStr(snap, "snapshot_id"), ch)
}

func init() {
	register(command{ord: 48, name: "snap",
		line: `snap <campaign> <target> [--deployment F] [--chain F] [--exclude GLOB]
                        pin a source snapshot`,
		run: func(root string, args []string, r *Runner) int {
			return r.withErr(root, func() error { return runSnap(root, args, r.Out) })
		}})
}
