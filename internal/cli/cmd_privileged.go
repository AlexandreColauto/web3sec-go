package cli

// cmd_privileged: `webv2 privileged <campaign>` — the separate bounded-role
// attacker track: per recorded privilege role, its explicit baseline,
// exposure band, constraints and terminal paths (cli.py cmd_privileged
// verbatim). No model calls.

import (
	"fmt"
	"strings"

	"websec/internal/privileged"
	"websec/internal/validation"
)

func runPrivileged(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		name, done, err := t23OneArg(args, "privileged", r)
		if err != nil || done {
			return err
		}
		c, err := t14Open(root, name)
		if err != nil {
			return err
		}
		exp, err := privileged.PrivilegedExposure(c)
		if err != nil {
			return err
		}
		roles := t14List(exp, "roles")
		fmt.Fprintf(r.Out, "privileged track (%d role(s), separate from the "+
			"EOA terminal report)\n", len(roles.A))
		for _, role := range roles.A {
			printPrivilegedRole(r, role)
		}
		return nil
	})
}

func printPrivilegedRole(r *Runner, role validation.Value) {
	fmt.Fprintf(r.Out, "role: %s (%s)\n", objStr(role, "role"),
		objStr(role, "role_label"))
	fmt.Fprintf(r.Out, "  baseline: %s\n", t14Join(t14List(role, "baseline")))
	fmt.Fprintf(r.Out, "  band: %s\n", objStr(role, "exposure_band"))
	fmt.Fprint(r.Out, "  constraints:\n")
	constraints := t14List(role, "constraints")
	if len(constraints.A) == 0 {
		fmt.Fprint(r.Out, "    (none)\n")
	}
	for _, con := range constraints.A {
		fmt.Fprintf(r.Out, "    - %s\n", privilegedConstraint(con))
	}
	printPrivilegedPaths(r, role, "direct")
	printPrivilegedPaths(r, role, "chains")
}

// privilegedConstraint is one constraint line: capability (or the unnamed
// placeholder), the mechanism, and the parenthesised qualifiers.
func privilegedConstraint(con validation.Value) string {
	capability := objStr(con, "capability")
	if capability == "" {
		capability = "(unnamed capability)"
	}
	line := capability
	if mech := objStr(con, "mechanism"); mech != "" {
		line += " via " + mech
	}
	quals := []string{}
	if v := objAt(con, "timelocked"); v.Kind == validation.Bool && v.B {
		quals = append(quals, "timelocked")
	}
	if th := objAt(con, "multisig_threshold"); th.Kind != validation.Bool {
		switch th.Kind {
		case validation.Int, validation.Flt:
			quals = append(quals, "threshold "+t23PyG(pyFloatOf(th)))
		}
	}
	if len(quals) > 0 {
		line += " (" + strings.Join(quals, ", ") + ")"
	}
	return line
}

// printPrivilegedPaths renders the direct / chains blocks (key is the label
// Python prints, always plural "chains").
func printPrivilegedPaths(r *Runner, role validation.Value, key string) {
	paths := t14List(role, key)
	if len(paths.A) == 0 {
		fmt.Fprintf(r.Out, "  %s: (none)\n", key)
		return
	}
	for _, p := range paths.A {
		fmt.Fprintf(r.Out, "  %s: %s -> %s%s\n", key,
			strings.Join(t14Strings(t14List(p, "path")), " -> "),
			objStr(p, "terminal_capability"), t23CapSuffix(p))
	}
}

func init() {
	register(command{ord: 10, name: "privileged",
		line: "privileged <campaign>               bounded privileged-role track",
		run:  runPrivileged})
}
