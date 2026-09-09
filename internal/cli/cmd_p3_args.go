package cli

// cmd_p3_args: a small argparse clone for the P3 commands (index, sinks,
// forkdiff, baseline). It reproduces the parts of argparse's parse_known_args
// + parse_args contract those parsers exercise, in argparse's own order:
//
//	1. a consumed -h/--help action prints the help block and exits 0;
//	2. an option expecting a value errors at the point it is seen
//	   ("argument --src: expected one argument", "--json: ignored explicit
//	   argument 'x'");
//	3. invalid subcommand choice;
//	4. missing required arguments (positionals first, then options in
//	   declaration order);
//	5. unrecognized arguments, reported by the ROOT parser with the
//	   top-level usage block, in argv order.
//
// The `--` separator drops out of the extras only when a positional is
// actually consumed after it; otherwise argparse reports `--` itself (that is
// what `webv2 baseline list --` and `webv2 index c --src x --` do).

import "strings"

// valOpt is one option that takes a value (--src SRC).
type valOpt struct {
	name     string
	val      string
	seen     bool
	required bool
}

// boolOpt is one store_true option (--json).
type boolOpt struct {
	name string
	set  bool
}

// posOpt is one positional argument (campaign / name / baseline_cmd).
type posOpt struct {
	name string
	val  string
	seen bool
}

// argSpec is one argparse parser.
type argSpec struct {
	prog   string // "index", "baseline add" — the `webv2 <prog>: error:` prefix
	usage  string // the pinned usage block
	vals   []*valOpt
	flags  []*boolOpt
	pos    []*posOpt
	extras []string
	// helpSeen records that -h/--help was consumed; the caller prints help
	// and exits 0 without running the command.
	helpSeen bool
	// deferExtras leaves the "unrecognized arguments" decision to the
	// caller: a nested subparser's extras must be merged with the parent
	// parser's before argparse reports them (baselineDispatch).
	deferExtras bool
}

// parse runs the spec over args. It returns the first failure in argparse's
// precedence order, or nil when the command may run.
func (sp *argSpec) parse(args []string) error {
	sepIdx := -1 // index in sp.extras of a pending `--`
	afterSep := false
	posIdx := 0
	lastPosIdx := -1 // argv index of the positional token consumed last
	lastOptIdx := -1 // argv index of the last recognized option token
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !afterSep && a == "--" {
			afterSep = true
			// argparse's positional patterns are `-*A-*`, so a `--` that
			// immediately FOLLOWS a positional matched after the last
			// option is swallowed by that positional's span
			// (`baseline remove NAME --`, `index c --`); otherwise it is
			// an unrecognized argument (`baseline list --`,
			// `index c --src x --`). A `--` consumed before a positional
			// is swallowed later, when that positional is matched.
			if lastPosIdx == i-1 && lastPosIdx > lastOptIdx {
				continue
			}
			sepIdx = len(sp.extras)
			sp.extras = append(sp.extras, a)
			continue
		}
		if !afterSep {
			if explicit, ok := helpToken(a); ok {
				if explicit != "" {
					return t14ArgparseErr(sp.usage, sp.prog,
						"argument -h/--help: ignored explicit argument %s",
						quoteSingle(explicit))
				}
				sp.helpSeen = true
				return nil
			}
			if dst := sp.valNamed(a); dst != nil {
				fname, val, hasVal := splitFlag(a)
				if hasVal {
					dst.val, dst.seen = val, true
					lastOptIdx = i
					continue
				}
				next, ok := flagValue(args, i)
				if !ok {
					return t14ArgparseErr(sp.usage, sp.prog,
						"argument %s: expected one argument", fname)
				}
				dst.val, dst.seen = next, true
				lastOptIdx = i
				i++
				continue
			}
			if dst := sp.flagNamed(a); dst != nil {
				fname, val, hasVal := splitFlag(a)
				if hasVal {
					return t14ArgparseErr(sp.usage, sp.prog,
						"argument %s: ignored explicit argument %s",
						fname, quoteSingle(val))
				}
				dst.set = true
				lastOptIdx = i
				continue
			}
			if looksLikeOption(a) {
				sp.extras = append(sp.extras, a)
				continue
			}
		}
		if posIdx < len(sp.pos) {
			sp.pos[posIdx].val, sp.pos[posIdx].seen = a, true
			posIdx++
			lastPosIdx = i
			if sepIdx >= 0 {
				// A positional consumed after `--` swallows the separator.
				sp.extras = append(sp.extras[:sepIdx], sp.extras[sepIdx+1:]...)
				sepIdx = -1
			}
			continue
		}
		sp.extras = append(sp.extras, a)
	}
	var missing []string
	for _, p := range sp.pos {
		if !p.seen {
			missing = append(missing, p.name)
		}
	}
	for _, v := range sp.vals {
		if v.required && !v.seen {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return t14ArgparseErr(sp.usage, sp.prog,
			"the following arguments are required: %s",
			strings.Join(missing, ", "))
	}
	if len(sp.extras) > 0 && !sp.deferExtras {
		return t14Unrecognized(strings.Join(sp.extras, " "))
	}
	return nil
}

// helpToken matches argparse's -h/--help, including the short-option cluster
// form `-hx` (help wins and the tail is ignored) and the `-h=x` /
// `--help=x` explicit-argument error.
func helpToken(a string) (explicit string, ok bool) {
	switch {
	case a == "-h" || a == "--help":
		return "", true
	case strings.HasPrefix(a, "--help="):
		return a[len("--help="):], true
	case strings.HasPrefix(a, "-h="):
		return a[len("-h="):], true
	case strings.HasPrefix(a, "-h") && !strings.HasPrefix(a, "--"):
		return "", true
	}
	return "", false
}

// valNamed returns the value option a names (--src, --path, ...), if any.
func (sp *argSpec) valNamed(a string) *valOpt {
	name, _, _ := splitFlag(a)
	for _, v := range sp.vals {
		if v.name == name {
			return v
		}
	}
	return nil
}

// flagNamed returns the store_true option a names, if any.
func (sp *argSpec) flagNamed(a string) *boolOpt {
	name, _, _ := splitFlag(a)
	for _, f := range sp.flags {
		if f.name == name {
			return f
		}
	}
	return nil
}
