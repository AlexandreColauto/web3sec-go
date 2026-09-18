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

// valOpt is one option that takes a value (--src SRC). An appendable option
// (--force ARCH, action="append") accumulates every occurrence in multi
// while val keeps the last one (argparse's final value).
type valOpt struct {
	name     string
	val      string
	multi    []string
	append   bool
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

// parseState carries the loop-local bookkeeping of parse.
type parseState struct {
	sepIdx     int  // index in sp.extras of a pending `--`
	afterSep   bool // seen `--`: everything is positional or extra
	posIdx     int  // next positional slot
	lastPosIdx int  // argv index of the positional token consumed last
	lastOptIdx int  // argv index of the last recognized option token
}

// parse runs the spec over args. It returns the first failure in argparse's
// precedence order, or nil when the command may run.
func (sp *argSpec) parse(args []string) error {
	st := &parseState{sepIdx: -1, lastPosIdx: -1, lastOptIdx: -1}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !st.afterSep && a == "--" {
			st.afterSep = true
			// argparse's positional patterns are `-*A-*`, so a `--` that
			// immediately FOLLOWS a positional matched after the last
			// option is swallowed by that positional's span
			// (`baseline remove NAME --`, `index c --`); otherwise it is
			// an unrecognized argument (`baseline list --`,
			// `index c --src x --`). A `--` consumed before a positional
			// is swallowed later, when that positional is matched.
			if st.lastPosIdx == i-1 && st.lastPosIdx > st.lastOptIdx {
				continue
			}
			st.sepIdx = len(sp.extras)
			sp.extras = append(sp.extras, a)
			continue
		}
		if !st.afterSep {
			next, consumed, err := sp.parseOption(args, i, st)
			if err != nil {
				return err
			}
			if sp.helpSeen {
				return nil
			}
			if consumed {
				i = next
				continue
			}
		}
		sp.parsePositional(a, i, st)
	}
	if err := sp.parseCheckMissing(); err != nil {
		return err
	}
	return sp.parseCheckExtras()
}

// parseOption consumes one option token at args[i]: -h/--help, a value
// option, a store_true flag, or an unrecognized option-looking token (an
// extra). It returns the index of the last argv token it consumed and
// whether the token was recognized; an unrecognized non-option token falls
// through to the positional matcher.
func (sp *argSpec) parseOption(args []string, i int, st *parseState) (next int, consumed bool, err error) {
	a := args[i]
	if explicit, ok := helpToken(a); ok {
		if explicit != "" {
			return i, true, t14ArgparseErr(sp.usage, sp.prog,
				"argument -h/--help: ignored explicit argument %s",
				quoteSingle(explicit))
		}
		sp.helpSeen = true
		return i, true, nil
	}
	if dst := sp.valNamed(a); dst != nil {
		fname, val, hasVal := splitFlag(a)
		optIdx := i
		if !hasVal {
			value, ok := flagValue(args, i)
			if !ok {
				return i, true, t14ArgparseErr(sp.usage, sp.prog,
					"argument %s: expected one argument", fname)
			}
			val = value
			i++
		}
		dst.val, dst.seen = val, true
		if dst.append {
			dst.multi = append(dst.multi, val)
		}
		st.lastOptIdx = optIdx
		return i, true, nil
	}
	if dst := sp.flagNamed(a); dst != nil {
		fname, val, hasVal := splitFlag(a)
		if hasVal {
			return i, true, t14ArgparseErr(sp.usage, sp.prog,
				"argument %s: ignored explicit argument %s",
				fname, quoteSingle(val))
		}
		dst.set = true
		st.lastOptIdx = i
		return i, true, nil
	}
	if looksLikeOption(a) {
		sp.extras = append(sp.extras, a)
		return i, true, nil
	}
	return i, false, nil
}

// parsePositional consumes a as the next positional while one is still open;
// otherwise it records the token as unrecognized.
func (sp *argSpec) parsePositional(a string, i int, st *parseState) {
	if st.posIdx < len(sp.pos) {
		sp.pos[st.posIdx].val, sp.pos[st.posIdx].seen = a, true
		st.posIdx++
		st.lastPosIdx = i
		if st.sepIdx >= 0 {
			// A positional consumed after `--` swallows the separator.
			sp.extras = append(sp.extras[:st.sepIdx], sp.extras[st.sepIdx+1:]...)
			st.sepIdx = -1
		}
		return
	}
	sp.extras = append(sp.extras, a)
}

// parseCheckMissing is argparse's required-arguments check: positionals
// first, then options in declaration order.
func (sp *argSpec) parseCheckMissing() error {
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
	return nil
}

// parseCheckExtras reports unrecognized arguments unless the decision is
// deferred to the caller.
func (sp *argSpec) parseCheckExtras() error {
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
