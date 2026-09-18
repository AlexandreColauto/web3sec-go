package harness

import (
	"strconv"
	"strings"
	"unicode"
)

// lexCommand splits a recorded command string into the argv a POSIX shell
// would hand the tool, or names the construct that stopped it ("" = the
// string is one simple command we could lex). Modeled:
//
//   - space and TAB separate words — with a newline, the only IFS
//     whitespace a POSIX shell splits on. CR, VT and FF are NOT
//     separators (r30 P2-1): `/bin/sh -c 'tool --loop-bound<VT>4'` hands
//     the tool ONE argv element `--loop-bound\v4`, so splitting it would
//     invent a flag the tool never received;
//   - single quotes are literal end to end (no escapes, no expansion);
//   - in double quotes only $ ` " \ and a newline are escaped by a
//     backslash — POSIX keeps the backslash before anything else — and
//     expansions inside them are single words;
//   - outside quotes a backslash escapes the next rune, and a backslash
//     before a newline is a line continuation;
//   - '$' begins an expansion only before a name start, '{', '(', a digit
//     or a special parameter; before ANYTHING else it is a LITERAL '$' and
//     the next rune is lexed as itself (r31 F1), so `$;` still ends the
//     command, `$ ` still separates words, `$'` still opens a quote and a
//     trailing '$' is one character of the word;
//   - '#' opens a comment only at a WORD BOUNDARY ("4#x" is a value, and
//     a quoted '#' is a word), and a comment runs to the end of the line;
//   - a `--` element is returned as itself: click's end-of-options rule
//     lives in boundFromArgv, where it belongs.
//
// NOT modeled — each returns a construct name instead of a guessed argv,
// because the argv is not derivable from the text: an unmatched quote, a
// trailing backslash, an unterminated expansion, a command LIST (a
// newline, ';' or '&' with another command after it), a pipeline or
// subshell (| ( )), a redirection (< >) and braces.
//
// An expansion ($VAR, $(...), backticks) or a glob (* ? [) is NOT an
// error by itself: it marks one token unknown, because the shell would
// have replaced the text with something this parse cannot know.
// boundFromArgv then decides whether that unknown token could have been
// an option. A tilde is ordinary text on purpose: a tilde expansion is an
// absolute path, so it can be neither an option nor a word that starts
// with one, and it cannot hide a flag.
func lexCommand(command string) ([]shToken, string) {
	rs := []rune(command)
	var (
		toks    []shToken
		word    strings.Builder
		unknown bool
		started bool
	)
	flush := func() {
		if started {
			toks = append(toks, shToken{text: word.String(),
				unknown: unknown})
		}
		word.Reset()
		unknown, started = false, false
	}
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == ' ' || c == '\t':
			// IFS whitespace, and nothing else: CR/VT/FF fall through
			// to the default arm below and stay inside the word
			// (r30 P2-1, evidence in zz_r30_test.go). A newline is
			// next, because it separates COMMANDS, not just words.
			flush()
		case c == '\n' || c == ';' || c == '&':
			flush()
			if restHasCommand(rs[i+1:]) {
				return nil, "command list (separator " +
					strconv.QuoteRune(c) + ")"
			}
			return toks, ""
		case c == '|' || c == '(' || c == ')':
			return nil, "pipeline or subshell (" +
				strconv.QuoteRune(c) + ")"
		case c == '<' || c == '>':
			return nil, "redirection (" + strconv.QuoteRune(c) + ")"
		case c == '{' || c == '}':
			return nil, "brace expression (" +
				strconv.QuoteRune(c) + ")"
		case c == '#' && !started:
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
			i--
		case c == '\'':
			started = true
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			if j >= len(rs) {
				return nil, "unmatched single quote"
			}
			word.WriteString(string(rs[i+1 : j]))
			i = j
		case c == '"':
			started = true
			j, construct := lexDoubleQuoted(rs, i, &word, &unknown)
			if construct != "" {
				return nil, construct
			}
			i = j
		case c == '\\':
			started = true
			if i+1 >= len(rs) {
				return nil, "unterminated escape (trailing " +
					"backslash)"
			}
			if rs[i+1] == '\n' {
				i++ // line continuation: the shell joins the lines
				continue
			}
			word.WriteRune(rs[i+1])
			i++
		case c == '$' || c == '`':
			started = true
			span, last, construct := expansionSpan(rs, i)
			if construct != "" {
				return nil, construct
			}
			// Only a span that CONSUMED runes is an expansion, whose
			// substituted value is not derivable from the text. A
			// literal '$' (r31 F1) consumes nothing and is known
			// exactly, so it must not mark the word unknown — a word
			// is unknown if ANY part of it was substituted.
			if last > i {
				unknown = true
			}
			word.WriteString(span)
			i = last
		case c == '*' || c == '?' || c == '[':
			started, unknown = true, true
			word.WriteRune(c)
		default:
			started = true
			word.WriteRune(c)
		}
	}
	flush()
	return toks, ""
}

// restHasCommand reports whether anything after a command separator is
// another command. Whitespace, blank lines and comment lines are not: a
// command string with a trailing newline and a trailing comment is still
// one command, so it must not be refused as a list. Only real IFS
// whitespace counts here too (r30 P2-1): a CR, VT or FF after the
// separator is an ordinary character, so `cmd\n\vecho x` names a second
// command whose first word merely begins with a control byte.
func restHasCommand(rest []rune) bool {
	for i := 0; i < len(rest); {
		switch c := rest[i]; {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '#':
			for i < len(rest) && rest[i] != '\n' {
				i++
			}
		default:
			return true
		}
	}
	return false
}

// lexDoubleQuoted consumes the double-quoted region beginning at rs[i]
// (== '"'), appends its text to word and returns the index of the closing
// quote. POSIX keeps a backslash literal unless it precedes $ ` " \ or a
// newline, so `--loop-bound "\4"` is the two-rune value `\4` (which click
// refuses) and not the integer 4.
func lexDoubleQuoted(rs []rune, i int, word *strings.Builder,
	unknown *bool) (int, string) {
	for j := i + 1; j < len(rs); j++ {
		switch c := rs[j]; c {
		case '"':
			return j, ""
		case '\\':
			if j+1 >= len(rs) {
				return 0, "unmatched double quote"
			}
			switch n := rs[j+1]; n {
			case '$', '`', '"', '\\':
				word.WriteRune(n)
				j++
			case '\n':
				j++ // line continuation
			default:
				word.WriteRune('\\')
			}
		case '$', '`':
			span, last, construct := expansionSpan(rs, j)
			if construct != "" {
				return 0, construct
			}
			// As above: the literal '$' (r31 F1) is known text, so
			// it must not mark the word unknown by itself. A '$'
			// before the closing '"' is literal too, which is what
			// makes `"a$"` one word instead of an unmatched quote.
			if last > j {
				*unknown = true
			}
			word.WriteString(span)
			j = last
		default:
			word.WriteRune(c)
		}
	}
	return 0, "unmatched double quote"
}

// expansionSpan consumes the shell expansion that begins at rs[i] ('$' or
// '`') and returns its literal text plus the index of its last rune. The
// text is carried so a refusal can quote what the parse saw; a span that
// CONSUMES runes (last > i) is an expansion, whose substituted value is
// not derivable from the command string, so its caller marks the token
// unknown. A span that consumes nothing is the LITERAL '$' below: the text
// is known exactly, so it marks the token unknown NOT (r31 F1).
//
// r31 F1: the r29/r30 default arm swallowed ONE rune after every '$', so
// `$;` was one token and the ';' inside it stopped separating. A POSIX
// shell reads '$' followed by a character that cannot begin a parameter as
// a LITERAL '$' and lexes that character itself, so
//
//	--match-path $; --fuzz-runs 500   is a command LIST in the shell
//	                                  (/bin/sh exits 127 on the second
//	                                  command), not an invocation that
//	                                  named --fuzz-runs 500;
//	--contract $ --loop-bound 7       names loop_bound 7 (the space
//	                                  separates, the '$' is a value);
//	--solc-path $'x --loop-bound 7'   is the one word `$x --loop-bound 7`
//	                                  (the ' opens a quoted region), not
//	                                  an unmatched quote.
//
// Only a POSIX name start, '{', '(', a digit or a special parameter stays
// an expansion. Everything else — ';', '&', '|', a newline, space, TAB, a
// quote, a backslash — is lexed as itself by the caller.
func expansionSpan(rs []rune, i int) (string, int, string) {
	if rs[i] == '`' {
		for j := i + 1; j < len(rs); j++ {
			if rs[j] == '\\' {
				j++
				continue
			}
			if rs[j] == '`' {
				return string(rs[i : j+1]), j, ""
			}
		}
		return "", 0, "unterminated command substitution (backquote)"
	}
	if i+1 >= len(rs) {
		return "$", i, "" // a trailing '$' is literal
	}
	switch n := rs[i+1]; {
	case n == '(':
		// $(...) may contain spaces and quotes, so its extent matters:
		// scan to the matching paren, ignoring quoted regions.
		depth := 1
		inSingle, inDouble := false, false
		for j := i + 2; j < len(rs); j++ {
			switch c := rs[j]; {
			case inSingle:
				inSingle = c != '\''
			case inDouble:
				switch c {
				case '\\':
					j++
				case '"':
					inDouble = false
				}
			case c == '\'':
				inSingle = true
			case c == '"':
				inDouble = true
			case c == '\\':
				j++
			case c == '(':
				depth++
			case c == ')':
				depth--
				if depth == 0 {
					return string(rs[i : j+1]), j, ""
				}
			}
		}
		return "", 0, "unterminated command substitution ($(...))"
	case n == '{':
		for j := i + 2; j < len(rs); j++ {
			if rs[j] == '}' {
				return string(rs[i : j+1]), j, ""
			}
		}
		return "", 0, "unterminated parameter expansion (${...})"
	case isNameStart(n):
		j := i + 2
		for j < len(rs) && isNameRune(rs[j]) {
			j++
		}
		return string(rs[i:j]), j - 1, ""
	case isSpecialParam(n):
		return string(rs[i : i+2]), i + 1, "" // $1, $?, $@, $$, $-, ...
	default:
		// '$' before anything else is a LITERAL '$' (r31 F1): the
		// caller lexes rs[i+1] as itself, so a separator after '$'
		// still separates and a quote after it still quotes.
		return "$", i, ""
	}
}

// isSpecialParam reports the one-rune parameter a POSIX shell expands after
// a '$' besides a name, a digit or a brace/paren form: the special
// parameters. A digit is a positional parameter ($1); the rest are the
// shell's own ($*, $@, $#, $?, $-, $$, $!). Every OTHER rune after '$' is
// literal (r31 F1) — including a non-ASCII digit, which is not a positional
// parameter to any shell.
func isSpecialParam(r rune) bool {
	switch r {
	case '*', '@', '#', '?', '-', '$', '!':
		return true
	}
	return r >= '0' && r <= '9'
}

// isNameStart reports a POSIX name's first rune ($VAR/$var_1 forms).
func isNameStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_'
}

// isNameRune reports a rune a POSIX name may continue with.
func isNameRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}
