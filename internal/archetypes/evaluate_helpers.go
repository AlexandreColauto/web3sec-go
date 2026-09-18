// evaluate_helpers.go: the shared matcher/compile helpers split out of
// evaluate.go — marker matching, regex compilation and value-list utilities.
package archetypes

import (
	"fmt"
	"regexp"
	"strings"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// containsLower reports whether strings.ToLower(s) contains any marker
// (lowercased) — the case-insensitive marker match both G10 checks share.
func containsLower(s string, markers []string) bool {
	l := strings.ToLower(s)
	for _, m := range markers {
		if strings.Contains(l, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// containsSubstr reports whether name contains any of the needles.
func containsSubstr(name string, needles []string) bool {
	for _, nd := range needles {
		if strings.Contains(name, nd) {
			return true
		}
	}
	return false
}

// compileRegex is _compile_regex: an invalid pattern is an error naming where
// it came from — never a bare regexp error.
func compileRegex(pattern, context string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid regex %s: %s",
			context, validation.PyReprStr(pattern), err)
	}
	return re, nil
}

// optionalPattern compiles check[key] when present (nil when absent).
func optionalPattern(check validation.Value, key, context string) (*regexp.Regexp, error) {
	v := validation.ObjAt(check, key)
	if v.Kind != validation.Str {
		return nil, nil
	}
	return compileRegex(v.S, context)
}

// unguarded is _unguarded: no authorization modifier in guarded_by.
func unguarded(n validation.Value) bool {
	for _, m := range listAt(n, "guarded_by") {
		if m.Kind == validation.Str && structidx.IsAuthzGuard(m.S) {
			return false
		}
	}
	return true
}

// anyMatchStr is anyMatch over a []string.
func anyMatchStr(pat *regexp.Regexp, values []string) bool {
	for _, v := range values {
		if pat.MatchString(v) {
			return true
		}
	}
	return false
}

// anyMatch is any(pat.search(v) for v in values).
func anyMatch(pat *regexp.Regexp, values []validation.Value) bool {
	for _, v := range values {
		if v.Kind == validation.Str && pat.MatchString(v.S) {
			return true
		}
	}
	return false
}

func stringSet(values []validation.Value) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		if v.Kind == validation.Str {
			out[v.S] = true
		}
	}
	return out
}

func dedupeStrings(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// pyListRepr renders a []string the way Python's repr() does.

func listAt(v validation.Value, key string) []validation.Value {
	x := validation.ObjAt(v, key)
	if x.Kind != validation.Arr {
		return nil
	}
	return x.A
}
