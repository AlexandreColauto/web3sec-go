// Package srcclass classifies a source file by what it IS in the audit
// surface: an implementation, a test double, an interface, a library, or
// something else entirely.
//
// The package exists because two surfaces need the SAME answer and must not
// carry two vocabularies:
//
//   - internal/probes ranks rows down when they live in scaffolding (a test
//     double is not a second site of a pattern), and
//   - `webv2 scorecard` reports the audit SURFACE — how many files of a pin
//     are actually implementation code, since "153 files / 31k lines" is a
//     number that silently includes the mocks and the vendored libraries.
//
// WHY there is an `other` class, and why it is first in the rule order: a
// headline file count was never a count of solidity to reason about. A tree
// that holds foundry.toml, README.md and a data.json has three more files
// than it has contracts, and the count that misleads an operator is the one
// that silently includes config and docs — not the one that visibly omits
// them. So the extension decides before any directory rule: a file that is
// not `*.sol` is not solidity, and a README under lib/ is neither a library
// of solidity nor an implementation. Only a `*.sol` file is then asked the
// directory questions.
//
// The test-double rule is the probes' original: a path segment naming a test
// directory, or a file name that is a mock or a `.t.sol` foundry test. The
// interface rule is the Solidity convention (`IName.sol` with a capital N, or
// a path naming an interfaces directory). The library rule covers vendored and
// shared code: lib/, libs/, libraries/, external/, vendor/, node_modules/,
// forge-std/. Implementation is what is left of the solidity — the code a
// finding has to live in to be about the product.
//
// Precedence matters and is fixed: not-solidity > test-double > library >
// interface > implementation. A mock under lib/ is scaffolding first; an
// interface nobody can store state in is not an implementation; and a
// non-solidity file is none of the solidity roles however its path reads.
package srcclass

import (
	"regexp"
	"strings"
	"unicode"
)

// Class is one of the five surface roles.
type Class string

// The five classes. Strings are the values a --json view prints, so they are
// part of the output contract.
const (
	Implementation Class = "implementation"
	TestDouble     Class = "test-double"
	Library        Class = "library"
	Interface      Class = "interface"
	Other          Class = "other"
)

// Classes is the reporting order (implementation first: it is the number an
// operator reads for "how much code did I actually audit"; other last, as the
// remainder that is not code to audit at all).
var Classes = []Class{Implementation, TestDouble, Library, Interface, Other}

var testDoubleDirs = map[string]struct{}{
	"mock": {}, "mocks": {}, "test": {}, "tests": {}, "harness": {}, "fixtures": {},
}

var testDoubleFileRe = regexp.MustCompile(`(?i)^mock[\w.-]*\.sol$|\w*mock\.sol$|\.t\.sol$`)

var libraryDirs = map[string]struct{}{
	"lib": {}, "libs": {}, "libraries": {}, "external": {}, "vendor": {},
	"node_modules": {}, "forge-std": {}, "openzeppelin": {}, "@openzeppelin": {},
}

// interfaceDirs is the directory half of the interface rule. It is matched per
// SEGMENT, like testDoubleDirs and libraryDirs: a path is recorded relative to
// its pin root, so `interfaces/Foo.sol` (the directory first) is the same
// statement as `src/interfaces/Foo.sol`, and a substring test that demands a
// leading slash answers those two differently.
var interfaceDirs = map[string]struct{}{
	"interface": {}, "interfaces": {}, "abstract": {},
}

// slash normalizes a path to forward slashes with no trailing slash.
func slash(path string) string {
	p := strings.ReplaceAll(path, "\\", "/")
	return strings.Trim(p, "/")
}

// dirs returns the directory segments and the basename of a normalized path.
func dirs(p string) ([]string, string) {
	if p == "" {
		return nil, ""
	}
	parts := strings.Split(p, "/")
	return parts[:len(parts)-1], parts[len(parts)-1]
}

func lower(s string) string { return strings.ToLower(s) }

// Classify returns the surface role of a path.
func Classify(path string) Class {
	p := slash(path)
	if p == "" {
		return Implementation
	}
	segs, name := dirs(p)
	// The .sol gate runs BEFORE every directory rule: a file that is not
	// solidity is not an implementation, a library, an interface or a test
	// double of solidity, whatever its directory happens to be named.
	if !strings.HasSuffix(lower(name), ".sol") {
		return Other
	}
	for _, seg := range segs {
		if _, ok := testDoubleDirs[lower(seg)]; ok {
			return TestDouble
		}
	}
	if testDoubleFileRe.MatchString(name) {
		return TestDouble
	}
	for _, seg := range segs {
		if _, ok := libraryDirs[lower(seg)]; ok {
			return Library
		}
	}
	if lower(name) == "interfaces.sol" {
		return Interface
	}
	for _, seg := range segs {
		if _, ok := interfaceDirs[lower(seg)]; ok {
			return Interface
		}
	}
	if len(name) > 4 && name[0] == 'I' && len(name) > 1 &&
		unicode.IsUpper(rune(name[1])) {
		return Interface
	}
	return Implementation
}

// IsTestDouble is the scaffolding predicate the probe ranking uses. A test
// double is not a second site of a pattern.
func IsTestDouble(path string) bool { return Classify(path) == TestDouble }
