// manifests.go: the offline "adapter" readers behind `model --facts <dir>`
// (I4, Wave I Task 8), mirroring the G1 dataset-loader pattern: format
// detection is by file name, parsing is total (an entry the reader cannot
// read is an ERROR naming the file and the line, never a silent skip), and
// the output order is the pinned manifest order below.
//
// READ THIS BEFORE ADDING A READER: there is deliberately NO DNS READER and
// no DNS code path here. A manifest directory can only ever yield
// dependency facts; a DNS fact exists only in an operator-written
// operator_facts document, because there is nothing offline to resolve from.
// Nothing in this file opens a socket, and the observed_at stamped on every
// extracted fact is the caller-supplied operator date — never a local clock.
package protocolgraph

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"websec/internal/validation"
)

// factManifests is the pinned read order: changing it changes the emitted
// fact order (and therefore the document bytes) for a directory holding more
// than one manifest.
var factManifests = []string{
	"remappings.txt",
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"Cargo.lock",
	"go.sum",
	"foundry.lock",
}

// manifestAliases maps a pinned manifest name to the alternative spelling(s)
// a different tool version may have used (forge writes foundry.lock; the
// plan text spells it Foundry.lock — both are read).
var manifestAliases = map[string][]string{
	"foundry.lock": {"Foundry.lock"},
}

// depEntry is one dependency assertion read out of an offline manifest:
// the package name, its pinned version ("" when a remapping carries no
// version tag), and the verbatim entry text.
type depEntry struct {
	pkg string
	ver string
	pin string
}

// observedAtRe is the only date shape accepted: a fact's date is an operator
// assertion, and an unparseable one must not be smuggled through.
var observedAtRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// FactsFromDir is the directory half of `--facts`: read every supported
// offline manifest in dir, deterministically and in factManifests order, and
// return a schema-valid operator_facts document. observedAt is the operator's
// assertion date stamped on every extracted fact (the CLI requires it for
// directories; it is never taken from the wall clock).
//
// A directory with no supported manifest is an ERROR, not an empty success.
// Every extracted fact targets an offchain-service component whose path is
// the pinned package name: one component per tracked dependency, which is
// what makes the "second dependency fact for one component" law meaningful
// (a package pinned twice is a contradiction, not a merge).
func FactsFromDir(dir, observedAt string) (validation.Value, error) {
	if !observedAtRe.MatchString(observedAt) {
		return validation.VNull(), fmt.Errorf(
			"operator facts: observed_at must be YYYY-MM-DD, got %q", observedAt)
	}
	facts := []validation.Value{}
	found := false
	for _, name := range factManifests {
		rel, raw, err := openManifest(dir, name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return validation.VNull(), err
		}
		found = true
		entries, err := parseManifest(rel, raw)
		if err != nil {
			return validation.VNull(), err
		}
		for _, e := range entries {
			facts = append(facts, validation.VObj(
				kv("target", validation.VObj(
					kv("kind", validation.VStr("offchain-service")),
					kv("path", validation.VStr(e.pkg)),
				)),
				kv("dependency", validation.VObj(
					kv("observed_at", validation.VStr(observedAt)),
					kv("source", validation.VStr("operator-supplied manifest")),
					kv("package", validation.VStr(e.pkg)),
					kv("version", validation.VStr(e.ver)),
					kv("pin", validation.VStr(e.pin)),
					kv("resolved_from", validation.VStr(rel)),
				)),
			))
		}
	}
	if !found {
		return validation.VNull(), fmt.Errorf("no supported manifest in %s", dir)
	}
	doc := validation.VObj(
		kv("schema_version", validation.VStr("1")),
		kv("facts", validation.VArr(facts...)),
	)
	// the extractor must emit exactly what the document schema accepts; a
	// mismatch is a bug in this file, so fail loudly here rather than later
	if err := validation.Validate(doc, "operator_facts", 1); err != nil {
		return validation.VNull(), fmt.Errorf(
			"operator facts: extraction produced an invalid document: %w", err)
	}
	return doc, nil
}

// openManifest reads the first spelling of a manifest that exists, returning
// the name it was actually read under (that name is the fact's
// resolved_from). A missing manifest is fs.ErrNotExist for the caller to
// skip; any other read error surfaces.
func openManifest(dir, name string) (string, []byte, error) {
	names := append([]string{name}, manifestAliases[name]...)
	var lastErr error = fs.ErrNotExist
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err == nil {
			return n, raw, nil
		}
		lastErr = err
		if !errors.Is(err, fs.ErrNotExist) {
			break
		}
	}
	return "", nil, lastErr
}

// parseManifest dispatches one manifest to its format-specific, total reader.
func parseManifest(name string, raw []byte) ([]depEntry, error) {
	lines := manifestLines(raw)
	switch name {
	case "remappings.txt":
		return parseRemappings(name, lines)
	case "package-lock.json":
		return parsePackageLock(name, lines)
	case "yarn.lock":
		return parseYarnLock(name, lines)
	case "pnpm-lock.yaml":
		return parsePnpmLock(name, lines)
	case "Cargo.lock":
		return parseTomlPackages(name, lines, "package")
	case "go.sum":
		return parseGoSum(name, lines)
	case "foundry.lock", "Foundry.lock":
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
			return parseFoundryJSON(name, raw)
		}
		return parseTomlPackages(name, lines, "dependencies")
	}
	return nil, fmt.Errorf("%s: unsupported manifest", name)
}

// manifestLines splits a manifest into lines with the newline stripped; CRLF
// is normalised so a Windows checkout does not change a single fact byte.
func manifestLines(raw []byte) []string {
	return strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
}

// manifestError renders the file+line shape every reader must use for an
// entry it cannot read: "<file>:<line>: <detail>".
func manifestError(name string, line int, format string, args ...any) error {
	return fmt.Errorf("%s:%d: %s", name, line, fmt.Sprintf(format, args...))
}

// indentOf is the leading-space count of a line (tabs count as one, which is
// only ever a fallback shape).
func indentOf(line string) int {
	n := 0
	for _, r := range line {
		if r == ' ' || r == '\t' {
			n++
			continue
		}
		break
	}
	return n
}
