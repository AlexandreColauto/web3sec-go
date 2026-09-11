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
	"encoding/json"
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

// ---- remappings.txt -------------------------------------------------------

// versionTagRe finds an @<version> tag inside a remapping target. The LAST
// match wins, so a scoped or nested target still yields its trailing tag.
var versionTagRe = regexp.MustCompile(`@([A-Za-z0-9][A-Za-z0-9._-]*)`)

// parseRemappings reads forge's remappings.txt: one dependency fact per
// non-empty, non-comment line. package is the remapping prefix (its trailing
// path separator is syntax, not part of the name), version is the target's
// @<version> tag when it carries one (else ""), and pin is the line verbatim.
func parseRemappings(name string, lines []string) ([]depEntry, error) {
	out := []depEntry{}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return nil, manifestError(name, i+1,
				"malformed remapping (no '=')")
		}
		left := strings.TrimSpace(line[:eq])
		right := strings.TrimSpace(line[eq+1:])
		if left == "" || right == "" {
			return nil, manifestError(name, i+1,
				"malformed remapping (empty prefix or target)")
		}
		out = append(out, depEntry{
			pkg: strings.TrimSuffix(left, "/"),
			ver: versionTag(right),
			pin: raw,
		})
	}
	return out, nil
}

// versionTag is the last @<version> tag in a remapping target, or "".
func versionTag(target string) string {
	m := versionTagRe.FindAllStringSubmatch(target, -1)
	if len(m) == 0 {
		return ""
	}
	return m[len(m)-1][1]
}

// ---- go.sum ---------------------------------------------------------------

// parseGoSum reads go.sum's `<module> <version> <hash>` lines. Each module
// appears twice (the module hash and the go.mod hash of the same
// module@version); the /go.mod mirror lines are folded into their entry
// rather than emitted twice, which is a format rule, not a silent skip.
func parseGoSum(name string, lines []string) ([]depEntry, error) {
	out := []depEntry{}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, manifestError(name, i+1,
				"malformed go.sum line (want '<module> <version> <hash>')")
		}
		if strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		if !strings.HasPrefix(fields[1], "v") {
			return nil, manifestError(name, i+1,
				"malformed go.sum version %q", fields[1])
		}
		out = append(out, depEntry{pkg: fields[0], ver: fields[1], pin: line})
	}
	return out, nil
}

// ---- TOML [[table]] blocks (Cargo.lock, a TOML foundry.lock) --------------

// parseTomlPackages reads an array-of-tables manifest: every `[[table]]`
// block must carry a string `name` and a string `version`, and a block that
// does not is an error at the block's opening line.
func parseTomlPackages(name string, lines []string, table string) ([]depEntry,
	error) {
	out := []depEntry{}
	inBlock := false
	blockLine := 0
	pkg, ver, nameLine, verLine := "", "", "", ""
	closeBlock := func() error {
		if !inBlock {
			return nil
		}
		inBlock = false
		if pkg == "" || ver == "" {
			return manifestError(name, blockLine,
				"%s entry is missing name or version", table)
		}
		out = append(out, depEntry{pkg: pkg, ver: ver,
			pin: nameLine + "\n" + verLine})
		return nil
	}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[[") {
			if err := closeBlock(); err != nil {
				return nil, err
			}
			if line == "[["+table+"]]" {
				inBlock, blockLine = true, i+1
				pkg, ver, nameLine, verLine = "", "", "", ""
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			// any other table ends the block currently open
			if err := closeBlock(); err != nil {
				return nil, err
			}
			continue
		}
		if !inBlock || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := tomlString(line)
		if !ok {
			continue
		}
		switch key {
		case "name":
			pkg, nameLine = val, line
		case "version":
			ver, verLine = val, line
		}
	}
	if err := closeBlock(); err != nil {
		return nil, err
	}
	return out, nil
}

// tomlString is `key = "value"` for a single-line TOML string entry.
func tomlString(line string) (string, string, bool) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:eq])
	val := strings.TrimSpace(line[eq+1:])
	if len(val) < 2 || val[0] != '"' || val[len(val)-1] != '"' {
		return "", "", false
	}
	if key == "" {
		return "", "", false
	}
	return key, val[1 : len(val)-1], true
}

// ---- package-lock.json ----------------------------------------------------

var (
	packageLockNodeRe = regexp.MustCompile(`^"node_modules/([^"/]+)":\s*\{`)
	packageLockV1Re   = regexp.MustCompile(`^"([^"]+)":\s*\{`)
	jsonVersionRe     = regexp.MustCompile(`^"version":\s*"([^"]*)"`)
	jsonVersionAnyRe  = regexp.MustCompile(`"version":\s*"([^"]*)"`)
)

// parsePackageLock reads npm's package-lock.json: the v2/v3 `packages` map
// (direct = a single-segment `node_modules/<name>` key; nested hoists are not
// direct dependencies) or, when there is no `packages` map, the v1
// top-level `dependencies` keys. An entry without a `version` is an error at
// the entry's key line.
func parsePackageLock(name string, lines []string) ([]depEntry, error) {
	start, mode := locatePackageLock(lines)
	if start < 0 {
		return nil, manifestError(name, 1,
			"malformed package-lock.json (no packages/dependencies object)")
	}
	base := indentOf(lines[start])
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" {
			continue
		}
		if indentOf(lines[i]) <= base && strings.HasPrefix(t, "}") {
			end = i
			break
		}
	}
	entryIndent := base + 2
	keyRe := packageLockNodeRe
	if mode == "v1" {
		keyRe = packageLockV1Re
	}
	out := []depEntry{}
	for i := start + 1; i < end; {
		line := lines[i]
		t := strings.TrimSpace(line)
		if t == "" || indentOf(line) != entryIndent || !keyRe.MatchString(t) {
			i++
			continue
		}
		pkg := keyRe.FindStringSubmatch(t)[1]
		ver, verLine := "", ""
		if m := jsonVersionAnyRe.FindStringSubmatch(t); m != nil {
			// compact form: the entry object is on the key's own line
			ver, verLine = m[1], line
		}
		j := i + 1
		for ; verLine == "" && j < end; j++ {
			tj := strings.TrimSpace(lines[j])
			if tj == "" {
				continue
			}
			if m := jsonVersionRe.FindStringSubmatch(tj); m != nil {
				ver, verLine = m[1], lines[j]
				break
			}
			if indentOf(lines[j]) <= entryIndent {
				break
			}
		}
		if verLine == "" {
			return nil, manifestError(name, i+1,
				"package-lock.json entry %q has no version", pkg)
		}
		out = append(out, depEntry{pkg: pkg, ver: ver,
			pin: line + "\n" + verLine})
		i = j
	}
	if len(out) == 0 {
		return nil, manifestError(name, start+1,
			"package-lock.json exposes no dependency entries")
	}
	return out, nil
}

// locatePackageLock finds the dependency map: `packages` (npm v2/v3) wins
// wherever it appears, else the v1 `dependencies` object.
func locatePackageLock(lines []string) (int, string) {
	for _, mode := range []string{"packages", "v1"} {
		key := `"packages"`
		if mode == "v1" {
			key = `"dependencies"`
		}
		for i, raw := range lines {
			t := strings.TrimSpace(raw)
			if strings.HasPrefix(t, key) && strings.HasSuffix(t, "{") {
				return i, mode
			}
		}
	}
	return -1, ""
}

// ---- yarn.lock ------------------------------------------------------------

var yarnVersionRe = regexp.MustCompile(`^version[:\s]\s*["']?([^"'\s]+)["']?`)

// parseYarnLock reads yarn.lock v1 and berry: an unindented header line ends
// with ':', and its block must carry a `version` line (v1 `version "x"` or
// berry `version: x`). A header without one is an error at the header line.
func parseYarnLock(name string, lines []string) ([]depEntry, error) {
	out := []depEntry{}
	header, headerText, pkg, ver, verLine := -1, "", "", "", ""
	flush := func() error {
		if header < 0 {
			return nil
		}
		h, ht, p := header, headerText, pkg
		header = -1
		if ver == "" {
			return manifestError(name, h+1,
				"yarn.lock entry %q has no version line", ht)
		}
		out = append(out, depEntry{pkg: p, ver: ver, pin: ht + "\n" + verLine})
		return nil
	}
	for i, raw := range lines {
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if indentOf(raw) == 0 {
			if err := flush(); err != nil {
				return nil, err
			}
			if !strings.HasSuffix(t, ":") {
				return nil, manifestError(name, i+1,
					"yarn.lock entry header %q does not end with ':'", t)
			}
			if strings.HasPrefix(t, "__metadata") {
				continue // berry's global metadata, not a dependency
			}
			header, headerText = i, raw
			pkg, ver, verLine = yarnPackage(t), "", ""
			continue
		}
		if header < 0 || ver != "" {
			continue
		}
		if m := yarnVersionRe.FindStringSubmatch(t); m != nil {
			ver, verLine = m[1], raw
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

// yarnPackage is the package name of a yarn header: the first comma-separated
// range, with its @<range> suffix removed (scoped names keep their leading @).
func yarnPackage(header string) string {
	h := strings.TrimSuffix(strings.TrimSpace(header), ":")
	h = strings.Trim(h, `"'`)
	if c := strings.Index(h, ","); c >= 0 {
		h = h[:c]
	}
	h = strings.TrimSpace(h)
	if at := strings.LastIndex(h, "@"); at > 0 {
		return h[:at]
	}
	return h
}

// ---- pnpm-lock.yaml -------------------------------------------------------

var pnpmVersionRe = regexp.MustCompile(`^version:\s*["']?([^"'#\s]+)["']?`)

// parsePnpmLock reads the importers section of pnpm-lock.yaml: each
// dependencies/devDependencies/optionalDependencies map contributes its
// entries (name + version). A dependency without a version line is an error
// at the dependency's line.
func parsePnpmLock(name string, lines []string) ([]depEntry, error) {
	out := []depEntry{}
	for i := 0; i < len(lines); {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			i++
			continue
		}
		if !isPnpmDepsSection(t) {
			i++
			continue
		}
		sec := indentOf(lines[i])
		j := i + 1
		for ; j < len(lines); j++ {
			tj := strings.TrimSpace(lines[j])
			if tj == "" || strings.HasPrefix(tj, "#") {
				continue
			}
			ij := indentOf(lines[j])
			if ij <= sec {
				break
			}
			if ij != sec+2 || !strings.HasSuffix(tj, ":") {
				return nil, manifestError(name, j+1,
					"pnpm-lock.yaml dependency entry %q is malformed", tj)
			}
			pkg := strings.Trim(strings.TrimSuffix(tj, ":"), `"'`)
			ver, verLine, k := "", "", j+1
			for ; k < len(lines); k++ {
				tk := strings.TrimSpace(lines[k])
				if tk == "" || strings.HasPrefix(tk, "#") {
					continue
				}
				if indentOf(lines[k]) <= sec+2 {
					break
				}
				if m := pnpmVersionRe.FindStringSubmatch(tk); m != nil {
					ver, verLine = m[1], lines[k]
					break
				}
			}
			if verLine == "" {
				return nil, manifestError(name, j+1,
					"pnpm-lock.yaml entry %q has no version", pkg)
			}
			out = append(out, depEntry{pkg: pkg, ver: ver,
				pin: lines[j] + "\n" + verLine})
			j = k
		}
		i = j
	}
	if len(out) == 0 {
		return nil, manifestError(name, 1,
			"malformed pnpm-lock.yaml (no importer dependencies)")
	}
	return out, nil
}

// isPnpmDepsSection is one of the three dependency maps an importer carries.
func isPnpmDepsSection(t string) bool {
	switch t {
	case "dependencies:", "devDependencies:", "optionalDependencies:":
		return true
	}
	return false
}

// ---- foundry.lock ---------------------------------------------------------

// parseFoundryJSON reads forge's foundry.lock: a JSON object keyed by the
// installed dependency path, each value carrying a `tag`/`branch` object
// (whose `name` is the pinned version) or a bare `rev`. A dependency path is
// the package name (its last path segment).
func parseFoundryJSON(name string, raw []byte) ([]depEntry, error) {
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		return nil, manifestError(name, jsonErrorLine(raw, err),
			"malformed foundry.lock (%s)", err)
	}
	if doc.Kind != validation.Obj {
		return nil, manifestError(name, 1,
			"malformed foundry.lock (want a JSON object)")
	}
	lines := manifestLines(raw)
	out := []depEntry{}
	for _, pair := range doc.O {
		ver := ""
		if tag := objAt(pair.V, "tag"); tag.Kind == validation.Obj {
			ver = objAt(tag, "name").S
		}
		if ver == "" {
			if br := objAt(pair.V, "branch"); br.Kind == validation.Obj {
				ver = objAt(br, "name").S
			}
		}
		if ver == "" {
			ver = objAt(pair.V, "rev").S
		}
		line, ok := entryStartLine(lines, pair.K)
		if !ok {
			line = 1
		}
		if ver == "" {
			return nil, manifestError(name, line,
				"foundry.lock entry %q has no tag, branch or rev", pair.K)
		}
		out = append(out, depEntry{pkg: pathBase(pair.K), ver: ver,
			pin: rawEntryText(lines, line)})
	}
	return out, nil
}

// pathBase is the last path segment of a dependency path (the package name).
func pathBase(p string) string {
	t := strings.TrimSuffix(p, "/")
	if s := strings.LastIndex(t, "/"); s >= 0 {
		return t[s+1:]
	}
	return t
}

// entryStartLine finds the line that opens entry key's object, so a
// malformed entry can be reported with a line and its text captured.
func entryStartLine(lines []string, key string) (int, bool) {
	needle := `"` + key + `"`
	for i, raw := range lines {
		if strings.HasPrefix(strings.TrimSpace(raw), needle) {
			return i, true
		}
	}
	return 0, false
}

// rawEntryText is the verbatim text of the JSON entry opening at start: from
// its key line through the line that closes its braces.
func rawEntryText(lines []string, start int) string {
	depth := 0
	opened := false
	for i := start; i < len(lines); i++ {
		depth += strings.Count(lines[i], "{")
		depth -= strings.Count(lines[i], "}")
		if strings.Contains(lines[i], "{") {
			opened = true
		}
		if opened && depth <= 0 {
			return strings.Join(lines[start:i+1], "\n")
		}
	}
	return strings.Join(lines[start:], "\n")
}

// jsonErrorLine maps an encoding/json syntax error offset onto a 1-based
// line number (the readers report file+line, like every other entry error).
func jsonErrorLine(raw []byte, err error) int {
	var se *json.SyntaxError
	if errors.As(err, &se) && se.Offset > 0 {
		off := int(se.Offset)
		if off > len(raw) {
			off = len(raw)
		}
		return 1 + strings.Count(string(raw[:off]), "\n")
	}
	return 1
}
