package protocolgraph

import (
	"regexp"
	"strings"
)

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
