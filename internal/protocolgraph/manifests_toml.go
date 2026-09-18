package protocolgraph

import (
	"strings"
)

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
