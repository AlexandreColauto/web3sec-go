package validation

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ListPrefixed is filepath.Glob(filepath.Join(dir, prefix+"*"+suffix)) without
// the glob. A Glob treats the WHOLE path as a pattern: a campaign rooted under
// a directory whose name contains a metacharacter ([ ] ? *) — "audit [2026]",
// a shell glob expanded into a path — matched nothing, and every finding,
// chain and memory reader in the tool silently reported an empty campaign
// because of where the operator happened to put it.
//
// The result is the sorted full paths of dir's regular files whose base name
// starts with prefix and ends with suffix. A missing or unreadable dir is an
// empty list, exactly as a Glob with no matches is.
func ListPrefixed(dir, prefix, suffix string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	sort.Strings(out)
	return out
}

// ListSubPrefixed is filepath.Glob(filepath.Join(dir, subPrefix+"*", leaf))
// without the glob: the sorted paths of <dir>/<subPrefix>*/<leaf> (the EXEC-*
// record layout). The leaf is taken literally, so a campaign root containing
// a metacharacter still lists its records.
func ListSubPrefixed(dir, subPrefix, leaf string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), subPrefix) {
			continue
		}
		p := filepath.Join(dir, e.Name(), leaf)
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
