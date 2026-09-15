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
// starts with prefix and ends with suffix, and os.ReadDir's error. The error
// is returned raw, so the caller can tell the three cases apart:
//
//   - the directory does not exist: os.IsNotExist(err) is true. A campaign
//     that has produced no findings yet has no findings/ directory; that is
//     an empty list, and the caller decides so (ListPrefixedOptional encodes
//     the common form of that decision).
//   - the directory was read: err is nil and the list is the whole truth.
//   - the directory could not be read (EACCES, ENOTDIR, EIO): err is non-nil
//     and NOT IsNotExist. A caller that cannot list the directory has no
//     evidence about its contents and must refuse, naming the path — never
//     report a count. Folding this case into an empty list is exactly how an
//     unreadable evidence store answered "findings=0" and let `audit` pass
//     while every "every CONFIRMED finding needs X" proof clause came out
//     vacuously done.
func ListPrefixed(dir, prefix, suffix string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
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
	return out, nil
}

// ListPrefixedOptional is ListPrefixed for a directory whose ABSENCE is
// meaningful on its own: a campaign that has not produced any findings,
// chains, memory or execs yet simply has no directory, and an empty list is
// the honest answer. ONLY os.IsNotExist is folded into emptiness. Every other
// error (EACCES, ENOTDIR, EIO) is returned unchanged, so the caller refuses.
//
// This is deliberately NOT the old silent behaviour: the old helper folded
// every error into `return nil`, so an unreadable directory was
// indistinguishable from an empty one. Here the swallow is one named class of
// error, and the caller still writes the refusal (naming the path) for the
// rest.
//
// Do not use this on a path whose absence is itself a problem the caller must
// report: call ListPrefixed and handle the error directly.
func ListPrefixedOptional(dir, prefix, suffix string) ([]string, error) {
	paths, err := ListPrefixed(dir, prefix, suffix)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return paths, nil
}

// ListSubPrefixed is filepath.Glob(filepath.Join(dir, subPrefix+"*", leaf))
// without the glob: the sorted paths of <dir>/<subPrefix>*/<leaf> (the EXEC-*
// record layout). The leaf is taken literally, so a campaign root containing
// a metacharacter still lists its records.
//
// Error handling matches ListPrefixed. The per-entry os.Stat is also honest
// about its three cases: a leaf that does not exist is the layout filter
// working as documented (rows lacking the leaf are skipped), while a leaf
// that cannot be stat'ed (EACCES, EIO) means the record's existence cannot be
// decided — that error propagates instead of silently dropping the row.
func ListSubPrefixed(dir, subPrefix, leaf string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), subPrefix) {
			continue
		}
		p := filepath.Join(dir, e.Name(), leaf)
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// ListSubPrefixedOptional is ListSubPrefixed with the same
// absence-is-not-an-error contract as ListPrefixedOptional: only
// os.IsNotExist on the directory itself is folded into an empty list; every
// other error, including a leaf that cannot be stat'ed, is returned for the
// caller to refuse with.
func ListSubPrefixedOptional(dir, subPrefix, leaf string) ([]string, error) {
	paths, err := ListSubPrefixed(dir, subPrefix, leaf)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return paths, nil
}
