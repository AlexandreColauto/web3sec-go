// Shared doctor helpers: note-length reading, the pin file walk, path
// splitting, in-place key writes, integer rendering and the mirror delta.
package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"

	"websec/internal/validation"
)

// runeLen is Python's len(str) for the note shapes doctor caps.
func runeLen(v validation.Value) int {
	if v.Kind == validation.Str {
		return utf8.RuneCountInString(v.S)
	}
	return 0
}

// walkFiles is `[p for p in snap_dir.rglob("*") if p.is_file()]`.
func walkFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		fi, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				// The entry vanished between the listing and the stat, or
				// the name is a broken symlink: absence, not a read failure.
				return nil
			}
			// r44b P3-a: this used to `return nil` on EVERY stat error, so a
			// pin dir that lists but cannot be searched (mode 0400 — the
			// names come back, the stat of each entry does not) made the
			// scope report "0 files, 0.0 MB": the r37b empty-but-present
			// lie, over a tree this run never read. It is the same fold as
			// the missing manifest above, and both refuse.
			return fmt.Errorf("the snapshot store %s cannot be read: %v", p, err)
		}
		if fi.Mode().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// splitPath is PurePath.parts for a relative path.
func splitPath(rel string) []string {
	var out []string
	cur := ""
	for _, r := range rel {
		if r == '/' || r == filepath.Separator {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// setKey replaces key in place (Python's dict assignment keeps position).
func setKey(v *validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return
		}
	}
	v.O = append(v.O, validation.KV{K: key, V: val})
}

// itoa is str(int).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// mirrorDelta compares the old projection tail against the rebuilt one
// by position: same-prefix counts (kept), positions present in both but
// unequal (changed — edited content under a chain that still verifies),
// extra old rows (dropped), extra new rows (added). Counts only; the
// human output prints the number, the JSON carries it.
func mirrorDelta(oldV, newV validation.Value) (kept, changed, dropped, added int64) {
	min := len(oldV.A)
	if len(newV.A) < min {
		min = len(newV.A)
	}
	for i := 0; i < min; i++ {
		if validation.CanonSpaced(oldV.A[i]) == validation.CanonSpaced(newV.A[i]) {
			kept++
		} else {
			changed++
		}
	}
	dropped = int64(len(oldV.A) - min)
	added = int64(len(newV.A) - min)
	return
}
