// hashing.go: artifact hashing — a file's sha256 and the input_hashes tree
// over the resolved workdir (r36 F4).
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"websec/internal/validation"
)

// shaFile is _sha.
func shaFile(path string) string {
	digest, err := shaFileErr(path)
	if err != nil {
		return "" // best-effort: shaFileErr exists for callers that must know
	}
	return digest
}

// shaFileErr is shaFile with the error surfaced, so a hash that cannot be
// computed can be reported instead of silently digesting nothing.
func shaFileErr(path string) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashDir is _hash_dir: relative path -> sha256 for every file under the
// RESOLVED directory d, in sorted relative-path order ([] when d is nil
// or absent). r36 F4: the root is resolved first, so a symlink workdir
// hashes the directory the process actually ran in instead of producing
// the fabricated {'.': ”} the old Lstat-on-symlink path emitted; and a
// digest that cannot be computed is recorded EXPLICITLY as
// "sha256-unavailable (...)" — never as an empty string, which a
// consumer could mistake for a real digest (an empty digest is a
// fabrication; absence or an explicit failure, nothing else).
func hashDir(d *string) validation.Value {
	if d == nil {
		return validation.VObj()
	}
	root := resolvedPath(*d)
	fi, err := os.Stat(root)
	if err != nil || !fi.IsDir() {
		return validation.VObj()
	}
	var rels []string
	_ = filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr == nil {
			rels = append(rels, rel)
		}
		return nil
	})
	sort.Strings(rels)
	o := make([]validation.KV, 0, len(rels))
	for _, rel := range rels {
		digest, err := shaFileErr(filepath.Join(root, rel))
		if err != nil {
			o = append(o, validation.KV{K: rel, V: validation.VStr(
				"sha256-unavailable (" + err.Error() + ")")})
			continue
		}
		o = append(o, validation.KV{K: rel, V: validation.VStr(digest)})
	}
	return validation.VObj(o...)
}
