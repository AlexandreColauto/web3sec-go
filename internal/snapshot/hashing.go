// Package snapshot ports web3sec-final/src/webv2/snapshot.py: content
// hashing, merkle ladders, and the pin/manifest machinery.
package snapshot

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/validation"
)

// SourceExcludes mirrors SOURCE_EXCLUDES. The check is NAME-based against
// EVERY component of the ABSOLUTE path (Python: set(p.parts) &
// SOURCE_EXCLUDES) — so a root that itself lives under a directory named
// e.g. "cache" has every file excluded, and a FILE named "cache" is
// excluded too. Faithful, quirky, kept.
var SourceExcludes = map[string]struct{}{
	".git":              {},
	".hg":               {},
	".slps":             {},
	"node_modules":      {},
	"cache":             {},
	"out":               {},
	".venv":             {},
	"__pycache__":       {},
	".mantis_snapshots": {},
}

// LockfileNames mirrors LOCKFILE_NAMES (order preserved).
var LockfileNames = []string{
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
	"go.sum", "uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt",
	"Foundry.lock",
}

type fileEntry struct {
	rel string // posix, relative to root
	abs string
}

// pinnedFiles is _pinned_files: the files a snapshot's digests cover —
// same exclusions as _content_hash, plus the pin's own metadata file at
// the root. Order is Python's sorted(Path) order: compare the component
// (PARTS) tuple, not the joined string.
func pinnedFiles(root string) ([]fileEntry, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	skip := map[string]struct{}{"snapshot.json": {}}
	var files []fileEntry
	walkErr := filepath.WalkDir(rootAbs, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			// pathlib's rglob swallows scandir errors below the root;
			// the root itself failing is real.
			if p == rootAbs {
				return err
			}
			return nil
		}
		if p == rootAbs {
			return nil
		}
		// is_file(): follows symlinks; broken links and dirs drop out.
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			return nil
		}
		for _, part := range strings.Split(p, string(os.PathSeparator)) {
			if _, bad := SourceExcludes[part]; bad {
				return nil
			}
		}
		if filepath.Dir(p) == rootAbs {
			if _, s := skip[filepath.Base(p)]; s {
				return nil
			}
		}
		files = append(files, fileEntry{
			rel: strings.TrimPrefix(p, rootAbs+string(os.PathSeparator)),
			abs: p,
		})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Slice(files, func(i, j int) bool {
		a := strings.Split(files[i].rel, "/")
		b := strings.Split(files[j].rel, "/")
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})
	return files, nil
}

// PinnedFiles returns the pinned files as posix paths relative to root.
func PinnedFiles(root string) ([]string, error) {
	files, err := pinnedFiles(root)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.rel
	}
	return out, nil
}

func putLen8(h io.Writer, n int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	h.Write(b[:])
}

// ContentHash is _content_hash: sha256 over every pinned file, path-sorted
// (parts order), each file framed as 8be(len(rel)) + rel + 8be(size) +
// content (streamed, exactly size bytes). The length prefixes make the
// digest unambiguous. Returns (hex digest, file count).
func ContentHash(root string) (string, int, error) {
	files, err := pinnedFiles(root)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	for _, f := range files {
		st, err := os.Stat(f.abs)
		if err != nil {
			return "", 0, err
		}
		putLen8(h, int64(len(f.rel)))
		h.Write([]byte(f.rel))
		putLen8(h, st.Size())
		fh, err := os.Open(f.abs)
		if err != nil {
			return "", 0, err
		}
		// fh.read(min(1<<16, remaining)) until the size is consumed:
		// LimitReader stops at exactly st.Size() bytes (an early EOF
		// stops the copy, same as the Python loop's `if not chunk`).
		io.Copy(h, io.LimitReader(fh, st.Size()))
		fh.Close()
	}
	return hex.EncodeToString(h.Sum(nil)), len(files), nil
}

// FileLeaf is _file_leaf: the 32-byte merkle leaf for one file —
// sha256(8be(len(rel)) + rel + 8be(len(data)) + data).
func FileLeaf(p, root string) ([]byte, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	pAbs, err := filepath.Abs(p)
	if err != nil {
		return nil, err
	}
	rel := pAbs
	if strings.HasPrefix(pAbs, rootAbs+string(os.PathSeparator)) {
		rel = strings.TrimPrefix(pAbs, rootAbs+string(os.PathSeparator))
	}
	data, err := os.ReadFile(pAbs)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	putLen8(h, int64(len(rel)))
	h.Write([]byte(rel))
	putLen8(h, int64(len(data)))
	h.Write(data)
	return h.Sum(nil), nil
}

// MerkleRoot is _merkle_root: iterative binary merkle; an odd node is
// duplicated; the empty tree hashes to sha256("").
func MerkleRoot(leaves [][]byte) string {
	if len(leaves) == 0 {
		return hex.EncodeToString(sha256.New().Sum(nil))
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha256.New()
			h.Write(level[i])
			h.Write(level[i+1])
			next[i/2] = h.Sum(nil)
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}

// Canonical is _canonical: the one deterministic serialization every
// manifest fingerprint is computed over (sorted keys, no whitespace,
// escaped non-ASCII) = the compact canonical JSON.
func Canonical(v validation.Value) string {
	return validation.CanonCompact(v)
}

// SourceMerkleRoot is source_merkle_root: merkle over the file leaves of
// every pinned file.
func SourceMerkleRoot(snapDir string) (string, error) {
	files, err := pinnedFiles(snapDir)
	if err != nil {
		return "", err
	}
	leaves := make([][]byte, len(files))
	for i, f := range files {
		leaf, err := FileLeaf(f.abs, snapDir)
		if err != nil {
			return "", err
		}
		leaves[i] = leaf
	}
	return MerkleRoot(leaves), nil
}

// LockfileLeaves returns the file leaves of the pinned files whose NAME is
// a known dependency lockfile, in pinned order (the input to the
// manifest's dependency_lock_hash).
func LockfileLeaves(snapDir string) ([][]byte, error) {
	files, err := pinnedFiles(snapDir)
	if err != nil {
		return nil, err
	}
	var leaves [][]byte
	for _, f := range files {
		if _, ok := lockfileSet()[filepath.Base(f.rel)]; ok {
			leaf, err := FileLeaf(f.abs, snapDir)
			if err != nil {
				return nil, err
			}
			leaves = append(leaves, leaf)
		}
	}
	return leaves, nil
}

var lockfileSetMemo map[string]struct{}

func lockfileSet() map[string]struct{} {
	if lockfileSetMemo == nil {
		m := make(map[string]struct{}, len(LockfileNames))
		for _, n := range LockfileNames {
			m[n] = struct{}{}
		}
		lockfileSetMemo = m
	}
	return lockfileSetMemo
}
