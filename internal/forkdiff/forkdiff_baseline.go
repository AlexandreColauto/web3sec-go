package forkdiff

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

// checkName is _check_name.
func checkName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid baseline name %s "+
			"(expected [a-z0-9][a-z0-9-]{1,40})", validation.PyReprStr(name))
	}
	return nil
}

func manifestPath() string { return filepath.Join(BaselinesDir, "manifest.json") }

// loadManifest is _load_manifest: the absent manifest reads as empty.
func loadManifest() (validation.Value, error) {
	p := manifestPath()
	if _, err := os.Stat(p); err != nil {
		return validation.VObj(
			validation.KV{K: "baselines", V: validation.VArr()},
			validation.KV{K: "updated_at", V: validation.VNull()},
		), nil
	}
	return validation.ReadJson(p)
}

// addBaselineOp carries one AddBaseline's shared context: the validated
// name/source pair, the resolved destination paths, and the caller's
// optional metadata pointers.
type addBaselineOp struct {
	name      string
	srcPath   string
	sourceURL *string
	licenseID *string
	destRoot  string
	destSrc   string
}

// AddBaseline is add_baseline: register a version-pinned baseline tree.
// Copies the source into baselines/<name>/src/ and records its fingerprint —
// the COPY is what gets matched against and drift-audited.
//
// The copy is staged in a temporary sibling directory and swapped over the
// live tree only after it (and its fingerprint) fully succeed, so a failed
// copy can never gut an existing baseline. A source that overlaps the
// destination tree is refused up front for the same reason.
func AddBaseline(name, srcPath string, sourceURL, licenseID *string) (validation.Value, error) {
	op := &addBaselineOp{name: name, srcPath: srcPath,
		sourceURL: sourceURL, licenseID: licenseID}
	if err := op.addBaselineCheckSource(); err != nil {
		return validation.VNull(), err
	}
	if err := op.addBaselineResolve(); err != nil {
		return validation.VNull(), err
	}
	fp, err := op.addBaselineInstall()
	if err != nil {
		return validation.VNull(), err
	}
	meta, err := op.addBaselineWriteMeta(fp)
	if err != nil {
		return validation.VNull(), err
	}
	if err := op.addBaselineUpdateManifest(); err != nil {
		return validation.VNull(), err
	}
	return meta, nil
}

// addBaselineCheckSource validates the name and that the source is a
// directory, before anything is resolved or written.
func (op *addBaselineOp) addBaselineCheckSource() error {
	if err := checkName(op.name); err != nil {
		return err
	}
	st, err := os.Stat(op.srcPath)
	if err != nil || !st.IsDir() {
		return fmt.Errorf(
			"baseline source not a directory: %s", op.srcPath)
	}
	return nil
}

// addBaselineResolve computes the destination paths and refuses a source
// that overlaps the destination tree (either direction), resolved through
// symlinks.
func (op *addBaselineOp) addBaselineResolve() error {
	op.destRoot = filepath.Join(BaselinesDir, op.name)
	op.destSrc = filepath.Join(op.destRoot, "src")
	srcRes, err := filepath.Abs(op.srcPath)
	if err != nil {
		return err
	}
	if r, err := filepath.EvalSymlinks(srcRes); err == nil {
		srcRes = r
	}
	destRes, err := filepath.Abs(op.destRoot)
	if err != nil {
		return err
	}
	if r, err := filepath.EvalSymlinks(destRes); err == nil {
		destRes = r
	}
	if srcRes == destRes || isAncestor(srcRes, destRes) || isAncestor(destRes, srcRes) {
		return fmt.Errorf(
			"baseline source %s overlaps the destination %s: refusing a "+
				"self-referential add", op.srcPath, op.destSrc)
	}
	return nil
}

// addBaselineInstall stages the copy in a temporary sibling directory,
// fingerprints it, and swaps it over the live tree.
func (op *addBaselineOp) addBaselineInstall() (validation.Value, error) {
	if err := os.MkdirAll(BaselinesDir, 0o755); err != nil {
		return validation.VNull(), err
	}
	if err := os.MkdirAll(op.destRoot, 0o755); err != nil {
		return validation.VNull(), err
	}
	staging, err := os.MkdirTemp(filepath.Dir(op.destRoot), "."+op.name+".tmp-")
	if err != nil {
		return validation.VNull(), err
	}
	defer os.RemoveAll(staging)
	stagedSrc := filepath.Join(staging, "src")
	if err := copyTree(op.srcPath, stagedSrc); err != nil {
		return validation.VNull(), err
	}
	fp, err := FingerprintTree(stagedSrc)
	if err != nil {
		return validation.VNull(), err
	}
	if err := op.addBaselineSwap(stagedSrc); err != nil {
		return validation.VNull(), err
	}
	return fp, nil
}

// addBaselineSwap moves the staged tree over the live src/, backing up and
// restoring the old tree when one already exists.
func (op *addBaselineOp) addBaselineSwap(stagedSrc string) error {
	if _, err := os.Lstat(op.destSrc); err == nil {
		backup := filepath.Join(filepath.Dir(op.destRoot), "."+op.name+".bak")
		if _, err := os.Lstat(backup); err == nil {
			if err := os.RemoveAll(backup); err != nil {
				return err
			}
		}
		if err := os.Rename(op.destSrc, backup); err != nil {
			return err
		}
		if err := os.Rename(stagedSrc, op.destSrc); err != nil {
			_ = os.Rename(backup, op.destSrc) // restore the old tree
			return err
		}
		_ = os.RemoveAll(backup)
	} else {
		if err := os.Rename(stagedSrc, op.destSrc); err != nil {
			return err
		}
	}
	return nil
}

// addBaselineWriteMeta records the baseline's metadata (name, clock, source,
// license, fingerprint) as baseline.json inside the destination.
func (op *addBaselineOp) addBaselineWriteMeta(fp validation.Value) (validation.Value, error) {
	meta := validation.VObj(
		validation.KV{K: "name", V: validation.VStr(op.name)},
		validation.KV{K: "added_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "source_url", V: optStr(op.sourceURL)},
		validation.KV{K: "license", V: optStr(op.licenseID)},
		validation.KV{K: "fingerprint", V: fp},
		validation.KV{K: "fingerprint_sha256", V: validation.VStr(FingerprintSha256(fp))},
	)
	if err := validation.WriteJson(filepath.Join(op.destRoot, "baseline.json"),
		meta, ""); err != nil {
		return validation.VNull(), err
	}
	return meta, nil
}

// addBaselineUpdateManifest appends the name to the manifest's baselines
// list (idempotently) and stamps the manifest's updated_at.
func (op *addBaselineOp) addBaselineUpdateManifest() error {
	man, err := loadManifest()
	if err != nil {
		return err
	}
	names := strs(man, "baselines")
	found := false
	for _, n := range names {
		if n == op.name {
			found = true
		}
	}
	if !found {
		names = append(names, op.name)
	}
	man = setKey(man, "baselines", validation.StrArr(names))
	man = setKey(man, "updated_at", validation.VStr(state.NowIso()))
	return validation.WriteJson(manifestPath(), man, "")
}

func optStr(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

// setKey replaces or appends a key, preserving the original key order.
func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	out := make([]validation.KV, 0, len(v.O)+1)
	replaced := false
	for _, kv := range v.O {
		if kv.K == key {
			out = append(out, validation.KV{K: key, V: val})
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, validation.KV{K: key, V: val})
	}
	return validation.VObj(out...)
}

// isAncestor reports whether a is an ancestor directory of b (Python's
// `a in b.parents`).
func isAncestor(a, b string) bool {
	for p := filepath.Dir(b); ; p = filepath.Dir(p) {
		if p == a {
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
	}
}

// copyTree is shutil.copytree with symlinks=False: directories are
// recreated, file symlinks are followed and their contents copied.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, ierr := os.Stat(path)
		if ierr != nil {
			return ierr
		}
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, oerr := os.Open(path)
		if oerr != nil {
			return oerr
		}
		defer in.Close()
		out, cerr := os.Create(target)
		if cerr != nil {
			return cerr
		}
		if _, werr := io.Copy(out, in); werr != nil {
			out.Close()
			return werr
		}
		if cerr := out.Close(); cerr != nil {
			return cerr
		}
		return os.Chmod(target, info.Mode().Perm())
	})
}

// ListBaselines is list_baselines: registered baselines, sorted by name.
func ListBaselines() ([]validation.Value, error) {
	man, err := loadManifest()
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, name := range strs(man, "baselines") {
		p := filepath.Join(BaselinesDir, name, "baseline.json")
		if _, err := os.Stat(p); err != nil {
			continue
		}
		m, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return validation.ObjStr(out[i], "name") < validation.ObjStr(out[j], "name")
	})
	return out, nil
}

// RemoveBaseline is remove_baseline.
func RemoveBaseline(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	root := filepath.Join(BaselinesDir, name)
	if _, err := os.Stat(root); err == nil {
		if err := os.RemoveAll(root); err != nil {
			return err
		}
	}
	man, err := loadManifest()
	if err != nil {
		return err
	}
	kept := []string{}
	for _, n := range strs(man, "baselines") {
		if n != name {
			kept = append(kept, n)
		}
	}
	man = setKey(man, "baselines", validation.StrArr(kept))
	man = setKey(man, "updated_at", validation.VStr(state.NowIso()))
	return validation.WriteJson(manifestPath(), man, "")
}
