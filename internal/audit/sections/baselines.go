// Section 10: baselines — reference trees are content-addressed at add time;
// a baseline whose src/ drifted from its recorded fingerprint is a broken
// comparison basis (or a tampered reference). Manifest and disk must agree
// in both directions. REPORTED, not raised: this section audits the
// baselines, so a malformed manifest or an unreadable baseline becomes a
// problem entry, never a crash (every other section degrades the same way).
//
// The baseline directory and the T0-parser fingerprint belong to
// forkdiff.py (not ported yet), so both arrive through the ForkdiffAPI
// seam. fingerprint_sha256 itself is pure (canonical JSON + sha256) and is
// implemented here; only fingerprint_tree (the parser) is deferred. The
// default seam reports no baseline directory at all, which is byte-identical
// to the live Python twin (its repo baselines/ holds an empty manifest).
package sections

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

// ForkdiffAPI is the forkdiff seam: BASELINES_DIR and fingerprint_tree.
type ForkdiffAPI interface {
	// BaselinesDir is FD.BASELINES_DIR ("" = no such directory).
	BaselinesDir(c *state.Campaign) string
	// FingerprintTree is FD.fingerprint_tree(root): the content-addressable
	// shape of a source tree, from the T0 parser.
	FingerprintTree(root string) (validation.Value, error)
}

// noForkdiff is the absent-module default: no baselines dir, so the section
// is {checked: 0, problems: [], ok: true} exactly as Python reports for a
// repository whose baselines/ carries no registered baseline.
type noForkdiff struct{}

// BaselinesDir is "no baselines directory configured".
func (noForkdiff) BaselinesDir(*state.Campaign) string { return "" }

// FingerprintTree is unreachable through the default (no dir = no loop);
// it reports the missing module rather than pretending a tree is empty.
func (noForkdiff) FingerprintTree(string) (validation.Value, error) {
	return validation.VNull(), fmt.Errorf(
		"forkdiff.fingerprint_tree is not ported")
}

var forkdiffImpl ForkdiffAPI = noForkdiff{}

// SetForkdiff installs the forkdiff seam; nil restores the default (no
// baselines directory).
func SetForkdiff(f ForkdiffAPI) {
	if f == nil {
		f = noForkdiff{}
	}
	forkdiffImpl = f
}

// Baselines is audit.py section 10: {checked, problems, ok}.
func Baselines(c *state.Campaign) (validation.Value, error) {
	var problems []validation.Value
	var onDisk map[string]struct{}
	if err := baselinesInto(c, &problems, &onDisk); err != nil {
		// Python's belt-and-braces `except Exception`: the audit must not
		// crash, so the failure becomes one more problem entry.
		problems = append(problems, validation.VStr(
			"baselines section failed: "+err.Error()))
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(onDisk)))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}

// baselinesInto is the try block of section 10. A returned error is
// Python's outer `except Exception`; per-baseline failures are problems.
func baselinesInto(c *state.Campaign, problems *[]validation.Value,
	onDisk *map[string]struct{}) error {
	bdir := forkdiffImpl.BaselinesDir(c)
	if bdir == "" {
		return nil // Python's `if bdir.exists():` guard
	}
	if st, err := os.Stat(bdir); err != nil || !st.IsDir() {
		return nil
	}
	listed := baselinesManifest(filepath.Join(bdir, "manifest.json"), problems)
	disk, err := baselinesOnDisk(bdir)
	if err != nil {
		return err
	}
	*onDisk = disk
	for _, name := range sortedSetDiff(listed, disk) {
		*problems = append(*problems, validation.VStr(fmt.Sprintf(
			"manifest lists baseline %s but it is not on disk",
			validation.PyReprStr(name))))
	}
	for _, name := range sortedSetDiff(disk, listed) {
		*problems = append(*problems, validation.VStr(fmt.Sprintf(
			"baseline %s is on disk but missing from the manifest",
			validation.PyReprStr(name))))
	}
	return baselinesFingerprints(bdir, sortedIntersect(disk, listed), problems)
}

// baselinesManifest reads manifest.json (Python's inner try/except): an
// unreadable file and a malformed 'baselines' list are both problems, and
// either way the listed set is empty.
func baselinesManifest(manPath string, problems *[]validation.Value) map[string]struct{} {
	if _, err := os.Stat(manPath); err != nil {
		return map[string]struct{}{}
	}
	man, err := validation.ReadJson(manPath)
	if err != nil {
		*problems = append(*problems, validation.VStr(fmt.Sprintf(
			"baseline manifest unreadable (%s): %s",
			filepath.Base(manPath), err.Error())))
		return map[string]struct{}{}
	}
	raw := validation.VArr()
	if man.Kind == validation.Obj {
		if hasObjKey(man, "baselines") {
			raw = objAt(man, "baselines")
		}
	}
	malformed := raw.Kind != validation.Arr
	for _, item := range raw.A {
		if item.Kind != validation.Str {
			malformed = true
		}
	}
	if malformed {
		*problems = append(*problems, validation.VStr(
			"baseline manifest malformed: 'baselines' is not a list of "+
				"names — treating it as empty"))
		return map[string]struct{}{}
	}
	out := map[string]struct{}{}
	for _, item := range raw.A {
		out[item.S] = struct{}{}
	}
	return out
}

// baselinesOnDisk is Python's on_disk set: child dirs that carry a
// baseline.json.
func baselinesOnDisk(bdir string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(bdir)
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	for _, e := range entries {
		dir := filepath.Join(bdir, e.Name())
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "baseline.json")); err == nil {
			out[e.Name()] = struct{}{}
		}
	}
	return out, nil
}

// baselinesFingerprints re-derives each registered baseline's fingerprint
// and compares it to the manifest's recorded hash.
func baselinesFingerprints(bdir string, names []string,
	problems *[]validation.Value) error {
	for _, name := range names {
		dir := filepath.Join(bdir, name)
		meta, rerr := validation.ReadJson(filepath.Join(dir, "baseline.json"))
		var actual string
		if rerr == nil {
			fp, ferr := forkdiffImpl.FingerprintTree(filepath.Join(dir, "src"))
			if ferr != nil {
				rerr = ferr
			} else {
				actual = fingerprintSha256(fp)
			}
		}
		if rerr != nil {
			*problems = append(*problems, validation.VStr(fmt.Sprintf(
				"baseline %s: unreadable (%s)",
				validation.PyReprStr(name), rerr.Error())))
			continue
		}
		if meta.Kind != validation.Obj {
			// Python: meta.get(...) raises AttributeError, which the outer
			// except turns into "baselines section failed: ...".
			return fmt.Errorf("'%s' object has no attribute 'get'", pyTypeName(meta))
		}
		stored := objAt(meta, "fingerprint_sha256")
		if stored.Kind != validation.Str || stored.S != actual {
			*problems = append(*problems, validation.VStr(fmt.Sprintf(
				"baseline %s: fingerprint mismatch (stored %s..., actual "+
					"%s...) — the reference tree changed after registration",
				validation.PyReprStr(name), trunc12(pyStrValue(stored)),
				trunc12(actual))))
		}
	}
	return nil
}

// fingerprintSha256 is FD.fingerprint_sha256:
// sha256(json.dumps(fp, sort_keys=True, separators=(",", ":"))).
func fingerprintSha256(fp validation.Value) string {
	return validation.Sha256Hex([]byte(validation.CanonCompact(fp)))
}

// hasObjKey is Python `"key" in dict`.
func hasObjKey(v validation.Value, key string) bool {
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}

// sortedSetDiff is Python sorted(a - b).
func sortedSetDiff(a, b map[string]struct{}) []string {
	out := make([]string, 0, len(a))
	for k := range a {
		if _, in := b[k]; !in {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// sortedIntersect is Python sorted(a & b).
func sortedIntersect(a, b map[string]struct{}) []string {
	out := make([]string, 0, len(a))
	for k := range a {
		if _, in := b[k]; in {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
