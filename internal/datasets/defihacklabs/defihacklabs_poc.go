package defihacklabs

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/validation"
)

// PocIndex is build_poc_index's return: the exact repo-relative posix paths,
// a lowercased-path lookup (the clone lives on a case-sensitive filesystem but
// the explorer metadata has case drift, recon §10.3), and a normalized-stem
// index over *_exp.sol files only (helper files like interface.sol must never
// match an incident name).
type PocIndex struct {
	Files map[string]bool
	Lower map[string]string
	Stems map[string][]string
}

// BuildPocIndex is build_poc_index.
func BuildPocIndex(pocRoot string) PocIndex {
	root := pocRoot
	testDir := filepath.Join(root, "src", "test")
	idx := PocIndex{Files: map[string]bool{}, Lower: map[string]string{},
		Stems: map[string][]string{}}
	var rels []string
	if isDir(testDir) {
		_ = filepath.WalkDir(testDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".sol") {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return nil
			}
			rels = append(rels, filepath.ToSlash(rel))
			return nil
		})
	}
	sort.Slice(rels, func(i, j int) bool { return lessPathParts(rels[i], rels[j]) })
	for _, p := range rels {
		idx.Files[p] = true
	}
	for _, p := range rels {
		idx.Lower[strings.ToLower(p)] = p
	}
	for _, p := range rels {
		base := p
		if i := strings.LastIndex(p, "/"); i >= 0 {
			base = p[i+1:]
		}
		if !strings.HasSuffix(base, ".sol") {
			continue
		}
		stem := base[:len(base)-len(".sol")]
		if !strings.HasSuffix(strings.ToLower(stem), "_exp") {
			continue
		}
		stem = stem[:len(stem)-len("_exp")]
		key := NormalizeName(validation.VStr(stem))
		idx.Stems[key] = append(idx.Stems[key], p)
	}
	return idx
}

// lessPathParts is Python's Path ordering: compare the tuple of path parts
// (never the joined string — "2024-03/x" sorts before "2024-03-01/y" as
// parts, the opposite of the string order).
func lessPathParts(a, b string) bool {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}

// contractVariants is _contract_variants: candidate repo-relative paths for a
// Contract field value, covering the observed drift (recon §10.3): a leading
// /, a missing _exp suffix (EverValueCoin), a wrong .sol name
// (Gangsterfinance.sol vs Gangsterfinance_exp.sol). Order is most-literal
// first so an exact hit always wins over a repaired one.
func contractVariants(contract string) []string {
	raw := strings.TrimLeft(pyStrip(contract), "/")
	if raw == "" {
		return nil
	}
	out := []string{raw}
	if !strings.HasSuffix(raw, ".sol") {
		raw += ".sol"
		out = append(out, raw)
	}
	stem := raw[:len(raw)-len(".sol")]
	if !strings.HasSuffix(strings.ToLower(stem), "_exp") {
		out = append(out, stem+"_exp.sol")
	}
	return out
}

// ResolvePoc is resolve_poc: resolve one incident to its PoC repo-relative
// path (or nil). Priority (recon §2): the Contract field (with drift-tolerant
// variants, exact then case-insensitive), the RCA pocLink path, then the
// normalized-name stem fallback. The first hit wins; ties in the stem index
// resolve to the sorted-first path.
func ResolvePoc(incident validation.Value, rca *validation.Value, idx PocIndex) *string {
	for _, candidate := range contractVariants(pyStrOrEmpty(at(incident, "Contract"))) {
		if idx.Files[candidate] {
			c := candidate
			return &c
		}
		if hit, ok := idx.Lower[strings.ToLower(candidate)]; ok {
			h := hit
			return &h
		}
	}
	if rca != nil {
		_, linkPath, _ := ExtractPocLink(at(*rca, "pocLink"))
		if linkPath != nil && *linkPath != "" {
			if idx.Files[*linkPath] {
				return linkPath
			}
			if hit, ok := idx.Lower[strings.ToLower(*linkPath)]; ok {
				h := hit
				return &h
			}
		}
	}
	matches := idx.Stems[NormalizeName(at(incident, "name"))]
	if len(matches) > 0 {
		sorted := append([]string{}, matches...)
		sort.Strings(sorted)
		m := sorted[0]
		return &m
	}
	return nil
}

// FindRCA is find_rca: join an incident name to its RCA record by normalized
// name. The 29 normalized-key collision groups (Paribus/Paribus_, ...) resolve
// deterministically to the FIRST key in file order (documented choice — either
// record describes the same protocol's exploit family). nil when nothing
// matches (154 incidents).
func FindRCA(name validation.Value, rcaData validation.Value) *validation.Value {
	target := NormalizeName(name)
	if target == "" {
		return nil
	}
	if rcaData.Kind != validation.Obj {
		return nil
	}
	for _, p := range rcaData.O {
		if p.V.Kind != validation.Obj {
			continue
		}
		if NormalizeName(validation.VStr(p.K)) == target {
			v := p.V
			return &v
		}
	}
	return nil
}
