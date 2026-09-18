// Operator-supplied gold packs: load, validate row-by-row, and verify the sha256 sidecar.
package evalscore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"websec/internal/validation"
)

// GoldPack is an operator-supplied suite: an explicit file of
// evaluation_case rows, plus its sha256 sidecar when one sits next to it.
// It exists because a held-out answer key must never be embedded in the
// shipped binary (see the leakage partition rule): the operator loads the
// key at grading time, the tool verifies it, nothing persists.
//
// Digest is the sha256 of the RAW file bytes (never a re-serialisation:
// the sidecar describes the bytes on disk, and re-encoding the parsed JSON
// would hash something the operator never wrote). Verified is true only
// when a sidecar was found next to the pack and matched.
type GoldPack struct {
	Cases    []validation.Value
	Digest   string
	Verified bool
}

// LoadGoldPack reads and verifies an operator-supplied gold pack and
// returns its case rows. path == "" is the normal case — no pack, the
// embedded suite is the suite — and returns (nil, nil).
//
// Everything else is fail-loud, because this is grading, not scoring: a
// missing file, a file that is not a JSON array of objects, a row that
// fails evaluation_case validation (a mis-typed gold row must not quietly
// shrink the answer key — the error names the row's case_id), a duplicate
// case_id, and a mismatching sidecar all refuse. A pack with no sidecar is
// ACCEPTED and reported as unverified by the caller, which is a fact the
// operator must see in the provenance line.
func LoadGoldPack(path string) ([]validation.Value, error) {
	pack, err := OpenGoldPack(path)
	if err != nil {
		return nil, err
	}
	return pack.Cases, nil
}

// OpenGoldPack is LoadGoldPack plus the tamper-evidence facts the callers
// print (the digest, and whether a sidecar verified it). One read of the
// file: the hash the provenance line prints is the hash of the very bytes
// that were parsed.
func OpenGoldPack(path string) (GoldPack, error) {
	if path == "" {
		return GoldPack{}, nil
	}
	doc, digest, err := openGoldRead(path)
	if err != nil {
		return GoldPack{}, err
	}
	cases, err := openGoldCases(path, doc)
	if err != nil {
		return GoldPack{}, err
	}
	return openGoldVerifySidecar(path, digest, cases)
}

// openGoldRead reads the pack file, hashes the raw bytes and parses the
// document, refusing an unreadable file, invalid JSON and a non-array doc.
func openGoldRead(path string) (validation.Value, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return validation.Value{}, "", fmt.Errorf("gold pack %s is not readable: %v",
			path, err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.Value{}, "", fmt.Errorf("gold pack %s is not valid JSON: %v",
			path, err)
	}
	if doc.Kind != validation.Arr {
		return validation.Value{}, "", fmt.Errorf(
			"gold pack %s must be a JSON array of evaluation_case objects, "+
				"found %s", path, jsonKindName(doc))
	}
	return doc, digest, nil
}

// openGoldCases validates the parsed pack's rows in order and returns the
// case rows, refusing duplicate case_ids and duplicate anchors.
func openGoldCases(path string, doc validation.Value) ([]validation.Value, error) {
	cases := make([]validation.Value, 0, len(doc.A))
	seen := map[string]bool{}
	anchors := map[string]string{}
	for i, row := range doc.A {
		if err := openGoldCheckRow(path, row, i); err != nil {
			return nil, err
		}
		cid := field(row, "case_id")
		if seen[cid] {
			return nil, fmt.Errorf(
				"gold pack %s: duplicate case_id %s — a case id names one "+
					"gold row", path, cid)
		}
		seen[cid] = true
		// r6 (critic issue 3): the same ANCHOR under two ids is answer-key
		// duplication — one real finding satisfies both, GoldTotal grows
		// without the suite learning anything new, and the Wilson
		// confidence widens off a phantom second sample. Refuse it the way
		// duplicate case_ids are refused; the anchor's canonical form is
		// bug_class + sorted location basenames + outcome + mechanisms.
		key := anchorKey(row)
		if prev, dup := anchors[key]; dup {
			return nil, fmt.Errorf(
				"gold pack %s: cases %s and %s have the same gold anchor "+
					"(bug_class, locations, outcome, mechanisms) — one "+
					"finding would satisfy both and inflate the answer key; "+
					"merge them", path, prev, cid)
		}
		anchors[key] = cid
		cases = append(cases, row)
	}
	return cases, nil
}

// openGoldCheckRow refuses one pack row that is not a well-formed
// evaluation_case: a non-object, a row failing evaluation_case validation,
// and a control row carrying match_mechanisms.
func openGoldCheckRow(path string, row validation.Value, i int) error {
	if row.Kind != validation.Obj {
		return fmt.Errorf(
			"gold pack %s row %d must be a JSON object, found %s",
			path, i, jsonKindName(row))
	}
	if err := validation.Validate(row, "evaluation_case", 1); err != nil {
		cid := field(row, "case_id")
		if cid == "" {
			cid = fmt.Sprintf("(row %d)", i)
		}
		return fmt.Errorf(
			"gold pack %s: case %s fails evaluation_case validation: %v",
			path, cid, err)
	}
	// R2-5 (critic): the mechanism leg runs only on NON-control anchors
	// (a control case is a program's ABSENCE check — nothing to anchor
	// a phrase against). A control row carrying match_mechanisms is
	// dead authoring: refused at load so an author believes the gate
	// bites when it cannot.
	if field(obj(row, "gold"), "outcome") == notExploitable &&
		obj(row, "gold").Kind == validation.Obj &&
		obj(obj(row, "gold"), "match_mechanisms").Kind != validation.Null {
		return fmt.Errorf(
			"gold pack %s: case %s is a control (outcome %s) and "+
				"carries match_mechanisms — the mechanism leg never runs "+
				"for control cases; drop the phrases or the outcome",
			path, field(row, "case_id"), notExploitable)
	}
	return nil
}

// openGoldVerifySidecar checks the pack's tamper-evidence sidecar, when one
// exists, and reports the pack with its digest (Verified only on a match).
func openGoldVerifySidecar(path, digest string, cases []validation.Value) (GoldPack, error) {
	sidecar, ok := goldPackSidecar(path)
	if !ok {
		return GoldPack{Cases: cases, Digest: digest}, nil
	}
	sraw, err := os.ReadFile(sidecar)
	if err != nil {
		return GoldPack{}, fmt.Errorf("gold pack sidecar %s is not readable: %v",
			sidecar, err)
	}
	// The sidecar is one hex line, or a `sha256sum`-style "<hex>  <name>"
	// line (the real pack's sidecar is the two-token form): the FIRST
	// whitespace-separated token is the digest either way.
	want := ""
	if f := strings.Fields(string(sraw)); len(f) > 0 {
		want = f[0]
	}
	if !strings.EqualFold(want, digest) {
		return GoldPack{}, fmt.Errorf(
			"gold pack %s does not match its sidecar %s: sidecar sha256 %s, "+
				"file sha256 %s", path, sidecar, want, digest)
	}
	return GoldPack{Cases: cases, Digest: digest, Verified: true}, nil
}

// goldPackSidecar finds the pack's tamper-evidence sidecar, or reports that
// there is none. The store convention (evalstore.SidecarName) is the stem
// with .json replaced by .sha256 — cases.json -> cases.sha256 — so the
// candidates are the same name beside the pack, the literal `<path>.sha256`,
// and the store's own <dir>/cases.sha256.
func goldPackSidecar(path string) (string, bool) {
	candidates := []string{path + ".sha256"}
	if ext := filepath.Ext(path); ext != "" {
		candidates = append(candidates, strings.TrimSuffix(path, ext)+".sha256")
	}
	candidates = append(candidates, filepath.Join(filepath.Dir(path), "cases.sha256"))
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, true
		}
	}
	return "", false
}
