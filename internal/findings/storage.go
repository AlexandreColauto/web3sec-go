// storage.go: finding_path / save_finding / load_finding /
// load_all_findings / load_live_findings / new_finding_id (webv2.findings).
package findings

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// FindingPath is finding_path: <findings_dir>/<finding_id>.json.
func FindingPath(campaign *state.Campaign, findingID string) string {
	return filepath.Join(campaign.FindingsDir, findingID+".json")
}

// SaveFinding is save_finding: stamp updated_at on the finding, validate it
// against the finding schema, and write it. The caller's Value is mutated in
// place (Python mutates the dict it was handed).
func SaveFinding(campaign *state.Campaign, finding *validation.Value) error {
	finding.O = validation.SetOrAppend(finding.O, "updated_at", validation.VStr(state.NowIso()))
	if err := validation.Validate(*finding, "finding", 1); err != nil {
		return err
	}
	id := validation.ObjStr(*finding, "finding_id")
	if id == "" {
		// Python's finding["finding_id"] raises KeyError("finding_id").
		return fmt.Errorf("'finding_id'")
	}
	return validation.WriteJson(FindingPath(campaign, id), *finding, "")
}

// LoadFinding is load_finding: the stored finding, or the FileNotFoundError
// Python raises (message text included).
func LoadFinding(campaign *state.Campaign, findingID string) (validation.Value, error) {
	p := FindingPath(campaign, findingID)
	if _, err := os.Stat(p); err != nil {
		return validation.VNull(), fmt.Errorf("no finding %s in %s",
			validation.PyReprStr(findingID), campaign.CampaignID)
	}
	return validation.ReadJson(p)
}

// LoadAllFindings is load_all_findings: all findings ordered by
// (created_at, finding_id) — deterministic regardless of the random-UUID
// filenames (the dedup processing-order contract; filename glob order is
// random per run).
//
// r43a: a findings/ directory that does not exist is an empty campaign (the
// Optional form), but a findings/ directory that CANNOT be listed is a
// refusal naming the path. Every proof clause of the form "every CONFIRMED
// finding needs X" passes vacuously on an empty list, so answering "no
// findings" for an unreadable store certified stages that were never proven.
func LoadAllFindings(campaign *state.Campaign) ([]validation.Value, error) {
	matches, err := validation.ListPrefixedOptional(campaign.FindingsDir,
		"F-", ".json")
	if err != nil {
		return nil, fmt.Errorf("the findings store %s cannot be listed: %v",
			campaign.FindingsDir, err)
	}
	out := make([]validation.Value, 0, len(matches))
	for _, p := range matches {
		v, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := validation.ObjStr(out[i], "created_at"), validation.ObjStr(out[j], "created_at")
		if ci != cj {
			return ci < cj
		}
		return validation.ObjStr(out[i], "finding_id") < validation.ObjStr(out[j], "finding_id")
	})
	return out, nil
}

// LoadLiveFindings is load_live_findings: all findings not in a terminal
// junk state (dedup, scope, superseded). The asymmetry against IsTerminal
// is the twin's, ported deliberately: DISPROVED and INFORMATIONAL rows
// stay "live" for triage and evalscore because they are NEGATIVE
// EXAMPLES the pipeline must keep seeing (a disproved claim is a scored
// answer; a superseded or merged one is bookkeeping noise). Not a drift
// bug — r12 audit concluded "unexplained"; this is the explanation.
func LoadLiveFindings(campaign *state.Campaign) ([]validation.Value, error) {
	all, err := LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	out := make([]validation.Value, 0, len(all))
	for _, f := range all {
		if s := validation.ObjStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" ||
			s == "SUPERSEDED" {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// NewFindingID is new_finding_id: "F-" + the first 12 hex chars of a fresh
// uuid4. Python mints this from raw uuid.uuid4(), NOT state.new_id, so the
// WEBV2_UUID golden pin does not apply — in either twin.
func NewFindingID() string {
	return findingIDSource()
}

// findingIDSource is the id minter. The golden suite installs a
// deterministic one (WEBV2_FINDING_IDS=pin + WEBV2_FINDING_ID_SEQ) so a
// replayed recipe mints the same ids across processes; production mints a
// raw uuid4.
var findingIDSource = newRandomFindingID

// SetFindingIDSource installs a finding-id minter; nil restores uuid4.
func SetFindingIDSource(f func() string) {
	if f == nil {
		f = newRandomFindingID
	}
	findingIDSource = f
}

func newRandomFindingID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: crypto/rand failure is unrecoverable, there is no caller to return to
		panic("findings: uuid4: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return "F-" + hex.EncodeToString(b)[:12]
}

// PinnedFindingID and ResetPinnedFindingIDs are the golden suite's
// deterministic id stream: F-<sha256("task13-finding:<n>")[:12]>. Replaying
// the recipe reproduces every id, so the id-dependent orderings (findings are
// sorted by file name) coincide run to run.
var pinnedFindingCounter int

// ResetPinnedFindingIDs rewinds the pinned finding-id stream.
func ResetPinnedFindingIDs() { pinnedFindingCounter = 0 }

// PinnedFindingID mints the next deterministic finding id.
func PinnedFindingID() string {
	h := sha256.Sum256([]byte("task13-finding:" +
		strconv.Itoa(pinnedFindingCounter)))
	pinnedFindingCounter++
	return "F-" + hex.EncodeToString(h[:])[:12]
}

// SaveThenLog is the findings-package sibling of the state package's
// unwind law (r17): a finding file written while its ledger event was
// refused is a projection lie — for TERMINAL statuses (DISPROVED,
// DUPLICATE) it is worse than a lie, it is a one-way door (the
// transition table refuses to reopen what the log never recorded).
// Callers capture the pre-save bytes through this helper; on log
// refusal the FILE is restored before the error returns.
func SaveThenLog(campaign *state.Campaign, finding *validation.Value,
	log func() error) error {
	id := validation.ObjStr(*finding, "finding_id")
	path := FindingPath(campaign, id)
	prevRaw, hadRaw, perr := prevBytes(path)
	if perr != nil && !os.IsNotExist(perr) {
		return perr
	}
	if err := SaveFinding(campaign, finding); err != nil {
		return err
	}
	if err := log(); err != nil {
		if rerr := restoreBytes(path, prevRaw, hadRaw); rerr != nil {
			// r18 P2: a FAILED restore means the finding bytes are still
			// AHEAD of the refused event — the exact half-land this
			// helper exists to prevent. Returning only the ledger error
			// laundered that fact; name both failures so no caller can
			// report a clean unwind that never happened.
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — the finding "+
				"file may hold post-write bytes with no event; repair "+
				"by hand before continuing)", err, rerr)
		}
		return err
	}
	return nil
}

func prevBytes(path string) ([]byte, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func restoreBytes(path string, raw []byte, had bool) error {
	if !had {
		return os.Remove(path)
	}
	return os.WriteFile(path, raw, 0o644)
}

// SaveThenLogMany generalizes SaveThenLog to a SET of findings that must
// land atomically with one event (dedup.candidate_resolved stamps BOTH
// sides then logs once: a refused event with one side stamped and the
// other not is a verdict half-written across two files). Same law:
// capture every file's bytes first; one failed restore names the whole
// failure, none is silent.
func SaveThenLogMany(campaign *state.Campaign, findingsList []*validation.Value,
	log func() error) error {
	type snap struct {
		path      string
		raw       []byte
		had       bool
		findingID string
	}
	snaps := make([]snap, 0, len(findingsList))
	for _, f := range findingsList {
		id := validation.ObjStr(*f, "finding_id")
		path := FindingPath(campaign, id)
		raw, had, perr := prevBytes(path)
		if perr != nil && !os.IsNotExist(perr) {
			return perr
		}
		snaps = append(snaps, snap{path: path, raw: raw, had: had, findingID: id})
	}
	for i, f := range findingsList {
		if err := SaveFinding(campaign, f); err != nil {
			for j := 0; j < i; j++ {
				_ = restoreBytes(snaps[j].path, snaps[j].raw, snaps[j].had)
			}
			return err
		}
	}
	if err := log(); err != nil {
		var failed []string
		for _, s := range snaps {
			if rerr := restoreBytes(s.path, s.raw, s.had); rerr != nil {
				failed = append(failed, s.findingID)
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("%w (UNWIND INCOMPLETE: %v still hold "+
				"post-write bytes with no event — repair by hand)", err,
				strings.Join(failed, ", "))
		}
		return err
	}
	return nil
}
