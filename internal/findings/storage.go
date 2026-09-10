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
	"time"

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
	finding.O = validation.SetOrAppend(finding.O, "updated_at", validation.VStr(nowIso()))
	if err := validation.Validate(*finding, "finding", 1); err != nil {
		return err
	}
	id := objStr(*finding, "finding_id")
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
func LoadAllFindings(campaign *state.Campaign) ([]validation.Value, error) {
	matches, err := filepath.Glob(filepath.Join(campaign.FindingsDir, "F-*.json"))
	if err != nil {
		return nil, err
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
		ci, cj := objStr(out[i], "created_at"), objStr(out[j], "created_at")
		if ci != cj {
			return ci < cj
		}
		return objStr(out[i], "finding_id") < objStr(out[j], "finding_id")
	})
	return out, nil
}

// LoadLiveFindings is load_live_findings: all findings not in a terminal
// junk state (dedup, scope).
func LoadLiveFindings(campaign *state.Campaign) ([]validation.Value, error) {
	all, err := LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	out := make([]validation.Value, 0, len(all))
	for _, f := range all {
		if s := objStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" {
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
		panic("findings: uuid4: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return "F-" + hex.EncodeToString(b)[:12]
}

// nowIso is now_iso (mirrors state.nowIso, unexported there). The WEBV2_NOW
// golden-suite clock pin is honored identically.
func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
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
