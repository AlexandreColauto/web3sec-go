// storage.go: finding_path / save_finding / load_finding /
// load_all_findings / load_live_findings / new_finding_id (webv2.findings).
package findings

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	finding.O = setOrAppend(finding.O, "updated_at", validation.VStr(nowIso()))
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

// setOrAppend mirrors Python dict assignment: an existing key is replaced in
// place (position kept), a new key is appended at the end.
func setOrAppend(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, validation.KV{K: key, V: v})
}
