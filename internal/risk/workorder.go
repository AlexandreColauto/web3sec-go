// workorder.go: work_order_key (webv2.risk) — the ONE deterministic
// work-order key shared by every finding work-list.
package risk

import (
	"sort"

	"websec/internal/validation"
)

// bandRank is _BAND_RANK: band severity order, worst first — the display
// vocabulary validated_risk already emits. A band outside the table sorts
// last.
var bandRank = map[string]int{
	"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0,
}

// WorkOrderKey is work_order_key's 4-tuple. Sort ascending and the work that
// matters most comes first:
//
//		(blast rank desc, unprivileged first, band desc, finding_id)
//
//	  - BlastRank is -_W_BLAST[blast], the same table and the same
//	    unknown-blast default (2.0) validated_risk uses;
//	  - Privileged is _privilege_class(finding) != "unprivileged", the
//	    campaign's existing privilege reading (False sorts first);
//	  - BandRank is -_BAND_RANK[band] from validated_risk, so an uncalibrated
//	    finding still ranks;
//	  - FindingID is the total, deterministic tiebreak: exact ties keep id
//	    order and two runs never disagree.
type WorkOrderKey struct {
	BlastRank  float64
	Privileged bool
	BandRank   int
	FindingID  string
}

// Less is Python's tuple ordering over the same four components.
func (k WorkOrderKey) Less(o WorkOrderKey) bool {
	if k.BlastRank != o.BlastRank {
		return k.BlastRank < o.BlastRank
	}
	if k.Privileged != o.Privileged {
		return !k.Privileged
	}
	if k.BandRank != o.BandRank {
		return k.BandRank < o.BandRank
	}
	return k.FindingID < o.FindingID
}

// WorkOrderKeyFor is work_order_key: zero new data — no field, threshold or
// taxonomy is invented here. Pure: reads recorded fields, writes nothing,
// calls no model.
func WorkOrderKeyFor(finding validation.Value) (WorkOrderKey, error) {
	impact := orObj(validation.ObjAt(finding, "economic_impact"))
	blast := blastRadius(impact)
	rank, ok := wBlast[blast]
	if !ok {
		rank = 2.0
	}
	validated, err := ValidatedRisk(finding)
	if err != nil {
		return WorkOrderKey{}, err
	}
	band := objStrOf(validated, "band")
	return WorkOrderKey{
		BlastRank:  -rank,
		Privileged: privilegeClass(finding) != "unprivileged",
		BandRank:   -bandRankOr(band, -1),
		FindingID:  orStr(validation.ObjAt(finding, "finding_id")),
	}, nil
}

// bandRankOr is _BAND_RANK.get(band, def).
func bandRankOr(band string, def int) int {
	if r, ok := bandRank[band]; ok {
		return r
	}
	return def
}

// SortByWorkOrder is `sorted(rows, key=work_order_key)` — stable, so exact
// ties keep their input order after the id tiebreak.
func SortByWorkOrder(rows []validation.Value) ([]validation.Value, error) {
	type keyed struct {
		key WorkOrderKey
		row validation.Value
	}
	ks := make([]keyed, 0, len(rows))
	for _, row := range rows {
		k, err := WorkOrderKeyFor(row)
		if err != nil {
			return nil, err
		}
		ks = append(ks, keyed{key: k, row: row})
	}
	sort.SliceStable(ks, func(i, j int) bool {
		return ks[i].key.Less(ks[j].key)
	})
	out := make([]validation.Value, 0, len(ks))
	for _, k := range ks {
		out = append(out, k.row)
	}
	return out, nil
}

// objStrOf is str(v[key]) when the member is a string, else "".
func objStrOf(v validation.Value, key string) string {
	if got, ok := fieldAt(v, key); ok && got.Kind == validation.Str {
		return got.S
	}
	return ""
}
