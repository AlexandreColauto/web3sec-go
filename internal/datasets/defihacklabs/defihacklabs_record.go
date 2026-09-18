package defihacklabs

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strconv"

	"websec/internal/validation"
)

// BuildRecord is build_record: one common-shape record (pinned mapping, brief
// §Task 4). recordID comes from AssignIDs (collision-aware slug); rca from
// FindRCA; pocPath from ResolvePoc. Pinned points: url is pocLink > blob/main
// URL > None (no README-anchor fallback — the pin lists exactly three levels);
// program from name/chain; bug_class_label is the raw incident type (the
// taxonomy map's input, never pre-mapped); outcome confirmed-exploitable;
// severity None (Lost is a magnitude, not a severity); prior=True (real
// executed exploits are capability priors) with the atomic-label pattern;
// partition is set later by AssignPartitions (build_record stamps "dev" as the
// pre-partition placeholder).
func BuildRecord(incident validation.Value, recordID string, rca *validation.Value,
	pocPath *string) validation.Value {
	name := pyStrOrEmpty(at(incident, "name"))
	if name == "" {
		name = "Unknown protocol"
	}
	inctype := pyStrOrEmpty(at(incident, "type"))
	if inctype == "" {
		inctype = "Unknown"
	}
	date := pyStrOrEmpty(at(incident, "date"))
	platform := NormalizeChain(at(incident, "chain"))
	chainDisplay := "Unknown chain"
	if platform != nil {
		chainDisplay = *platform
	}
	var linkURL, linkCommit *string
	if rca != nil {
		linkURL, _, linkCommit = ExtractPocLink(at(*rca, "pocLink"))
	}
	url := validation.VNull()
	if linkURL != nil {
		url = validation.VStr(*linkURL)
	} else if pocPath != nil {
		url = validation.VStr(RepoURL + "/blob/main/" + *pocPath)
	}
	commit := CloneHead
	if linkCommit != nil {
		commit = *linkCommit
	}
	technique := inctype
	if rca != nil {
		if t := pyStrip(pyStrOrEmpty(at(*rca, "type"))); t != "" {
			technique = t
		}
	}
	title := recordTitle(name, inctype, chainDisplay, date, recordID)
	locations, codeFiles, exploitPath := pocPointers(pocPath)
	return validation.VObj(
		validation.KV{K: "id", V: validation.VStr(recordID)},
		validation.KV{K: "dataset", V: validation.VStr(Dataset)},
		validation.KV{K: "url", V: url},
		validation.KV{K: "program", V: recordProgram(name, platform)},
		validation.KV{K: "title", V: validation.VStr(title)},
		validation.KV{K: "description", V: validation.VStr(
			ComposeDescription(incident, rca))},
		validation.KV{K: "bug_class_label", V: validation.VStr(inctype)},
		validation.KV{K: "outcome", V: validation.VStr("confirmed-exploitable")},
		validation.KV{K: "severity", V: validation.VNull()},
		validation.KV{K: "negative", V: validation.VBool(false)},
		validation.KV{K: "prior", V: validation.VBool(true)},
		validation.KV{K: "pattern", V: validation.VStr(
			ComposePattern(incident, rca))},
		validation.KV{K: "root_cause", V: validation.VStr(
			ComposeRootCause(incident, rca))},
		validation.KV{K: "locations", V: locations},
		validation.KV{K: "code", V: validation.VObj(
			validation.KV{K: "repo", V: validation.VStr(RepoURL)},
			validation.KV{K: "commit", V: validation.VStr(commit)},
			validation.KV{K: "files", V: codeFiles})},
		validation.KV{K: "exploit", V: validation.VObj(
			validation.KV{K: "poc_path", V: exploitPath},
			validation.KV{K: "technique", V: validation.VStr(technique)})},
		validation.KV{K: "partition", V: validation.VStr("dev")},
	)
}

// recordTitle is build_record's title: "<name> - <type> (<chain>, <date>)"
// clipped to 500, padded to 5 with the record id.
func recordTitle(name, inctype, chainDisplay, date, recordID string) string {
	title := ClipText(fmt.Sprintf("%s - %s (%s, %s)", name, inctype,
		chainDisplay, date), 500)
	for runeLen(title) < 5 {
		title += " " + recordID
	}
	return title
}

// recordProgram is build_record's program block: platform/chains carry the
// normalized chain only when one is known.
func recordProgram(name string, platform *string) validation.Value {
	program := validation.VObj(
		validation.KV{K: "program", V: validation.VStr(name)},
		validation.KV{K: "platform", V: validation.VNull()},
		validation.KV{K: "chains", V: validation.VArr()})
	if platform == nil {
		return program
	}
	program = setKey(program, "platform", validation.VStr(*platform))
	return setKey(program, "chains",
		validation.VArr(validation.VStr(*platform)))
}

// pocPointers is build_record's PoC-derived triple: locations, code.files,
// exploit.poc_path.
func pocPointers(pocPath *string) (validation.Value, validation.Value,
	validation.Value) {
	if pocPath == nil {
		return validation.VArr(), validation.VArr(), validation.VNull()
	}
	return validation.VArr(validation.VObj(
			validation.KV{K: "file", V: validation.VStr(*pocPath)})),
		validation.VArr(validation.VStr(*pocPath)),
		validation.VStr(*pocPath)
}

// AssignIDs is assign_ids: the stable defihacklabs-<date>-<norm-name> slugs.
// 26 collision groups share a base slug (recon §7: 44 normalized-name dupes).
// The brief pins +chain on collision; 21 groups are identical even with the
// chain (exact duplicate rows), so the rule extends deterministically: within a
// group, members sort by (type, Contract, chain, full JSON) — the first keeps
// the bare slug, the rest take <slug>-<norm-chain> ("unknown" for null chains),
// then -<norm-type>, then -2/-3… until unique. Pure function of the incident
// list (no wall clock, no disk).
func AssignIDs(incidents []validation.Value) []string {
	bases := make([]string, len(incidents))
	for i, inc := range incidents {
		bases[i] = "defihacklabs-" + validation.PyStr(at(inc, "date")) + "-" +
			NormalizeName(at(inc, "name"))
	}
	groups := map[string][]int{}
	var order []string
	for i, base := range bases {
		if _, ok := groups[base]; !ok {
			order = append(order, base)
		}
		groups[base] = append(groups[base], i)
	}
	sortKey := func(idx int) [4]string {
		inc := incidents[idx]
		return [4]string{
			pyStrOrEmpty(at(inc, "type")),
			pyStrOrEmpty(at(inc, "Contract")),
			pyStrOrEmpty(at(inc, "chain")),
			validation.Canon(inc, false),
		}
	}
	ids := make([]string, len(incidents))
	for _, base := range order {
		members := groups[base]
		if len(members) == 1 {
			ids[members[0]] = base
			continue
		}
		ordered := append([]int{}, members...)
		sort.SliceStable(ordered, func(i, j int) bool {
			a, b := sortKey(ordered[i]), sortKey(ordered[j])
			for k := 0; k < 4; k++ {
				if a[k] != b[k] {
					return a[k] < b[k]
				}
			}
			return false
		})
		used := map[string]bool{base: true}
		ids[ordered[0]] = base
		for _, idx := range ordered[1:] {
			inc := incidents[idx]
			chainPart := NormalizeName(at(inc, "chain"))
			if chainPart == "" {
				chainPart = "unknown"
			}
			candidate := base + "-" + chainPart
			if used[candidate] {
				typePart := NormalizeName(at(inc, "type"))
				if typePart == "" {
					typePart = "notype"
				}
				candidate = candidate + "-" + typePart
			}
			suffix := 2
			for used[candidate] {
				candidate = base + "-" + chainPart + "-" + strconv.Itoa(suffix)
				suffix++
			}
			used[candidate] = true
			ids[idx] = candidate
		}
	}
	return ids
}

// AssignPartitions is assign_partitions: stamp the leakage partition —
// date-ascending, recent ceil(30%) held-out. Pure function of (date, id)
// order — ties break on the unique record id, so the cut is deterministic even
// when many incidents share a date. Operates in place, returns records.
func AssignPartitions(records []validation.Value, dates []string) []validation.Value {
	total := len(records)
	heldOut := int(math.Ceil(float64(total) * HeldOutRatio))
	order := make([]int, total)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		i, j := order[a], order[b]
		if dates[i] != dates[j] {
			return dates[i] < dates[j]
		}
		return validation.PyStr(at(records[i], "id")) < validation.PyStr(at(records[j], "id"))
	})
	heldOutIdx := map[int]bool{}
	if heldOut > 0 {
		for _, idx := range order[total-heldOut:] {
			heldOutIdx[idx] = true
		}
	}
	for i := range records {
		part := "dev"
		if heldOutIdx[i] {
			part = "held-out"
		}
		records[i] = setKey(records[i], "partition", validation.VStr(part))
	}
	return records
}

// LoadRecords is load_records: load the explorer + PoC clones into
// common-shape records. Pure file reads (never writes to the clones). Returns
// a *CloneAbsentError when a clone is absent — integration tests skip on the
// directories, so the suite never requires the data. Returns one record per
// incident (930), file order, partitioned per AssignPartitions.
func LoadRecords(explorerDir, pocRoot *string) ([]validation.Value, error) {
	explorer := ExplorerDir
	if explorerDir != nil {
		explorer = *explorerDir
	}
	poc := PocRoot
	if pocRoot != nil {
		poc = *pocRoot
	}
	incidentsPath := filepath.Join(explorer, "incidents.json")
	rootcausePath := filepath.Join(explorer, "rootcause_data.json")
	if !isFile(incidentsPath) {
		return nil, &CloneAbsentError{Path: incidentsPath}
	}
	if !isFile(rootcausePath) {
		return nil, &CloneAbsentError{Path: rootcausePath}
	}
	incidents, err := validation.ReadJson(incidentsPath)
	if err != nil {
		return nil, err
	}
	rcaData, err := validation.ReadJson(rootcausePath)
	if err != nil {
		return nil, err
	}
	if incidents.Kind != validation.Arr {
		return nil, fmt.Errorf("%s must be a JSON array", incidentsPath)
	}
	if rcaData.Kind != validation.Obj {
		return nil, fmt.Errorf("%s must be a JSON object", rootcausePath)
	}
	index := BuildPocIndex(poc)
	recordIDs := AssignIDs(incidents.A)
	records := make([]validation.Value, 0, len(incidents.A))
	for i, incident := range incidents.A {
		rca := FindRCA(at(incident, "name"), rcaData)
		pocPath := ResolvePoc(incident, rca, index)
		records = append(records, BuildRecord(incident, recordIDs[i], rca, pocPath))
	}
	dates := make([]string, len(incidents.A))
	for i, inc := range incidents.A {
		dates[i] = pyStrOrEmpty(at(inc, "date"))
	}
	return AssignPartitions(records, dates), nil
}
