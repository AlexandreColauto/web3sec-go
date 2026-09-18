package briefing

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"websec/internal/invariants"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- attention ledger (B4/D7) ----------------------------------------------

var isoInTextRe = regexp.MustCompile(
	`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?` +
		`(?:[+-]\d{2}:?\d{2}|Z)?`)

// FormatAge is format_age: compact, locale-free age.
func FormatAge(seconds float64) string {
	s := int64(seconds)
	if seconds < 0 {
		s = 0
	}
	switch {
	case s >= 86400:
		return fmt.Sprintf("%dd%dh", s/86400, (s%86400)/3600)
	case s >= 3600:
		return fmt.Sprintf("%dh%dm", s/3600, (s%3600)/60)
	case s >= 60:
		return fmt.Sprintf("%dm", s/60)
	}
	return fmt.Sprintf("%ds", s)
}

var isoLayouts = []string{
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05",
	"2006-01-02T15:04",
	"2006-01-02",
}

// ParseISO is _parse_iso: a tz-aware time from an ISO string, or nil. Naive
// stamps are read as UTC.
func ParseISO(ts string) *time.Time {
	if strings.TrimSpace(ts) == "" {
		return nil
	}
	s := strings.TrimSpace(ts)
	for _, layout := range isoLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			if t.Location() == time.UTC {
				return &t
			}
			u := t.UTC()
			return &u
		}
	}
	// Python's fromisoformat also accepts a trailing fractional part with
	// more than 9 digits and offsets without a colon; normalize both.
	if i := strings.IndexByte(s, '.'); i >= 0 {
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j-i-1 > 9 {
			s = s[:i+1+9] + s[j:]
		}
	}
	for _, layout := range isoLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			if t.Location() == time.UTC {
				return &t
			}
			u := t.UTC()
			return &u
		}
	}
	return nil
}

// age is _age: (seconds, rendered) or (nil, nil) when the stamp is unusable.
func age(now time.Time, ts string) (*int64, *string) {
	dt := ParseISO(ts)
	if dt == nil {
		return nil, nil
	}
	secs := int64(now.Sub(*dt).Seconds())
	if secs < 0 {
		secs = 0
	}
	txt := FormatAge(float64(secs))
	return &secs, &txt
}

// ageSortKey is _age_sort_key: oldest first; unknown sorts last.
func ageSortKey(secs *int64) int64 {
	if secs == nil {
		return 1
	}
	return -*secs
}

// firstStamp is _first_stamp: the first parseable candidate.
func firstStamp(candidates ...string) *string {
	for _, ts := range candidates {
		if ParseISO(ts) != nil {
			out := ts
			return &out
		}
	}
	return nil
}

func invariantsRankKey(item validation.Value) (bool, int64, string) {
	return !pyTruthyInt64Only(validation.ObjAt(item, "high_consequence")),
		ageSortKey(intPtr(validation.ObjAt(item, "age_seconds"))),
		validation.ObjStr(item, "invariant_id")
}

func leadRankKey(item validation.Value) (int, int64, string) {
	high := pyTruthyInt64Only(validation.ObjAt(item, "high_consequence"))
	kind := validation.ObjStr(item, "kind")
	cls := 2
	if kind == "queue" && high {
		cls = 0
	} else if kind == "invariant" && high {
		cls = 1
	}
	ident := validation.ObjStr(item, "priority_id")
	if ident == "" {
		ident = validation.ObjStr(item, "invariant_id")
	}
	if ident == "" {
		ident = "?"
	}
	return cls, ageSortKey(intPtr(validation.ObjAt(item, "age_seconds"))), ident
}

func entryTimestamp(entry validation.Value) *string {
	ts := validation.ObjStr(entry, "updated_at")
	if ParseISO(ts) != nil {
		out := ts
		return &out
	}
	m := isoInTextRe.FindString(validation.ObjStr(entry, "modified_by"))
	if m == "" {
		return nil
	}
	return &m
}

// priorityInvariant is _priority_invariant.
func priorityInvariant(priority, reg validation.Value) (string, *string, bool) {
	norm := map[string]validation.Value{}
	keys := map[string]string{}
	for _, e := range reg.O {
		if e.V.Kind != validation.Obj {
			continue
		}
		k := invariants.NormalizeInvID(e.K)
		norm[k] = e.V
		keys[k] = e.K
	}
	var bestRank *[2]any
	var bestKey string
	var bestSev *string
	bestHigh := false
	for _, raw := range listAt(priority, "invariant_ids") {
		if raw.Kind != validation.Str {
			continue
		}
		normID := invariants.NormalizeInvID(raw.S)
		key := raw.S
		entry := validation.VNull()
		if k, ok := keys[normID]; ok {
			key = k
			entry = norm[normID]
		}
		sevV := validation.ObjAt(entry, "severity_if_broken")
		var sev *string
		if sevV.Kind == validation.Str {
			s := sevV.S
			sev = &s
		}
		kind := validation.ObjStr(entry, "kind")
		high := (sev != nil && *sev == "critical") || kind == "liveness"
		rank := [2]any{!high, key}
		if bestRank == nil || rankLess(rank, *bestRank) {
			r := rank
			bestRank = &r
			bestKey = key
			bestSev = sev
			bestHigh = high
		}
	}
	if bestRank == nil {
		return "", nil, false
	}
	return bestKey, bestSev, bestHigh
}

func rankLess(a, b [2]any) bool {
	ab, bb := a[0].(bool), b[0].(bool)
	if ab != bb {
		return !ab
	}
	return a[1].(string) < b[1].(string)
}

func regOrEmpty(campaign *state.Campaign) validation.Value {
	links, err := invariants.LoadLinks(campaign)
	if err != nil {
		return validation.VObj()
	}
	reg := validation.ObjAt(links, "invariants")
	if reg.Kind != validation.Obj {
		return validation.VObj()
	}
	return reg
}

// AttentionLedger is attention_ledger: the queue/invariant debt ledger, aged
// against the brief's own generated_at.
func AttentionLedger(campaign *state.Campaign, now string,
	campaignID *string, closed bool) (validation.Value, error) {
	cid := campaign.CampaignID
	if campaignID != nil && *campaignID != "" {
		cid = *campaignID
	}
	nowDT := ParseISO(now)
	if nowDT == nil {
		t := time.Now().UTC()
		nowDT = &t
	}
	reg := regOrEmpty(campaign)
	queue := validation.VObj(
		kv("total", validation.VInt(0)), kv("worked", validation.VInt(0)),
		kv("untouched", validation.VInt(0)), kv("oldest", validation.VNull()),
		kv("line", validation.VNull()))
	invariantsBlock := validation.VObj(
		kv("total", validation.VInt(0)), kv("unverified", validation.VInt(0)),
		kv("high_consequence", validation.VInt(0)),
		kv("items", validation.VArr()), kv("line", validation.VNull()))
	ledger := validation.VObj(
		kv("as_of", validation.VStr(now)),
		kv("suppressed", validation.VNull()),
		kv("queue", queue), kv("invariants", invariantsBlock),
		kv("ranked", validation.VArr()), kv("lines", validation.VArr()))

	// -- queue debt
	ledgerQueueDebt(campaign, cid, nowDT, reg, &queue)

	// -- invariant debt
	items, err := ledgerInvariantDebt(campaign, cid, nowDT, reg, &invariantsBlock)
	if err != nil {
		return validation.VNull(), err
	}

	// -- the ordering list
	setKey(&ledger, "ranked", ledgerRanked(items, queue))

	// -- printable block
	setKey(&ledger, "lines", validation.StrArr(
		ledgerLines(queue, invariantsBlock, items)))

	if closed {
		suppressDebt(&ledger)
	}
	return ledger, nil
}

// ledgerQueueDebt fills the queue block from the plan's priorities: the
// untouched (not dispositioned) rows are counted, then the oldest one is
// minted.
func ledgerQueueDebt(campaign *state.Campaign, cid string, nowDT *time.Time,
	reg validation.Value, queue *validation.Value) {
	plan, planErr := planner.LoadPlanReadonly(campaign)
	if planErr != nil {
		plan = validation.VNull()
	}
	if plan.Kind != validation.Obj {
		return
	}
	priorities := []validation.Value{}
	for _, p := range listAt(plan, "priorities") {
		if p.Kind == validation.Obj {
			priorities = append(priorities, p)
		}
	}
	untouched := []validation.Value{}
	for _, p := range priorities {
		st := validation.ObjStr(p, "status")
		dispositioned := false
		for _, d := range planner.ProbeRowDispositioned {
			if st == d {
				dispositioned = true
				break
			}
		}
		if !dispositioned {
			untouched = append(untouched, p)
		}
	}
	setKey(queue, "total", validation.VInt(int64(len(priorities))))
	setKey(queue, "worked", validation.VInt(
		int64(len(priorities)-len(untouched))))
	setKey(queue, "untouched", validation.VInt(int64(len(untouched))))
	if len(untouched) > 0 {
		ledgerQueueOldest(untouched, nowDT, plan, cid, reg, queue)
	}
}

// queueAgeRow is one untouched priority row with its computed age.
type queueAgeRow struct {
	secs *int64
	pid  string
	age  *string
	p    validation.Value
}

func queueAgeRows(untouched []validation.Value, nowDT *time.Time,
	planT0 string) []queueAgeRow {
	rows := []queueAgeRow{}
	for _, p := range untouched {
		secs, ageTxt := age(*nowDT, deref(firstStamp(
			validation.ObjStr(p, "created_at"), validation.ObjStr(p, "generated_at"),
			validation.ObjStr(p, "opened_at"), planT0)))
		pid := validation.ObjStr(p, "id")
		if pid == "" {
			pid = "?"
		}
		rows = append(rows, queueAgeRow{secs, pid, ageTxt, p})
	}
	return rows
}

// ledgerQueueOldest mints the oldest-untouched queue entry: the age rows are
// stable-sorted by age then priority id, and the winner becomes the queue's
// `oldest` object and line.
func ledgerQueueOldest(untouched []validation.Value, nowDT *time.Time,
	plan validation.Value, cid string, reg validation.Value,
	queue *validation.Value) {
	planT0 := validation.ObjStr(plan, "created_at")
	if planT0 == "" {
		planT0 = validation.ObjStr(plan, "generated_at")
	}
	rows := queueAgeRows(untouched, nowDT, planT0)
	sort.SliceStable(rows, func(i, j int) bool {
		ki, kj := ageSortKey(rows[i].secs), ageSortKey(rows[j].secs)
		if ki != kj {
			return ki < kj
		}
		return rows[i].pid < rows[j].pid
	})
	r := rows[0]
	invID, severity, high := priorityInvariant(r.p, reg)
	suffix := ""
	if invID != "" {
		suffix = ", " + invID
		if severity != nil {
			suffix += " " + *severity
		}
	}
	ageTxt := "unknown"
	if r.age != nil {
		ageTxt = *r.age
	}
	command := fmt.Sprintf("webv2 answered %s %s answered "+
		"--reason R --actor A", cid, r.pid)
	if pyTruthyInt64Only(validation.ObjAt(r.p, "probe")) {
		command += " --anchor FIELD"
	}
	line := fmt.Sprintf("questions worked %d/%d — oldest untouched: "+
		"%s (%s%s)", intField(*queue, "worked"), intField(*queue, "total"),
		r.pid, ageTxt, suffix)
	var sevOut validation.Value
	if severity != nil {
		sevOut = validation.VStr(*severity)
	} else {
		sevOut = validation.VNull()
	}
	var invOut validation.Value
	if invID != "" {
		invOut = validation.VStr(invID)
	} else {
		invOut = validation.VNull()
	}
	var secsOut validation.Value = validation.VNull()
	if r.secs != nil {
		secsOut = validation.VInt(*r.secs)
	}
	oldest := validation.VObj(
		kv("priority_id", validation.VStr(r.pid)),
		kv("age", validation.VStr(ageTxt)),
		kv("age_seconds", secsOut),
		kv("invariant_id", invOut),
		kv("severity", sevOut),
		kv("high_consequence", validation.VBool(high)),
		kv("command", validation.VStr(command)),
		kv("line", validation.VStr(line+" — "+command)),
		kv("action", validation.VStr(fmt.Sprintf("work the oldest "+
			"untouched question %s (%s%s): %s", r.pid, ageTxt,
			suffix, command))))
	setKey(queue, "oldest", oldest)
	setKey(queue, "line", validation.ObjAt(oldest, "line"))
}

// ledgerInvariantDebt fills the invariants block from the registry's
// UNVERIFIED entries and returns the ranked items.
func ledgerInvariantDebt(campaign *state.Campaign, cid string,
	nowDT *time.Time, reg validation.Value,
	invariantsBlock *validation.Value) ([]validation.Value, error) {
	st, err := campaign.State()
	if err != nil {
		return nil, err
	}
	campaignStart := validation.ObjStr(st, "created_at")
	items := ledgerInvariantItems(reg, cid, nowDT, campaignStart)
	sort.SliceStable(items, func(i, j int) bool {
		hi, ki, ii := invariantsRankKey(items[i])
		hj, kj, ij := invariantsRankKey(items[j])
		if hi != hj {
			return !hi
		}
		if ki != kj {
			return ki < kj
		}
		return ii < ij
	})
	dictEntries := int64(0)
	for _, e := range reg.O {
		if e.V.Kind == validation.Obj {
			dictEntries++
		}
	}
	highCount := int64(0)
	for _, it := range items {
		if pyTruthyInt64Only(validation.ObjAt(it, "high_consequence")) {
			highCount++
		}
	}
	setKey(invariantsBlock, "total", validation.VInt(dictEntries))
	setKey(invariantsBlock, "unverified", validation.VInt(int64(len(items))))
	setKey(invariantsBlock, "high_consequence", validation.VInt(highCount))
	setKey(invariantsBlock, "items", validation.VArr(items...))
	if len(items) > 0 {
		top := items[0]
		setKey(invariantsBlock, "line", validation.VStr(fmt.Sprintf(
			"invariants: %d UNVERIFIED (liveness/critical first, with age) — "+
				"verify %s (unverified %s): %s", len(items),
			validation.ObjStr(top, "invariant_id"), validation.ObjStr(top, "age"),
			validation.ObjStr(top, "command"))))
	}
	return items, nil
}

// ledgerInvariantItems builds one display item per UNVERIFIED registry
// entry, aged from its own timestamp (falling back to the campaign start).
func ledgerInvariantItems(reg validation.Value, cid string, nowDT *time.Time,
	campaignStart string) []validation.Value {
	items := []validation.Value{}
	for _, e := range reg.O {
		if e.V.Kind != validation.Obj {
			continue
		}
		status := validation.ObjStr(e.V, "status")
		if status == "" {
			status = "UNVERIFIED"
		}
		if status != "UNVERIFIED" {
			continue
		}
		sevV := validation.ObjAt(e.V, "severity_if_broken")
		kindV := validation.ObjAt(e.V, "kind")
		ts := deref(entryTimestamp(e.V))
		if ts == "" {
			ts = campaignStart
		}
		secs, ageTxt := age(*nowDT, ts)
		ageText := "unknown"
		if ageTxt != nil {
			ageText = *ageTxt
		}
		command := fmt.Sprintf("webv2 invariant-verify %s %s --exec EXEC-*",
			cid, e.K)
		var secsOut validation.Value = validation.VNull()
		if secs != nil {
			secsOut = validation.VInt(*secs)
		}
		high := (sevV.Kind == validation.Str && sevV.S == "critical") ||
			(kindV.Kind == validation.Str && kindV.S == "liveness")
		line := fmt.Sprintf("verify %s (unverified %s): %s", e.K, ageText,
			command)
		items = append(items, validation.VObj(
			kv("kind", validation.VStr("invariant")),
			kv("invariant_id", validation.VStr(e.K)),
			kv("age", validation.VStr(ageText)),
			kv("age_seconds", secsOut),
			kv("severity_if_broken", sevV),
			kv("invariant_kind", kindV),
			kv("high_consequence", validation.VBool(high)),
			kv("command", validation.VStr(command)),
			kv("line", validation.VStr(line)),
			kv("action", validation.VStr(line))))
	}
	return items
}

// ledgerRanked assembles the ordering list: every invariant item, then the
// queue's oldest entry (when present), stable-sorted by the lead rank key.
func ledgerRanked(items []validation.Value,
	queue validation.Value) validation.Value {
	ranked := []validation.Value{}
	for _, it := range items {
		ranked = append(ranked, it)
	}
	if validation.ObjAt(queue, "oldest").Kind == validation.Obj {
		oldest := validation.ObjAt(queue, "oldest")
		ranked = append(ranked, validation.VObj(
			kv("kind", validation.VStr("queue")),
			kv("priority_id", validation.ObjAt(oldest, "priority_id")),
			kv("age", validation.ObjAt(oldest, "age")),
			kv("age_seconds", validation.ObjAt(oldest, "age_seconds")),
			kv("invariant_id", validation.ObjAt(oldest, "invariant_id")),
			kv("severity_if_broken", validation.ObjAt(oldest, "severity")),
			kv("high_consequence", validation.ObjAt(oldest, "high_consequence")),
			kv("command", validation.ObjAt(oldest, "command")),
			kv("line", validation.ObjAt(oldest, "line")),
			kv("action", validation.ObjAt(oldest, "action"))))
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		ci, ki, ii := leadRankKey(ranked[i])
		cj, kj, ij := leadRankKey(ranked[j])
		if ci != cj {
			return ci < cj
		}
		if ki != kj {
			return ki < kj
		}
		return ii < ij
	})
	return validation.VArr(ranked...)
}

// ledgerLines renders the printable block: the queue line, then the
// invariants line plus every other high-consequence invariant row.
func ledgerLines(queue, invariantsBlock validation.Value,
	items []validation.Value) []string {
	lines := []string{}
	if validation.ObjAt(queue, "line").Kind == validation.Str {
		lines = append(lines, validation.ObjAt(queue, "line").S)
	}
	if validation.ObjAt(invariantsBlock, "line").Kind == validation.Str {
		lines = append(lines, validation.ObjAt(invariantsBlock, "line").S)
		named := ""
		if len(items) > 0 {
			named = validation.ObjStr(items[0], "invariant_id")
		}
		for _, it := range items {
			if pyTruthyInt64Only(validation.ObjAt(it, "high_consequence")) &&
				validation.ObjStr(it, "invariant_id") != named {
				lines = append(lines, validation.ObjStr(it, "line"))
			}
		}
	}
	return lines
}
func suppressDebt(ledger *validation.Value) {
	setKey(ledger, "suppressed", validation.VStr("campaign closed by "+
		"decision — no debt nagging (closed-cockpit discipline)"))
	setKey(ledger, "lines", validation.VArr())
	setKey(ledger, "ranked", validation.VArr())
	queue := validation.ObjAt(*ledger, "queue")
	setKey(&queue, "line", validation.VNull())
	oldest := validation.ObjAt(queue, "oldest")
	if oldest.Kind == validation.Obj {
		setKey(&oldest, "line", validation.VNull())
		setKey(&oldest, "action", validation.VNull())
		setKey(&queue, "oldest", oldest)
	}
	setKey(ledger, "queue", queue)
	invariantsBlock := validation.ObjAt(*ledger, "invariants")
	setKey(&invariantsBlock, "line", validation.VNull())
	items := listAt(invariantsBlock, "items")
	for i := range items {
		setKey(&items[i], "line", validation.VNull())
		setKey(&items[i], "action", validation.VNull())
	}
	setKey(&invariantsBlock, "items", validation.VArr(items...))
	setKey(ledger, "invariants", invariantsBlock)
}
