// cmd_probes_pending: `probes <campaign> pending` — the B10(b) drain view.
//
// WHY IT EXISTS (docs/feedback-triage-morph-r2.md §B10(b)). The round-1
// replay's verdict was throughput, not information: both gold shapes sat in
// tier-0 surface rows that were never dispositioned, and the bootstrap's own
// lens rule ("any undispositioned row keeps the lens OPEN") first bites at
// end-of-pass lens closure, which an operator who stops at stage 5 never
// meets. B10(a) puts the forcing function on the CONFIRMED path; this is the
// cheap PULL half of the same item: one command that names every
// undispositioned row, ranked, each with the exact `answered` invocation its
// own data implies — read the row, discharge it.
//
// THE RANK is the row's own risk key first, the B7 join last: tier ascending
// (tier 0 = unprivileged or adversarial actor, the rows the eval's gold set
// actually sat in), then assertion_gap descending (how far the row asserts
// past its evidence), then the anchorlink convergence count descending (a row
// whose code a second store also names is the stronger lead). rank/row_id
// close the order so the same artifacts always print the same lines.
//
// THE CONVERGENCE COUNT is internal/anchorlink's, consumed, never
// re-implemented: the join runs once for the whole view and every row reads
// the anchors it is a member of. "N converging stores" is the size of the
// UNION of those anchors' stores[] — a row whose contract converges with the
// plan is 2, one that also converges with a filed finding is 3, one nothing
// else names is 0 (and `--json` carries the anchor keys and the store names
// so the number is checkable). A campaign with no protocol model, or one the
// seam rejects, has no convergence to report — that is 0, not a refusal.
//
// BYTE DISCIPLINE. This is a new subcommand, so its stdout is its own. The
// verb's usage/choice error text is NOT touched (see the note in
// cmd_probes.go); the help text gains the subcommand, and nothing else in the
// verb's existing output changes.
package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"websec/internal/anchorlink"
	"websec/internal/findings"
	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

const t29ProbesPendingUsage = `usage: webv2 probes campaign pending [-h] [--max N] [--json]
`

const t29ProbesPendingHelp = `usage: webv2 probes campaign pending [-h] [--max N] [--json]

the undispositioned surface rows, ranked (tier ascending, assertion_gap
descending, then the B7 convergence count), one line each with the exact
'answered' command the row's own data implies. The console cap is 20 rows;
--json is the uncapped machine view.

options:
  -h, --help  show this help message and exit
  --max N     how many rows to print (default 20)
  --json      the full pending list as JSON, never capped
`

// pendingCap is the drain view's console cap (B10b): a worklist is a queue,
// not a transcript. --max N widens it; --json is never capped.
const pendingCap = 20

// parseProbesPending is `probes <c> pending [--max N] [--json]`.
func parseProbesPending(a *probesArgs, args []string, r *Runner) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t29ProbesPendingHelp)
			return errHelpShown
		}
		if arg == "--json" {
			a.asJSON = true
			continue
		}
		name, val, hasVal := splitFlag(arg)
		if name == "--max" {
			if !hasVal {
				if i+1 >= len(args) {
					return t14ArgparseErr(t29ProbesPendingUsage,
						"probes campaign pending",
						"argument --max: expected one argument")
				}
				val = args[i+1]
				i++
			}
			n, err := strconv.Atoi(val)
			if err != nil {
				return t14ArgparseErr(t29ProbesPendingUsage,
					"probes campaign pending",
					"argument --max: invalid int value: %s",
					validation.PyReprStr(val))
			}
			if n < 1 {
				return t14ExitErr(2, "probes pending: --max %d prints "+
					"nothing — pass --max N with N >= 1, or --json for "+
					"the full list\n", n)
			}
			a.max = &n
			continue
		}
		return t14Unrecognized(arg)
	}
	return nil
}

// pendingConvergence is the B7 join's answer for ONE row: the stores that
// converge on the row's anchors (a set — the union across every anchor the row
// is a member of) and the canonical keys that carried them.
type pendingConvergence struct {
	stores map[string]bool
	keys   []string
}

// pendingRow is one undispositioned row's drain line: the row's own
// coordinates, the plan's disposition of it, the join's count and the exact
// command that discharges it.
type pendingRow struct {
	rowID      string
	probe      string
	axis       string
	lens       string
	tier       int64
	rank       int64
	gap        int64
	why        string
	cite       string
	anchor     string
	ref        string
	priorityID string
	status     string
	stale      bool
	converging int
	keys       []string
	stores     []string
	command    string
}

// pendingView is the loaded drain view.
type pendingView struct {
	c       *state.Campaign
	surface validation.Value
	summary validation.Value
	index   *validation.Value
	disp    validation.Value
	conv    map[string]pendingConvergence
	rows    []pendingRow
	cap     int
	asJSON  bool
}

// probesPending is the `probes <c> pending` body.
func probesPending(a *probesArgs, c *state.Campaign, r *Runner) error {
	v := &pendingView{c: c, cap: pendingCap, asJSON: a.asJSON}
	if a.max != nil {
		v.cap = *a.max
	}
	if err := pendingLoad(v); err != nil {
		return err
	}
	if v.asJSON {
		return pendingJSON(v, r)
	}
	pendingTable(v, r.Out)
	return nil
}

// pendingLoad reads the surface, its summary, the structural index (the row's
// own citations resolve through it), the plan's dispositions and the B7 join.
func pendingLoad(v *pendingView) error {
	surface, err := probes.CampaignSurface(v.c)
	if err != nil {
		return err
	}
	if surface == nil {
		return t14ExitErr(2, "probes: no probe surface for %s — run "+
			"`webv2 probes %s run` first\n", v.c.CampaignID, v.c.CampaignID)
	}
	v.surface = *surface
	summary, err := probes.SurfaceSummary(v.c, nil)
	if err != nil {
		return err
	}
	if summary == nil {
		return t14ExitErr(2, "probes: no probe surface for %s — run "+
			"`webv2 probes %s run` first\n", v.c.CampaignID, v.c.CampaignID)
	}
	v.summary = *summary
	index, err := probes.CampaignIndex(v.c)
	if err != nil {
		return err
	}
	v.index = index
	// The plan is optional — a campaign that has not planned yet lists every
	// row with `probes run --emit` as its next command, which is the honest
	// answer — but an UNREADABLE plan is a refusal: answering "no obligations"
	// for a plan that was never read would print a worklist of lies.
	planPath := filepath.Join(v.c.ArtifactsDir, "campaign_plan.json")
	var planPtr *validation.Value
	if t14Exists(planPath) {
		plan, err := validation.ReadJson(planPath)
		if err != nil {
			return t14ExitErr(2, "probes pending: unreadable %s (%v) — "+
				"repair it, or rebuild it with `webv2 plan %s <plan.json>`\n",
				planPath, err, v.c.CampaignID)
		}
		planPtr = &plan
	}
	v.disp = probes.RowDispositions(planPtr, v.surface)
	conv, err := pendingConvergences(v.c, v.surface, planPtr)
	if err != nil {
		return err
	}
	v.conv = conv
	v.rows = pendingRows(v.c, v.surface, v.disp, v.index, v.conv)
	return nil
}

// pendingConvergences runs the B7 seam once for the whole view: rows,
// priorities and findings in, canonical keys and their member stores out. A
// model the seam cannot index is zero convergence, never a refusal — the count
// ranks a worklist, it does not gate one. An UNLISTABLE findings store is a
// refusal, because answering "no convergence" for a store that was never read
// would silently reorder the queue.
func pendingConvergences(c *state.Campaign, surface validation.Value,
	plan *validation.Value) (map[string]pendingConvergence, error) {
	out := map[string]pendingConvergence{}
	store, err := anchorlink.Open(planner.ModelOrEmpty(c))
	if err != nil {
		return out, nil
	}
	var prios []validation.Value
	if plan != nil {
		prios = t14List(*plan, "priorities").A
	}
	found, err := findings.LoadAllFindings(c)
	if err != nil {
		return nil, t14ExitErr(2, "probes pending: %v\n", err)
	}
	for _, a := range store.Convergences(t14List(surface, "rows").A, prios, found) {
		for _, rid := range a.Rows {
			rec, ok := out[rid]
			if !ok {
				rec = pendingConvergence{stores: map[string]bool{}}
			}
			for _, s := range a.Stores {
				rec.stores[s] = true
			}
			rec.keys = append(rec.keys, a.Key)
			out[rid] = rec
		}
	}
	return out, nil
}

// pendingRows is the ranked worklist: every row the plan does not (or no
// longer) disposition, in the B10(b) order.
func pendingRows(c *state.Campaign, surface, disp validation.Value,
	index *validation.Value, conv map[string]pendingConvergence) []pendingRow {
	out := []pendingRow{}
	for _, row := range t14List(surface, "rows").A {
		rid := validation.ObjStr(row, "row_id")
		d := validation.ObjAt(disp, rid)
		if objBool(d, "dispositioned") {
			continue
		}
		anchor, ref := pendingAnchorRef(row, index)
		convRow := conv[rid]
		p := pendingRow{
			rowID:      rid,
			probe:      validation.ObjStr(row, "probe"),
			axis:       validation.ObjStr(row, "axis"),
			lens:       validation.ObjStr(row, "lens"),
			tier:       objInt(row, "tier"),
			rank:       objInt(row, "rank"),
			gap:        objInt(row, "assertion_gap"),
			why:        validation.ObjStr(row, "why"),
			cite:       pendingCite(row, ref),
			anchor:     anchor,
			ref:        ref,
			priorityID: validation.ObjStr(d, "priority_id"),
			status:     validation.ObjStr(d, "status"),
			stale:      objBool(d, "stale"),
			converging: len(convRow.stores),
			keys:       pendingSorted(convRow.keys),
			stores:     pendingStoreNames(convRow.stores),
		}
		p.command = pendingCommand(c.CampaignID, p)
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.tier != b.tier {
			return a.tier < b.tier
		}
		if a.gap != b.gap {
			return a.gap > b.gap
		}
		if a.converging != b.converging {
			return a.converging > b.converging
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		return a.rowID < b.rowID
	})
	return out
}

// pendingAnchorRef picks the field the row's OWN data points at — never a
// guess the row cannot back: the consumer coordinate when the probe produces
// one and the row carries it (the assertion-strength shape the replay's gold
// row had), else the first enum anchor the row actually has a value for. The
// second return is that anchor's own citation, the ref the closure records.
func pendingAnchorRef(row validation.Value,
	index *validation.Value) (string, string) {
	probeID := validation.ObjStr(row, "probe")
	candidates := []string{}
	if probes.AnchorAllowed(probeID, "consumer") {
		candidates = append(candidates, "consumer")
	}
	for _, a := range probes.AnchorEnum() {
		if a != "consumer" && probes.AnchorAllowed(probeID, a) {
			candidates = append(candidates, a)
		}
	}
	fallback := ""
	for _, a := range candidates {
		if fallback == "" {
			fallback = a
		}
		value, err := probes.RowAnchorValue(row, a)
		if err != nil || pendingAnchorEmpty(value) {
			continue
		}
		ref, err := probes.AnchorRef(row, a, index)
		if err != nil || strings.TrimSpace(ref) == "" {
			continue
		}
		return a, ref
	}
	if fallback == "" {
		return "", ""
	}
	ref, _ := probes.AnchorRef(row, fallback, index)
	return fallback, ref
}

// pendingAnchorEmpty reports an anchor value that names nothing.
func pendingAnchorEmpty(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return true
	case validation.Str:
		return strings.TrimSpace(v.S) == ""
	case validation.Arr:
		return len(v.A) == 0
	}
	return false
}

// pendingCite is the row's own coordinates as `<contract>#<consumer>:<line>`,
// falling back to the anchor's citation when the probe carries no consumer
// coordinate (a trust-assumption row names an actor, not a function).
func pendingCite(row validation.Value, ref string) string {
	contract := validation.ObjStr(row, "contract")
	consumer := validation.ObjStr(row, "consumer")
	line := objInt(row, "consumer_line")
	if contract != "" && consumer != "" && line > 0 {
		return fmt.Sprintf("%s#%s:%d", contract, consumer, line)
	}
	if strings.TrimSpace(ref) != "" {
		return ref
	}
	return "—"
}

// pendingCommand is the exact `answered` shape the row's own data implies —
// the bootstrap's lens-closure prose verbatim: `answered <C> Q-xxx <status>
// --anchor <field> --reason "..."`. The reason stays a placeholder on purpose:
// it is operator prose, and the gate refuses prose that names nothing from the
// row, so a generated sentence would be a fake discharge rather than a
// shortcut. A row the plan never emitted has no priority to answer, so its
// next command is the emit that creates one.
func pendingCommand(cid string, p pendingRow) string {
	if p.priorityID == "" {
		return fmt.Sprintf("webv2 probes %s run --emit", cid)
	}
	cmd := fmt.Sprintf("webv2 answered %s %s answered --reason "+
		"\"<why this row is safe>\"", cid, p.priorityID)
	if p.anchor != "" {
		cmd += " --anchor " + p.anchor
	}
	return cmd
}

// pendingSorted is a sorted copy of a string slice: the join's member order is
// already deterministic, and sorting again keeps the JSON render stable.
func pendingSorted(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

// pendingStoreNames is the sorted member list of a store set.
func pendingStoreNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pendingStoreWord is "store"/"stores" for the count.
func pendingStoreWord(n int) string {
	if n == 1 {
		return "store"
	}
	return "stores"
}

// pendingTable is the console branch: the surface line, one line per pending
// row (capped), then the pointer to the complete view. An empty worklist says
// so in one line and stops.
func pendingTable(v *pendingView, w io.Writer) {
	total := objInt(v.summary, "rows")
	if len(v.rows) == 0 {
		fmt.Fprintf(w, "probe surface: %d rows, 0 pending — all dispositioned\n",
			total)
		return
	}
	stale := 0
	for _, p := range v.rows {
		if p.stale {
			stale++
		}
	}
	staleClause := ""
	if stale > 0 {
		staleClause = fmt.Sprintf("%d stale; ", stale)
	}
	fmt.Fprintf(w, "probe surface: %d rows, %d pending (%scap %d; --max N "+
		"or --json for the full list)\n", total, len(v.rows), staleClause, v.cap)
	shown := len(v.rows)
	if shown > v.cap {
		shown = v.cap
	}
	for _, p := range v.rows[:shown] {
		fmt.Fprintf(w, "%s | tier %d | gap %d | %s | %s | %s | %d "+
			"converging %s -> %s\n", p.rowID, p.tier, p.gap, p.axis, p.probe,
			p.cite, p.converging, pendingStoreWord(p.converging), p.command)
	}
	if len(v.rows) > v.cap {
		fmt.Fprintf(w, "  … +%d more pending rows — use --max N or --json "+
			"for the full list\n", len(v.rows)-v.cap)
	}
}

// pendingJSON is the --json branch: the full list, never capped, with the
// counts, the join's members and the command per row.
func pendingJSON(v *pendingView, r *Runner) error {
	rows := []validation.Value{}
	for _, p := range v.rows {
		rows = append(rows, validation.VObj(
			validation.KV{K: "row_id", V: validation.VStr(p.rowID)},
			validation.KV{K: "probe", V: validation.VStr(p.probe)},
			validation.KV{K: "axis", V: validation.VStr(p.axis)},
			validation.KV{K: "lens", V: validation.VStr(p.lens)},
			validation.KV{K: "tier", V: validation.VInt(p.tier)},
			validation.KV{K: "rank", V: validation.VInt(p.rank)},
			validation.KV{K: "assertion_gap", V: validation.VInt(p.gap)},
			validation.KV{K: "cite", V: validation.VStr(p.cite)},
			validation.KV{K: "anchor", V: validation.VStr(p.anchor)},
			validation.KV{K: "anchor_ref", V: validation.VStr(p.ref)},
			validation.KV{K: "priority_id", V: validation.VStr(p.priorityID)},
			validation.KV{K: "status", V: validation.VStr(p.status)},
			validation.KV{K: "stale", V: validation.VBool(p.stale)},
			validation.KV{K: "converging_stores",
				V: validation.VInt(int64(p.converging))},
			validation.KV{K: "converging_keys", V: strListValue(p.keys)},
			validation.KV{K: "converging_names", V: strListValue(p.stores)},
			validation.KV{K: "command", V: validation.VStr(p.command)},
			validation.KV{K: "why", V: validation.VStr(p.why)}))
	}
	t14PrintJSON(r.Out, validation.VObj(
		validation.KV{K: "campaign_id",
			V: validation.ObjAt(v.surface, "campaign_id")},
		validation.KV{K: "index_sha",
			V: validation.ObjAt(v.surface, "index_sha")},
		validation.KV{K: "current_index_sha",
			V: validation.ObjAt(v.summary, "current_index_sha")},
		validation.KV{K: "stale", V: validation.ObjAt(v.summary, "stale")},
		validation.KV{K: "rows", V: validation.ObjAt(v.summary, "rows")},
		validation.KV{K: "pending", V: validation.VInt(int64(len(v.rows)))},
		validation.KV{K: "cap", V: validation.VInt(int64(v.cap))},
		validation.KV{K: "pending_rows", V: validation.VArr(rows...)}))
	return nil
}
