package cli

// cmd_probes: `webv2 probes <campaign> {run,list,blank}` — the operator
// surface for the mechanical candidate plane. cli.py cmd_probes verbatim:
// `run` builds (and optionally emits) the surface, `list` is the operator
// view, `blank` records the named decision that closes a blind axis.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

const t29ProbesUsage = `usage: webv2 probes [-h] campaign {run,list,blank} ...
`

const t29ProbesHelp = `usage: webv2 probes [-h] campaign {run,list,blank} ...

positional arguments:
  campaign
  {run,list,blank}
    run             build the surface from the current structural index
                    (--emit turns its rows into plan obligations)
    list            the surface as an operator view: rows, anchors,
                    dispositions, blind keys
    blank           record the named decision that closes a BLIND axis, citing
                    a key the probe actually published

options:
  -h, --help        show this help message and exit
`

const t29ProbesRunUsage = `usage: webv2 probes campaign run [-h] [--emit] [--per-axis N] [--total N]
`

const t29ProbesRunHelp = `usage: webv2 probes campaign run [-h] [--emit] [--per-axis N] [--total N]

quotas: a quota flag the run was not given adopts the value already recorded
in probe_surface.json (else the default), so a bare run repairs the surface
the campaign has instead of shrinking it

options:
  -h, --help    show this help message and exit
  --emit        also emit one plan priority per emitted row
  --per-axis N  per-axis quota (default 12)
  --total N     campaign ceiling across axes (default 40)
`

const t29ProbesListUsage = `usage: webv2 probes campaign list [-h] [--axis A] [--all] [--json]
`

const t29ProbesListHelp = `usage: webv2 probes campaign list [-h] [--axis A] [--all] [--json]

options:
  -h, --help  show this help message and exit
  --axis A    one axis: L-0n or the probe axis name
  --all       every axis (incl. no-sites/blind) + the published blind keys
  --json
`

const t29ProbesBlankUsage = `usage: webv2 probes campaign blank [-h] --axis L-0n --anchor-blind K
                                   --reason REASON --actor ACTOR
`

const t29ProbesBlankHelp = `usage: webv2 probes campaign blank [-h] --axis L-0n --anchor-blind K
                                   --reason REASON --actor ACTOR

options:
  -h, --help        show this help message and exit
  --axis L-0n       the blind axis: its probe axis name, or a lens id (L-0n) —
                    a lens spelling is resolved by the cited --anchor-blind
                    key to the ONE probe on that lens that published it
  --anchor-blind K  one of that axis's blind[] keys; on a lens spelling it
                    also selects the axis
  --reason REASON
  --actor ACTOR
`

// probesArgs is the parsed command line.
type probesArgs struct {
	campaign    string
	cmd         string // "" means list (the default subcommand)
	emit        bool
	perAxis     int
	perAxisSet  bool
	total       int
	totalSet    bool
	axis        *string
	all         bool
	asJSON      bool
	anchorBlind *string
	reason      *string
	actor       *string
}

func runProbes(root string, args []string, r *Runner) error {
	a, err := parseProbes(args, r)
	if err != nil || a == nil {
		return err
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	switch a.cmd {
	case "run":
		return probesRun(a, c, r)
	case "blank":
		return probesBlank(a, c, r)
	default:
		return probesList(a, c, r)
	}
}

// parseProbes is the argparse layer: campaign, then the subcommand (default
// `list`), then that subparser's own flags.
func parseProbes(args []string, r *Runner) (*probesArgs, error) {
	a := &probesArgs{perAxis: 12, total: 40}
	i := 0
	for i < len(args) {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t29ProbesHelp)
			return nil, nil
		}
		if strings.HasPrefix(arg, "-") {
			return nil, t14Unrecognized(arg)
		}
		if a.campaign == "" {
			a.campaign = arg
			i++
			continue
		}
		a.cmd = arg
		i++
		if !t14InList(a.cmd, []string{"run", "list", "blank"}) {
			return nil, t14ArgparseErr(t29ProbesUsage, "probes",
				"argument probes_cmd: invalid choice: %s (choose from %s)",
				validation.PyReprStr(a.cmd), "'run', 'list', 'blank'")
		}
		break
	}
	if a.campaign == "" {
		return nil, t14ArgparseErr(t29ProbesUsage, "probes",
			"the following arguments are required: campaign")
	}
	rest := args[i:]
	var perr error
	switch a.cmd {
	case "run":
		perr = parseProbesRun(a, rest, r)
	case "blank":
		perr = parseProbesBlank(a, rest, r)
	case "list":
		perr = parseProbesList(a, rest, r)
	}
	if perr != nil {
		if perr == errHelpShown {
			return nil, nil
		}
		return nil, perr
	}
	return a, nil
}

// parseProbesRun is `probes <c> run [--emit] [--per-axis N] [--total N]`.
func parseProbesRun(a *probesArgs, args []string, r *Runner) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t29ProbesRunHelp)
			return errHelpShown
		}
		switch arg {
		case "--emit":
			a.emit = true
			continue
		case "--per-axis", "--total":
			if i+1 >= len(args) {
				return t14ArgparseErr(t29ProbesRunUsage,
					"probes campaign run", "argument %s: expected one argument", arg)
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return t14ArgparseErr(t29ProbesRunUsage,
					"probes campaign run", "argument %s: invalid int value: %s",
					arg, validation.PyReprStr(args[i+1]))
			}
			if arg == "--per-axis" {
				a.perAxis = n
				a.perAxisSet = true
			} else {
				a.total = n
				a.totalSet = true
			}
			i++
			continue
		}
		return t14Unrecognized(arg)
	}
	return nil
}

// parseProbesList is `probes <c> list [--axis A] [--all] [--json]`.
func parseProbesList(a *probesArgs, args []string, r *Runner) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t29ProbesListHelp)
			return errHelpShown
		}
		switch arg {
		case "--all":
			a.all = true
			continue
		case "--json":
			a.asJSON = true
			continue
		case "--axis":
			if i+1 >= len(args) {
				return t14ArgparseErr(t29ProbesListUsage,
					"probes campaign list", "argument --axis: expected one argument")
			}
			v := args[i+1]
			a.axis = &v
			i++
			continue
		}
		return t14Unrecognized(arg)
	}
	return nil
}

// parseProbesBlank is `probes <c> blank --axis --anchor-blind --reason --actor`.
func parseProbesBlank(a *probesArgs, args []string, r *Runner) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t29ProbesBlankHelp)
			return errHelpShown
		}
		switch arg {
		case "--axis", "--anchor-blind", "--reason", "--actor":
			if i+1 >= len(args) {
				return t14ArgparseErr(t29ProbesBlankUsage,
					"probes campaign blank", "argument %s: expected one argument", arg)
			}
			v := args[i+1]
			switch arg {
			case "--axis":
				a.axis = &v
			case "--anchor-blind":
				a.anchorBlind = &v
			case "--reason":
				a.reason = &v
			default:
				a.actor = &v
			}
			i++
			continue
		}
		return t14Unrecognized(arg)
	}
	missing := []string{}
	if a.axis == nil {
		missing = append(missing, "--axis")
	}
	if a.anchorBlind == nil {
		missing = append(missing, "--anchor-blind")
	}
	if a.reason == nil {
		missing = append(missing, "--reason")
	}
	if a.actor == nil {
		missing = append(missing, "--actor")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(t29ProbesBlankUsage, "probes campaign blank",
			"the following arguments are required: %s", strings.Join(missing, ", "))
	}
	return nil
}

// errHelpShown is the sentinel a subparser help path returns: parseProbes
// already wrote the help and must not continue.
var errHelpShown = fmt.Errorf("help shown")

// probesRun is cli.py _probes_run.
func probesRun(a *probesArgs, c *state.Campaign, r *Runner) error {
	// An explicit flag is validated exactly as it always was, before the
	// artifact is consulted, so `--per-axis 0` keeps its existing message.
	var perAxisKnob, totalKnob *int
	if a.perAxisSet {
		perAxisKnob = &a.perAxis
	}
	if a.totalSet {
		totalKnob = &a.total
	}
	if err := probes.ValidateKnobs(perAxisKnob, totalKnob, nil); err != nil {
		return t14ExitErr(2, "probes: %v\n", err)
	}
	perAxis, total, provenance, err := effectiveProbeQuotas(a, c)
	if err != nil {
		return err
	}
	index, err := loadProbeIndex(c)
	if err != nil {
		return err
	}
	model := loadProbeModel(c)
	surface, err := probes.RunProbes(c, index, model, perAxis, total, 3)
	if err != nil {
		return err
	}
	stats := objAt(surface, "stats")
	fmt.Fprintf(r.Out, "probe surface: %d rows emitted (%d ranked, %d sites) "+
		"— index_sha %s\n", objInt(stats, "emitted"), objInt(stats, "rows"),
		objInt(stats, "sites"), t29Trunc(objStr(surface, "index_sha"), 12))
	fmt.Fprintf(r.Out, "quotas: --per-axis %d --total %d (%s)\n", perAxis,
		total, provenance)
	for _, line := range probeAxisLines(surface, nil, true) {
		fmt.Fprintln(r.Out, line)
	}
	for _, line := range probeWarningLines(surface) {
		fmt.Fprintln(r.Out, line)
	}
	for _, m := range t14List(surface, "missing").A {
		fmt.Fprintf(r.Out, "  missing: %s\n", objStr(m, "reason"))
	}
	if !a.emit {
		fmt.Fprintf(r.Out, "next: webv2 probes %s run --emit  (turn the rows "+
			"into plan obligations)\n", c.CampaignID)
		return nil
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	if !t29FileExists(planPath) {
		return t14ExitErr(2, "probes --emit: no campaign plan for %s — run "+
			"`webv2 plan %s <plan.json>` first\n", c.CampaignID, c.CampaignID)
	}
	plan, err := validation.ReadJson(planPath)
	if err != nil {
		return err
	}
	res, err := probes.EmitRows(c, plan, surface, &index)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "emit: created %d, updated %d, kept %d, reopened %d, "+
		"orphaned %d\n", len(t14List(res, "created").A),
		len(t14List(res, "updated").A), len(t14List(res, "kept").A),
		len(t14List(res, "reopened").A), len(t14List(res, "orphaned").A))
	if orph := t14List(res, "orphaned").A; len(orph) > 0 {
		parts := make([]string, 0, len(orph))
		for _, o := range orph {
			parts = append(parts, scalarStr(o))
		}
		fmt.Fprintf(r.Out, "  orphaned (in the plan, absent from this surface): "+
			"%s\n", strings.Join(parts, ", "))
	}
	return nil
}

// probeQuotaArtifact names the surface artifact an unset quota flag reads its
// value from; the provenance line and the invalid-record error both use it.
const probeQuotaArtifact = "probe_surface.json"

// effectiveProbeQuotas resolves the run's quotas one flag at a time: an
// explicit flag wins, else the value the existing surface artifact records,
// else the compiled-in default. The artifact is only read when a flag is
// unset, so an explicit pair never depends on it. The returned provenance
// describes where each effective value came from.
func effectiveProbeQuotas(a *probesArgs, c *state.Campaign) (int, int,
	string, error) {
	perAxis, total := a.perAxis, a.total
	perAxisSrc, totalSrc := "passed on the command line",
		"passed on the command line"
	if !a.perAxisSet {
		perAxisSrc = "defaults"
	}
	if !a.totalSet {
		totalSrc = "defaults"
	}
	if a.perAxisSet && a.totalSet {
		return perAxis, total, quotaProvenance(perAxisSrc, totalSrc), nil
	}
	surface, err := probes.CampaignSurface(c)
	if err != nil {
		return 0, 0, "", err
	}
	if surface == nil {
		return perAxis, total, quotaProvenance(perAxisSrc, totalSrc), nil
	}
	path := filepath.Join(c.ArtifactsDir, probeQuotaArtifact)
	if !a.perAxisSet {
		n, src, err := recordedProbeQuota(*surface, path, "per_axis",
			"--per-axis", perAxis)
		if err != nil {
			return 0, 0, "", err
		}
		perAxis, perAxisSrc = n, src
	}
	if !a.totalSet {
		n, src, err := recordedProbeQuota(*surface, path, "total",
			"--total", total)
		if err != nil {
			return 0, 0, "", err
		}
		total, totalSrc = n, src
	}
	return perAxis, total, quotaProvenance(perAxisSrc, totalSrc), nil
}

// recordedProbeQuota reads one quota knob from an existing surface. A knob
// that is not an integer is no record at all and the default stands; an
// integer that fails ValidateKnobs is an error naming the artifact and the
// value — a bad record must never be silently ignored.
func recordedProbeQuota(surface validation.Value, path, key, flag string,
	def int) (int, string, error) {
	raw := objAt(surface, key)
	if raw.Kind != validation.Int {
		return def, "defaults", nil
	}
	n := int(objInt(surface, key))
	knob := &n
	var err error
	if key == "per_axis" {
		err = probes.ValidateKnobs(knob, nil, nil)
	} else {
		err = probes.ValidateKnobs(nil, knob, nil)
	}
	if err != nil {
		return 0, "", t14ExitErr(2, "probes: %s records an invalid %s %d: "+
			"%v\n", path, flag, n, err)
	}
	return n, "recorded in " + probeQuotaArtifact, nil
}

// quotaProvenance names where each effective quota came from, collapsing the
// two entries when they share a source.
func quotaProvenance(perAxisSrc, totalSrc string) string {
	if perAxisSrc == totalSrc {
		return perAxisSrc
	}
	return fmt.Sprintf("--per-axis %s; --total %s", perAxisSrc, totalSrc)
}

// loadProbeIndex is cli.py _load_probe_index.
func loadProbeIndex(c *state.Campaign) (validation.Value, error) {
	p := filepath.Join(c.ArtifactsDir, "structural_index.json")
	if !t29FileExists(p) {
		return validation.VNull(), t14ExitErr(2, "probes: no structural "+
			"index for %s — run `webv2 index %s --src <target>` first\n",
			c.CampaignID, c.CampaignID)
	}
	idx, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull(), t14ExitErr(2, "probes: unreadable "+
			"structural index (%s) — re-run `webv2 index %s --src <target>`\n",
			err.Error(), c.CampaignID)
	}
	return idx, nil
}

// loadProbeModel is cli.py _load_probe_model: None is a legitimate input.
func loadProbeModel(c *state.Campaign) validation.Value {
	p := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if !t29FileExists(p) {
		return validation.VNull()
	}
	m, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull()
	}
	return m
}

// probeAxisLines is _probe_axis_lines.
func probeAxisLines(surface validation.Value, axisFilter *probes.AxisScope,
	showAll bool) []string {
	lines := []string{}
	for _, a := range t14List(surface, "axes").A {
		if axisFilter != nil && !t14InList(objStr(a, "axis"), axisFilter.Axes) {
			continue
		}
		if !showAll && objInt(a, "emitted") == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("  %s (%s, %s): sites %d, rows %d, "+
			"emitted %d, tail %d — %s", objStr(a, "axis"), objStr(a, "lens"),
			objStr(a, "probe"), objInt(a, "sites"), objInt(a, "rows"),
			objInt(a, "emitted"), objInt(a, "tail"), objStr(a, "status")))
		if showAll {
			for _, b := range t14List(a, "blind").A {
				near := ""
				if nearVal := objAt(b, "near"); nearVal.Kind == validation.Str {
					near = " (near " + nearVal.S + ")"
				}
				lines = append(lines, fmt.Sprintf("      blind: %s%s — %s",
					scalarStr(objAt(b, "key")), near,
					scalarStr(objAt(b, "reason"))))
			}
		}
	}
	return lines
}

// probeWarningLines is _probe_warning_lines.
func probeWarningLines(surface validation.Value) []string {
	lines := []string{}
	for _, w := range t14List(surface, "warnings").A {
		if msg := objStr(w, "message"); msg != "" {
			lines = append(lines, "  warning: "+msg)
		}
	}
	return lines
}

// probesList is cli.py _probes_list.
func probesList(a *probesArgs, c *state.Campaign, r *Runner) error {
	surface, err := probes.CampaignSurface(c)
	if err != nil {
		return err
	}
	if surface == nil {
		return t14ExitErr(2, "probes: no probe surface for %s — run "+
			"`webv2 probes %s run` first\n", c.CampaignID, c.CampaignID)
	}
	var axisFilter *probes.AxisScope
	if a.axis != nil {
		axisFilter = probes.AxisScopeOf(*a.axis)
		if axisFilter == nil {
			return t14ExitErr(2, "probes: unknown axis %s; registered: %s "+
				"(or their lens ids %s)\n", validation.PyReprStr(*a.axis),
				strings.Join(t29AxisNames(), ", "),
				strings.Join(t29LensIDs(), ", "))
		}
	}
	summary, err := probes.SurfaceSummary(c, nil)
	if err != nil {
		return err
	}
	if summary == nil {
		return t14ExitErr(2, "probes: no probe surface for %s — run "+
			"`webv2 probes %s run` first\n", c.CampaignID, c.CampaignID)
	}
	index, err := probes.CampaignIndex(c)
	if err != nil {
		return err
	}
	plan, err := planner.LoadPlanReadonly(c)
	var planPtr *validation.Value
	if err == nil {
		planPtr = &plan
	}
	dispositions := probes.RowDispositions(planPtr, *surface)
	if a.asJSON {
		rows := []validation.Value{}
		for _, row := range t14List(*surface, "rows").A {
			if axisFilter != nil && !t14InList(objStr(row, "axis"), axisFilter.Axes) {
				continue
			}
			d := objAt(dispositions, objStr(row, "row_id"))
			rows = append(rows, validation.VObj(
				validation.KV{K: "row_id", V: objAt(row, "row_id")},
				validation.KV{K: "probe", V: objAt(row, "probe")},
				validation.KV{K: "axis", V: objAt(row, "axis")},
				validation.KV{K: "lens", V: objAt(row, "lens")},
				validation.KV{K: "tier", V: objAt(row, "tier")},
				validation.KV{K: "rank", V: objAt(row, "rank")},
				validation.KV{K: "assertion_gap", V: objAt(row, "assertion_gap")},
				validation.KV{K: "anchors", V: strListValue(probes.RowAnchorPairs(row, index))},
				validation.KV{K: "priority_id", V: objAt(d, "priority_id")},
				validation.KV{K: "status", V: objAt(d, "status")},
				validation.KV{K: "dispositioned", V: validation.VBool(objBool(d, "dispositioned"))},
				validation.KV{K: "reason", V: objAt(d, "reason")},
				validation.KV{K: "anchor", V: objAt(d, "anchor")}))
		}
		axes := []validation.Value{}
		for _, ax := range t14List(*surface, "axes").A {
			if axisFilter != nil && !t14InList(objStr(ax, "axis"), axisFilter.Axes) {
				continue
			}
			axes = append(axes, ax)
		}
		t14PrintJSON(r.Out, validation.VObj(
			validation.KV{K: "campaign_id", V: objAt(*surface, "campaign_id")},
			validation.KV{K: "index_sha", V: objAt(*surface, "index_sha")},
			validation.KV{K: "current_index_sha", V: objAt(*summary, "current_index_sha")},
			validation.KV{K: "stale", V: objAt(*summary, "stale")},
			validation.KV{K: "rows", V: objAt(*summary, "rows")},
			validation.KV{K: "dispositioned", V: objAt(*summary, "dispositioned")},
			validation.KV{K: "open", V: objAt(*summary, "open")},
			validation.KV{K: "axes", V: validation.VArr(axes...)},
			validation.KV{K: "surface_rows", V: validation.VArr(rows...)}))
		return nil
	}
	stale := ""
	if objBool(*summary, "stale") {
		stale = " — stale?"
	}
	fmt.Fprintf(r.Out, "probe surface: %d rows (%d dispositioned, %d open)%s\n",
		objInt(*summary, "rows"), objInt(*summary, "dispositioned"),
		objInt(*summary, "open"), stale)
	for _, line := range probeAxisLines(*surface, axisFilter, a.all) {
		fmt.Fprintln(r.Out, line)
	}
	for _, line := range probeWarningLines(*surface) {
		fmt.Fprintln(r.Out, line)
	}
	for _, row := range t14List(*surface, "rows").A {
		if axisFilter != nil && !t14InList(objStr(row, "axis"), axisFilter.Axes) {
			continue
		}
		d := objAt(dispositions, objStr(row, "row_id"))
		stateStr := "open (not emitted)"
		switch {
		case objBool(d, "dispositioned"):
			stateStr = "dispositioned"
		case objStr(d, "status") != "" && objStr(d, "status") != "open":
			stateStr = "open (" + objStr(d, "status") + ")"
		case objStr(d, "priority_id") != "":
			stateStr = "open"
		}
		prio := objStr(d, "priority_id")
		if prio == "" {
			prio = "—"
		}
		anchors := strings.Join(probes.RowAnchorPairs(row, index), ", ")
		if anchors == "" {
			anchors = "—"
		}
		fmt.Fprintf(r.Out, "    %s rank %d tier %d gap %d %s — %s %s\n",
			objStr(row, "row_id"), objInt(row, "rank"), objInt(row, "tier"),
			objInt(row, "assertion_gap"), anchors, prio, stateStr)
		if reason := objStr(d, "reason"); reason != "" {
			fmt.Fprintf(r.Out, "        reason: %s\n", reason)
		}
	}
	t29PrintProbeClosure(c, planPtr, nil, false, r.Out)
	return nil
}

// t29PrintProbeClosure is _print_probe_closure (cmd_answered.go owns the
// only_closed=True call site; `probes list` needs only_closed=False).
func t29PrintProbeClosure(c *state.Campaign, plan *validation.Value,
	lensNames map[string]struct{}, onlyClosed bool, w io.Writer) {
	planVal := validation.VNull()
	if plan != nil {
		planVal = *plan
	}
	div, err := planner.DivergenceStatusFor(c, planVal, nil)
	if err != nil {
		return // never break a disposition on this
	}
	for _, entry := range t14List(div, "lenses").A {
		probe := objAt(entry, "probe")
		if probe.Kind != validation.Obj || objStr(probe, "message") == "" {
			continue
		}
		if lensNames != nil {
			_, a := lensNames[objStr(entry, "lens")]
			_, b := lensNames[objStr(entry, "id")]
			if !a && !b {
				continue
			}
		}
		if onlyClosed && !t14Truthy(objAt(probe, "closed")) {
			continue
		}
		fmt.Fprintf(w, "%s\n", objStr(probe, "message"))
	}
}

// t29AxisNames is `", ".join(PB.registered_axes())`.
func t29AxisNames() []string {
	return sortedStringsOf(probes.RegisteredAxes())
}

// t29LensIDs is `sorted({m["lens"] for m in registered_axes().values()})`.
func t29LensIDs() []string {
	seen := map[string]struct{}{}
	for _, meta := range probes.RegisteredAxes() {
		seen[meta.Lens] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringsOf(m map[string]probes.AxisMeta) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// probesBlank is cli.py _probes_blank.
func probesBlank(a *probesArgs, c *state.Campaign, r *Runner) error {
	entry, err := probes.SetBlank(c, *a.axis, *a.anchorBlind, *a.reason, *a.actor)
	if err != nil {
		return t14ExitErr(2, "probes blank: %v\n", err)
	}
	fmt.Fprintf(r.Out, "blank attestation recorded: %s cites %s (actor %s) — "+
		"`webv2 brief %s` now sees the axis attested\n", objStr(entry, "axis"),
		validation.PyReprStr(objStr(entry, "anchor_blind")),
		objStr(entry, "actor"), c.CampaignID)
	return nil
}

// t29Trunc is s[:n].
func t29Trunc(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

func t29FileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func strListValue(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

func objBool(v validation.Value, key string) bool {
	got := objAt(v, key)
	return got.Kind == validation.Bool && got.B
}

func init() {
	register(command{ord: 36, name: "probes",
		line: `probes <campaign> [run|list|blank]  the mechanical candidate surface`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runProbes(root, args, r)
			})
		}})
}
