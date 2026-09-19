package cli

// cmd_anchors: `webv2 anchors <campaign> <pattern>` — the B8 query verb over
// the B7 read-side code-anchor join (internal/anchorlink).
//
// WHY THIS VERB (feedback-triage-morph-r2 §B8, = review A9). The round-1
// campaign missed both gold shapes because the three stores that each name
// the same code — probe_surface rows, plan priorities, findings — were only
// ever read one at a time, and nothing in the CLI ever put them side by side.
// `anchors` is the "at which stage is this asserted?" reminder machine: it
// takes one code anchor (a path, optionally `#function` and `:line`), asks
// anchorlink.Query which members of each store name it, and prints them
// grouped by store with the row's disposition and the priority's status and
// risk. When a surface row and a priority (or a finding) co-name the code,
// the run ends with the L-03 enforcement-timing question on STDERR — the
// question the stores conspired to hide.
//
// THE ACT COMMAND (§B8: a member is listed "with its disposition/status and
// the command to act on it"). Every member that still has something to do
// carries the SMALLEST command that does it, on a wrapped next line: an OPEN
// priority is answered directly; an UNDISPOSITIONED surface row a priority
// claims through probe.row_id is answered through that priority — which is
// where answered's required --anchor lives — with the anchor field read off
// the row's own data; a row no priority claims is not yet a plan obligation,
// so its command is the emit that creates one. A dispositioned row, an empty
// group and the findings group (a filed finding is not an unanswered
// obligation this verb can discharge) print no command. The command text is
// the pending verb's own renderer (pendingCommand/pendingAnchorRef), so the
// two worklists cannot disagree about what an obligation costs.
//
// SCOPE. This verb consumes the seam read-only: it opens a campaign, decodes
// four artifacts and calls anchorlink.Open/Index/Query. It writes nothing,
// mutates nothing and never re-derives a row shape. Two artifacts are
// REQUIRED and their absence is a refusal at exit 2 with a heal line naming
// the command that produces them (`webv2 model`, `webv2 index` + `webv2
// probes run`); the plan and the findings store are tolerated ABSENT (a
// campaign may legitimately have neither yet) but an artifact that is present
// and unparseable is always a refusal — the r43a discipline, so an unreadable
// store never reads as "no members". A pattern that matches nothing is NOT a
// refusal: exit 0 with three empty groups, because "nothing names this code"
// is the answer to the question, not a failure to answer it.
//
// BYTE DISCIPLINE. `anchors` is a NEW verb, so its stdout is new bytes and no
// existing line moves; the only stderr it writes is the single lens line (and
// the refusals). Nothing here touches a golden-pinned surface.
//
// §B8's fourth store — "invariant-link" (invariant_links.json) — is NOT
// rendered: internal/anchorlink exports no invariant-link join (its store
// vocabulary is exactly surface/plan/findings), and this package owns no file
// that could add one. Flagged in the package report as a seam gap.

import (
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"websec/internal/anchorlink"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

// The four artifact file names this verb reads, named once: the heal lines
// quote them back to the operator.
const (
	anchorsModelArtifact   = "protocol_model.json"
	anchorsSurfaceArtifact = "probe_surface.json"
	anchorsPlanArtifact    = "campaign_plan.json"
)

const anchorsUsage = `usage: webv2 anchors [-h] campaign pattern
`

const anchorsHelp = anchorsUsage + `
ask which of a campaign's stores name one code anchor, grouped by store: the
surface rows, the OPEN plan priorities and the findings that cite it. When
rows and priorities (or rows and findings) name the same code, the run ends
with the enforcement-timing question (lens L-03) on stderr — the question the
round-1 surface/disposition miss failed to ask.

positional arguments:
  campaign      campaign id, e.g. C-xxxxxxxxxx
  pattern       the code anchor to ask about: a path, optionally qualified by
                a function and a line. Every accepted form:
                  Rollup.sol                   a basename
                  rollup/Rollup.sol            a directory tail
                  l1/rollup/Rollup.sol         the full model path
                  Rollup.sol#commitBatch       path#function
                  Rollup.sol#commitBatch:204   path#function:line
                  l1/rollup/Rollup.sol:204     path:line
                the path part matches at a segment boundary, so a basename, a
                directory tail and the full model path all reach the same
                rows; the function and line qualifiers narrow the surface rows
                and the findings. Priorities carry no function coordinates, so
                a function-qualified query still lists the OPEN priorities
                that name its path.

options:
  -h, --help    show this help message and exit
`

// anchorsTitleCap bounds the finding-title column of the findings group. The
// id is the addressable member; the title is the recognition cue, so it is
// cut rather than allowed to run a console line to several hundred columns
// (the morph titles do). A truncated title ends in an ellipsis, so a reader
// can always tell the difference between a short title and a cut one.
const anchorsTitleCap = 96

func runAnchors(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return anchorsCmd(root, args, r)
	})
}

// anchorsCmd is the whole verb: argparse-shaped parse, then load, query and
// render. A valid campaign and a valid pattern always exit 0.
func anchorsCmd(root string, args []string, r *Runner) error {
	campaign, pattern, seen := "", "", 0
	for _, a := range args {
		switch {
		case a == "-h" || a == "--help":
			// argparse answers help before it validates anything (the
			// helpRequested convention, cli.go:224); this verb's block is its
			// own constant, so it prints it inline like cmd_schema.go:58.
			fmt.Fprint(r.Out, anchorsHelp)
			return nil
		case strings.HasPrefix(a, "-"):
			return t14Unrecognized(a)
		default:
			switch seen {
			case 0:
				campaign = a
			case 1:
				pattern = a
			default:
				// argparse reports the surplus positionals through the ROOT
				// parser, which is what t14Unrecognized renders.
				return t14Unrecognized(a)
			}
			seen++
		}
	}
	missing := []string{}
	if campaign == "" {
		missing = append(missing, "campaign")
	}
	if pattern == "" {
		missing = append(missing, "pattern")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(anchorsUsage, "anchors",
			"the following arguments are required: %s", strings.Join(missing, ", "))
	}
	c, err := t14Open(root, campaign)
	if err != nil {
		// §B8: a missing campaign refuses at 2 (not the generic exit-1 mapper)
		// and heals by naming the verb that lists campaigns.
		return t14ExitErr(2, "anchors: %v — check the id with `webv2 status %s`, "+
			"or run `webv2 init` for a new campaign\n", err, campaign)
	}
	st, err := anchorsLoad(c)
	if err != nil {
		return err
	}
	m := st.s.Query(pattern)
	anchorsPrint(r.Out, pattern, st, m)
	if line, ok := anchorsLensLine(st, m); ok {
		fmt.Fprint(r.Err, line)
	}
	return nil
}

// anchorsStore is the decoded campaign store set: the three member slices the
// seam indexes, plus id→value lookups so the render can print a priority's
// status/risk and a finding's title without re-walking the artifacts.
type anchorsStore struct {
	c          *state.Campaign
	s          *anchorlink.Store
	rows       []validation.Value
	priorities []validation.Value
	findings   []validation.Value
	rowByID    map[string]validation.Value
	prioByID   map[string]validation.Value
	findByID   map[string]validation.Value
}

// anchorsLoad decodes protocol_model.json, probe_surface.json, the plan and
// the findings store, and wires the seam. See the file header for the
// required/optional split.
func anchorsLoad(c *state.Campaign) (*anchorsStore, error) {
	modelPath := artifactPath(c, anchorsModelArtifact)
	if !t14Exists(modelPath) {
		return nil, t14ExitErr(2, "anchors: no protocol model for %s (%s) — "+
			"run `webv2 model %s model.json` first\n", c.CampaignID, modelPath,
			c.CampaignID)
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return nil, t14ExitErr(2, "anchors: unreadable %s (%v) — rebuild it "+
			"with `webv2 model %s model.json`\n", modelPath, err, c.CampaignID)
	}
	s, err := anchorlink.Open(model)
	if err != nil {
		return nil, t14ExitErr(2, "anchors: %v (%s) — rebuild it with "+
			"`webv2 model %s model.json`\n", err, modelPath, c.CampaignID)
	}
	surfacePath := artifactPath(c, anchorsSurfaceArtifact)
	surface, err := probes.CampaignSurface(c)
	if err != nil {
		return nil, t14ExitErr(2, "anchors: unreadable %s (%v) — rebuild it "+
			"with `webv2 index %s --src <target>` then `webv2 probes %s run`\n",
			surfacePath, err, c.CampaignID, c.CampaignID)
	}
	if surface == nil {
		return nil, t14ExitErr(2, "anchors: no probe surface for %s — run "+
			"`webv2 index %s --src <target>` then `webv2 probes %s run` first\n",
			c.CampaignID, c.CampaignID, c.CampaignID)
	}
	st := &anchorsStore{
		c:        c,
		rows:     t14List(*surface, "rows").A,
		rowByID:  map[string]validation.Value{},
		prioByID: map[string]validation.Value{},
		findByID: map[string]validation.Value{},
	}
	// The plan is loaded directly rather than through
	// planner.LoadPlanReadonly: that helper folds "no plan artifact" and
	// "unparseable plan artifact" into one error, and this verb must tolerate
	// the first (a campaign with no plan yet has no priorities) while
	// refusing the second.
	if planPath := artifactPath(c, anchorsPlanArtifact); t14Exists(planPath) {
		plan, err := validation.ReadJson(planPath)
		if err != nil {
			return nil, t14ExitErr(2, "anchors: unreadable %s (%v) — repair "+
				"it, or rebuild it with `webv2 plan %s <plan.json>`\n",
				planPath, err, c.CampaignID)
		}
		st.priorities = t14List(plan, "priorities").A
	}
	paths, err := validation.ListPrefixedOptional(c.FindingsDir, "F-", ".json")
	if err != nil {
		return nil, t14ExitErr(2, "anchors: the findings store %s cannot be "+
			"listed: %v\n", c.FindingsDir, err)
	}
	for _, p := range paths {
		f, err := validation.ReadJson(p)
		if err != nil {
			return nil, t14ExitErr(2, "anchors: unreadable finding %s (%v) — "+
				"repair it, or re-file it with `webv2 ingest %s --json-file "+
				"%s`\n", p, err, c.CampaignID, p)
		}
		st.findings = append(st.findings, f)
	}
	for _, r := range st.rows {
		st.rowByID[validation.ObjStr(r, "row_id")] = r
	}
	for _, p := range st.priorities {
		st.prioByID[validation.ObjStr(p, "id")] = p
	}
	for _, f := range st.findings {
		st.findByID[validation.ObjStr(f, "finding_id")] = f
	}
	st.s = s.Index(st.rows, st.priorities, st.findings)
	return st, nil
}

// artifactPath is filepath.Join(c.ArtifactsDir, name) — the artifacts this
// verb reads live in the one directory, so the join is named once.
func artifactPath(c *state.Campaign, name string) string {
	return filepath.Join(c.ArtifactsDir, name)
}

// anchorsPrint renders the three groups. Every match the seam returned is
// printed (a query answer is an obligation list, not a transcript to cap),
// and an empty group says so rather than vanishing: "no priority names this
// code" is a fact the operator needs to see.
func anchorsPrint(w io.Writer, pattern string, st *anchorsStore,
	m anchorlink.Matches) {
	fmt.Fprintf(w, "anchors: %s — %d surface rows, %d open priorities, "+
		"%d findings\n", pattern, len(m.Rows), len(m.Priorities), len(m.Findings))
	anchorsPrintRows(w, st, m)
	anchorsPrintPriorities(w, st, m)
	anchorsPrintFindings(w, st, m)
}

// anchorsPrintCommand renders one member's discharge command on a wrapped next
// line: a row line already carries up to five columns, and appending a whole
// command to it would run the line past the width anchorsTitleCap exists to
// protect. The `-> ` marker is the pending verb's own (pendingTable), so the
// two worklists read alike.
func anchorsPrintCommand(w io.Writer, cmd string) {
	fmt.Fprintf(w, "    -> %s\n", cmd)
}

// anchorsPrintRows is the SURFACE ROWS group: row_id, tier, disposition (or
// UNDISPOSITIONED) and the row's own consumer/asserter/sibling sites, spelled
// exactly as the surface artifact spells them. The canonical model paths the
// seam resolves for the row (RowTargets) are printed alongside, because the
// query pattern may have been a basename: the resolved path is the key the
// other two stores were joined on.
func anchorsPrintRows(w io.Writer, st *anchorsStore, m anchorlink.Matches) {
	fmt.Fprintln(w, "surface rows:")
	if len(m.Rows) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	for _, rm := range m.Rows {
		row := st.rowByID[rm.RowID]
		stateStr := "UNDISPOSITIONED"
		if rm.Dispositioned {
			stateStr = rm.Disposition
		}
		fmt.Fprintf(w, "  %s  tier %d  %s", rm.RowID, rm.Tier, stateStr)
		if paths, _ := st.s.RowTargets(row); len(paths) > 0 {
			fmt.Fprintf(w, "  paths %s", strings.Join(paths, ", "))
		}
		for _, site := range anchorsSites(row) {
			fmt.Fprintf(w, "  %s %s", site.kind, site.text)
		}
		fmt.Fprintln(w)
		if cmd := st.rowCommand(row, rm); cmd != "" {
			anchorsPrintCommand(w, cmd)
		}
	}
}

// anchorsPrintPriorities is the OPEN PRIORITIES group: id, status, risk.
func anchorsPrintPriorities(w io.Writer, st *anchorsStore,
	m anchorlink.Matches) {
	fmt.Fprintln(w, "open priorities:")
	if len(m.Priorities) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	for _, id := range m.Priorities {
		p := st.prioByID[id]
		status := validation.ObjStr(p, "status")
		if status == "" {
			// priorityOpen reads a missing status as open (query.go:272);
			// print the same reading rather than an empty column.
			status = "open"
		}
		fmt.Fprintf(w, "  %s  %s  risk %s\n", id, status,
			anchorsRiskText(validation.ObjAt(p, "risk")))
		anchorsPrintCommand(w, st.priorityCommand(p))
	}
}

// rowCommand is the smallest command that discharges ONE surface row: a row a
// priority claims through probe.row_id is dispositioned THROUGH that priority
// (the claim is a probe row, so answered requires the --anchor field it claims
// is safe — checkProbeAnchor refuses the closure without one), and the anchor
// is read off the row's own data by the pending verb's own selector. A row no
// priority claims is not yet a plan obligation, so its smallest acting command
// is the emit that turns the surface into one. A row already dispositioned has
// nothing left to act on and gets no command at all.
//
// The command text comes from pendingCommand — the renderer `probes <c>
// pending` uses for the same obligation — so the two verbs cannot drift.
func (st *anchorsStore) rowCommand(row validation.Value,
	rm anchorlink.RowMatch) string {
	if rm.Dispositioned {
		return ""
	}
	claim := hintClaimID(st.priorities, rm.RowID)
	if claim == "" {
		return fmt.Sprintf("webv2 probes %s run --emit", st.c.CampaignID)
	}
	anchor, _ := pendingAnchorRef(row, nil)
	return pendingCommand(st.c.CampaignID,
		pendingRow{priorityID: claim, anchor: anchor})
}

// priorityCommand is the smallest command that discharges ONE listed priority:
// answer it, with a reason. Every listed priority is OPEN (the seam's
// open-only rule), so the command is never empty. A priority that carries a
// probe row is a probe disposition, and answered REFUSES that closure without
// the --anchor field the row's probe produces (checkProbeAnchor), so it
// renders the pending verb's shape — byte for byte the command the claimed
// row's own line renders, because it is the same obligation. A
// question-priority (no probe row) has no anchor to name and renders the shape
// the B9 hint prints for it (hintLine): the reason placeholder is operator
// prose either way, and the two agree.
func (st *anchorsStore) priorityCommand(p validation.Value) string {
	id := validation.ObjStr(p, "id")
	rowID := validation.ObjStr(validation.ObjAt(p, "probe"), "row_id")
	if rowID == "" {
		return fmt.Sprintf("webv2 answered %s %s answered --reason '<why>'",
			st.c.CampaignID, id)
	}
	anchor, _ := pendingAnchorRef(st.rowByID[rowID], nil)
	return pendingCommand(st.c.CampaignID,
		pendingRow{priorityID: id, anchor: anchor})
}

// anchorsRiskText renders the priority's risk, or an em dash when the
// artifact records none (a missing risk is not the number zero).
func anchorsRiskText(v validation.Value) string {
	switch v.Kind {
	case validation.Int, validation.Flt:
		return scalarStr(v)
	}
	return "—"
}

// anchorsPrintFindings is the FINDINGS group: id and the (capped) title.
func anchorsPrintFindings(w io.Writer, st *anchorsStore, m anchorlink.Matches) {
	fmt.Fprintln(w, "findings:")
	if len(m.Findings) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	for _, id := range m.Findings {
		title := anchorsTitle(validation.ObjStr(st.findByID[id], "title"))
		if title == "" {
			fmt.Fprintf(w, "  %s\n", id)
			continue
		}
		fmt.Fprintf(w, "  %s  %s\n", id, title)
	}
}

// anchorsTitle caps a finding title at anchorsTitleCap runes, marking the cut
// with an ellipsis.
func anchorsTitle(s string) string {
	runes := []rune(s)
	if len(runes) <= anchorsTitleCap {
		return s
	}
	return string(runes[:anchorsTitleCap]) + "…"
}

// anchorsSite is one rendered code coordinate of a surface row.
type anchorsSite struct {
	kind string // consumer, asserter or sibling
	text string
}

// anchorsSites is the row's coordinates in the seam's own order — the
// contract plus its consumer, its asserter, then each sibling — spelled as
// `<contract>#<function>:<line>` (the line and the function are dropped when
// the row carries none). This is the row's raw spelling, deliberately NOT
// path-resolved: a contract NAME the model carries on several paths has no
// single canonical path, and inventing one would be exactly the basename
// collision the seam's collision rule exists to prevent. The resolved paths
// ride the row line instead (anchorsPrintRows).
//
// A sibling that repeats the consumer's or the asserter's own coordinate is
// dropped: the probes that carry siblings usually name the very site they
// compare against, and printing it twice tells the operator nothing.
func anchorsSites(row validation.Value) []anchorsSite {
	out := []anchorsSite{}
	contract := validation.ObjStr(row, "contract")
	// The consumer's and the asserter's own line numbers, so a sibling that
	// repeats either coordinate can be dropped below.
	consumerFn := validation.ObjStr(row, "consumer")
	consumerLine := objInt(row, "consumer_line")
	asserterFn := validation.ObjStr(row, "asserter")
	asserterLine := objInt(row, "asserter_line")
	if consumerFn != "" {
		out = append(out, anchorsSite{"consumer",
			anchorsFnSite(contract, consumerFn, consumerLine)})
	}
	if asserterFn != "" {
		out = append(out, anchorsSite{"asserter",
			anchorsFnSite(contract, asserterFn, asserterLine)})
	}
	for _, sib := range t14List(row, "siblings").A {
		name := validation.ObjStr(sib, "contract")
		if name == "" {
			continue
		}
		line := objInt(sib, "line")
		if name == contract &&
			((consumerFn != "" && line == consumerLine) ||
				(asserterFn != "" && line == asserterLine)) {
			continue
		}
		out = append(out, anchorsSite{"sibling", anchorsLineSite(name, line)})
	}
	return out
}

// anchorsFnSite is `<contract>#<function>[:line]`; a row that names no
// contract (a bare function site) renders as the function alone.
func anchorsFnSite(contract, fn string, line int64) string {
	if contract == "" {
		return fn + anchorsLineSuffix(line)
	}
	return contract + "#" + fn + anchorsLineSuffix(line)
}

// anchorsLineSite is `<contract>[:line]` — a sibling carries no function.
func anchorsLineSite(contract string, line int64) string {
	return contract + anchorsLineSuffix(line)
}

// anchorsLineSuffix is ":<line>", or nothing when the row carries no line
// (a coordinate the artifact omitted must not print as ":0").
func anchorsLineSuffix(line int64) string {
	if line <= 0 {
		return ""
	}
	return ":" + strconv.FormatInt(line, 10)
}

// anchorsLensLine is the L-03 enforcement-timing question (§B8): the one
// stderr line the run appends when a surface row AND a priority (or a
// finding) co-name the queried code — the convergence the round-1 miss never
// saw because no verb showed the two stores together.
//
// It fires at most once per run (the first matched row that carries both an
// asserting and a consuming site), and the question names that row's own
// assertion: `gate` is the assertion the surface named, falling back to the
// probe id. The asserting site is the row's asserter when it has one, else
// the row's `base` (the forward-path contract the custody row compares
// against), else its first sibling; the consuming site is the row's
// consumer. A matched row with no such pair poses no question, so a run whose
// rows are bare path citations appends nothing.
func anchorsLensLine(st *anchorsStore, m anchorlink.Matches) (string, bool) {
	if len(m.Rows) == 0 || (len(m.Priorities) == 0 && len(m.Findings) == 0) {
		return "", false
	}
	for _, rm := range m.Rows {
		row := st.rowByID[rm.RowID]
		assertAt, okA := anchorsAssertSite(row)
		consumeAt, okC := anchorsConsumeSite(row)
		if !okA || !okC {
			continue
		}
		x := validation.ObjStr(row, "gate")
		if x == "" {
			x = validation.ObjStr(row, "probe")
		}
		if x == "" {
			x = "the assertion"
		}
		return fmt.Sprintf("the surface asserts %s at %s and consumes it at "+
			"%s — at which stage is it enforced? (lens L-03)\n", x, assertAt,
			consumeAt), true
	}
	return "", false
}

// anchorsAssertSite is where the row says its assertion is established.
func anchorsAssertSite(row validation.Value) (string, bool) {
	contract := validation.ObjStr(row, "contract")
	if fn := validation.ObjStr(row, "asserter"); fn != "" {
		return anchorsFnSite(contract, fn, objInt(row, "asserter_line")), true
	}
	if base := validation.ObjStr(row, "base"); base != "" {
		return anchorsLineSite(base, objInt(row, "base_line")), true
	}
	for _, sib := range t14List(row, "siblings").A {
		if name := validation.ObjStr(sib, "contract"); name != "" {
			return anchorsLineSite(name, objInt(sib, "line")), true
		}
	}
	return "", false
}

// anchorsConsumeSite is where the row says the assertion is consumed.
func anchorsConsumeSite(row validation.Value) (string, bool) {
	fn := validation.ObjStr(row, "consumer")
	if fn == "" {
		return "", false
	}
	return anchorsFnSite(validation.ObjStr(row, "contract"), fn,
		objInt(row, "consumer_line")), true
}

func init() {
	// ord 91: immediately after B1's `schema` (ord 90), so the two read-side
	// verbs added this wave sit together at the end of the catalog and no
	// existing verb is renumbered.
	register(command{ord: 91, name: "anchors",
		line: `anchors <campaign> <pattern>       ask which stores name one ` +
			`code anchor (surface, open priorities, findings)`,
		run: runAnchors})
}
