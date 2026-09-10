package cli

// cmd_status: `webv2 status <campaign> [--verbose]` — the orchestrator
// status dict as indent-2 JSON (cli.py cmd_status verbatim: always JSON,
// never canonical-sorted).
//
// The findings counts and coverage summary are read the way
// Orchestrator.status does: findings from findings/F-*.json (empty at
// P0), coverage from artifacts/coverage.json when present. Stage notes
// truncate at STATUS_NOTE_CAP (200) unless --verbose.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// statusNoteCap mirrors orchestrator.STATUS_NOTE_CAP.
const statusNoteCap = 200

func runStatus(root string, args []string, stdout io.Writer) error {
	if helpRequested(stdout, "status", args) {
		return nil
	}

	verbose := false
	var pos []string
	for _, a := range args {
		switch {
		case a == "--verbose":
			verbose = true
		case strings.HasPrefix(a, "-"):
			return usageErrf("unrecognized arguments: %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return usageErrf("status requires exactly one <campaign> argument")
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	st, err := c.State()
	if err != nil {
		return err
	}
	findings, err := statusFindings(c)
	if err != nil {
		return err
	}
	coverage, err := statusCoverage(c)
	if err != nil {
		return err
	}
	status := validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "program", V: objAt(st, "program")},
		validation.KV{K: "phase", V: objAt(st, "phase")},
		validation.KV{K: "pass", V: objAt(objAt(st, "budget"), "pass")},
		validation.KV{K: "active_snapshot", V: objAt(st, "active_snapshot_id")},
		validation.KV{K: "findings", V: findings},
		validation.KV{K: "coverage_summary", V: coverage},
		validation.KV{K: "stages", V: statusStages(st, verbose)},
	)
	fmt.Fprintln(stdout, prettyASCII(status))
	return nil
}

// statusFindings mirrors the counts loop of Orchestrator.status: findings
// ordered by (created_at, finding_id), counts in first-appearance order.
func statusFindings(c *state.Campaign) (validation.Value, error) {
	paths, err := filepath.Glob(filepath.Join(c.FindingsDir, "F-*.json"))
	if err != nil {
		return validation.VNull(), err
	}
	type row struct {
		created, fid, status string
	}
	var rows []row
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return validation.VNull(), err
		}
		f, err := validation.ParseOrdered(raw)
		if err != nil {
			return validation.VNull(), err
		}
		rows = append(rows, row{objStr(f, "created_at"), objStr(f, "finding_id"), objStr(f, "status")})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].created != rows[j].created {
			return rows[i].created < rows[j].created
		}
		return rows[i].fid < rows[j].fid
	})
	var counts []validation.KV
	index := map[string]int{}
	for _, r := range rows {
		if r.status == "" {
			continue
		}
		if i, ok := index[r.status]; ok {
			counts[i].V = validation.VInt(counts[i].V.I + 1)
			continue
		}
		index[r.status] = len(counts)
		counts = append(counts, validation.KV{K: r.status, V: validation.VInt(1)})
	}
	if counts == nil {
		return validation.VObj(), nil
	}
	return validation.VObj(counts...), nil
}

// statusCoverage mirrors `read_json(coverage.json).get("summary", {})`.
func statusCoverage(c *state.Campaign) (validation.Value, error) {
	p := filepath.Join(c.ArtifactsDir, "coverage.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return validation.VObj(), nil
		}
		return validation.VNull(), err
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.VNull(), err
	}
	if s := objAt(doc, "summary"); s.Kind == validation.Obj {
		return s, nil
	}
	return validation.VObj(), nil
}

// statusStages copies the stages dict, truncating long notes to the
// display cap unless verbose (rune-wise, like Python's note[:200]).
func statusStages(st validation.Value, verbose bool) validation.Value {
	stages := objAt(st, "stages")
	if stages.Kind != validation.Obj {
		return validation.VObj()
	}
	out := make([]validation.KV, 0, len(stages.O))
	for _, kv := range stages.O {
		entry := kv.V
		if entry.Kind == validation.Obj {
			kvs := make([]validation.KV, len(entry.O))
			copy(kvs, entry.O)
			entry = validation.VObj(kvs...)
			if note := objAt(entry, "note"); note.Kind == validation.Str && !verbose {
				if n := runeLen(note.S); n > statusNoteCap {
					short := string([]rune(note.S)[:statusNoteCap]) + " …[truncated; use --verbose]"
					for i := range entry.O {
						if entry.O[i].K == "note" {
							entry.O[i].V = validation.VStr(short)
						}
					}
				}
			}
		}
		out = append(out, validation.KV{K: kv.K, V: entry})
	}
	return validation.VObj(out...)
}

func runeLen(s string) int {
	return len([]rune(s))
}

func init() {
	register(command{ord: 2, name: "status",
		line: "status <campaign> [--verbose]        campaign status (JSON)",
		run: func(root string, args []string, r *Runner) int {
			return r.withErr(root, func() error { return runStatus(root, args, r.Out) })
		}})
}
