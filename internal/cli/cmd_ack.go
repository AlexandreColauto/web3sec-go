package cli

// cmd_ack: `webv2 ack <campaign> [finding]` — the A2 in-code
// acknowledgement scan: does the pinned source around the finding's anchors
// carry an owner comment marking the code as stub / TODO / not implemented /
// placeholder? A hit records finding.dedup_meta.in_code_ack, which the gate
// advisory, the A3 acceptance score and the report quote all read.
//
// With no finding, every live finding is scanned (idempotent re-scan: a hit
// replaces the stored record, a clean scan clears one). A finding that has
// no source pin or no resolvable anchor is SKIPPED with the reason printed —
// never an error: the scan is advisory infrastructure, and an unpinned
// campaign simply has nothing to scan. A missing FINDING (or campaign)
// falls through to the generic handler (exit 1).

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
)

const ackUsage = `usage: webv2 ack [-h] campaign [finding]
`

func runAck(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return ackCmd(root, args, r) })
}

func ackCmd(root string, args []string, r *Runner) error {
	if helpRequested(r.Out, "ack", args) {
		return nil
	}

	ensureSeams()
	var pos []string
	var posIdx []int
	var unknown []immunizeUnk
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "-"):
			unknown = append(unknown, immunizeUnk{i, a})
		default:
			pos = append(pos, a)
			posIdx = append(posIdx, i)
		}
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(ackUsage, "ack",
			"the following arguments are required: %s", strings.Join(missing, ", "))
	}
	if len(pos) > 2 {
		for j, t := range pos[2:] {
			unknown = append(unknown, immunizeUnk{posIdx[2+j], t})
		}
		pos = pos[:2]
	}
	if len(unknown) > 0 {
		sort.Slice(unknown, func(i, j int) bool {
			return unknown[i].idx < unknown[j].idx
		})
		toks := make([]string, len(unknown))
		for i, u := range unknown {
			toks[i] = u.tok
		}
		return t14Unrecognized(strings.Join(toks, " "))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	scan := func(fid string) (ackLine, error) {
		hit, err := findings.RecordAckScan(c, fid)
		if err != nil {
			// missing finding: the generic handler (exit 1).
			if _, lerr := findings.LoadFinding(c, fid); lerr != nil {
				return ackLine{}, lerr
			}
			// scannability problem: skip with the reason
			return ackLine{fid: fid, skip: err.Error()}, nil
		}
		f, lerr := findings.LoadFinding(c, fid)
		if lerr != nil {
			return ackLine{}, lerr
		}
		line := ackLine{fid: fid}
		if hit {
			ack := objAt(objAt(f, "dedup_meta"), "in_code_ack")
			line.hit = true
			line.file = objStr(ack, "file")
			line.lineNo = int(objAt(ack, "line").I)
			line.phrase = objStr(ack, "phrase")
		}
		return line, nil
	}
	print := func(line ackLine) {
		switch {
		case line.skip != "":
			fmt.Fprintf(r.Out, "%s: skipped — %s\n", line.fid, line.skip)
		case line.hit:
			fmt.Fprintf(r.Out, "%s: ack — %s:%d %q (window ±%d)\n",
				line.fid, line.file, line.lineNo, line.phrase,
				findings.AckWindow)
		default:
			fmt.Fprintf(r.Out, "%s: clean — no in-code acknowledgement "+
				"in window\n", line.fid)
		}
	}
	if len(pos) == 2 {
		line, err := scan(pos[1])
		if err != nil {
			return err
		}
		print(line)
		return nil
	}
	nAck, nClean, nSkip := 0, 0, 0
	all, err := findings.LoadLiveFindings(c)
	if err != nil {
		return err
	}
	for _, f := range all {
		line, err := scan(objStr(f, "finding_id"))
		if err != nil {
			return err
		}
		switch {
		case line.skip != "":
			nSkip++
		case line.hit:
			nAck++
		default:
			nClean++
		}
		print(line)
	}
	fmt.Fprintf(r.Out, "%d findings: %d ack, %d clean, %d skipped\n",
		len(all), nAck, nClean, nSkip)
	return nil
}

type ackLine struct {
	fid    string
	hit    bool
	skip   string
	file   string
	lineNo int
	phrase string
}

func init() {
	register(command{ord: 69, name: "ack",
		line: "ack <campaign> [f]  scan the pinned source for in-code " +
			"acknowledgements (stub/TODO/...) around the finding",
		run: runAck})
}
