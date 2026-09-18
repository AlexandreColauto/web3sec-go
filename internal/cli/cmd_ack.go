package cli

// cmd_ack: `webv2 ack <campaign> [finding]` — the A2 in-code
// acknowledgement scan: does the pinned source around the finding's anchors
// carry an owner comment marking the code as stub / placeholder / not implemented /
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
	"websec/internal/validation"

	"websec/internal/findings"
	"websec/internal/state"
)

const ackUsage = `usage: webv2 ack [-h] campaign [finding]
`

func runAck(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return ackCmd(root, args, r) })
}

// ackParseArgs splits the raw argv into positionals, reproducing argparse's
// required-then-unknown order.
func ackParseArgs(args []string) ([]string, error) {
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
		return nil, t14ArgparseErr(ackUsage, "ack",
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
		return nil, t14Unrecognized(strings.Join(toks, " "))
	}
	return pos, nil
}

// ackScan carries the open campaign and the output runner the ack scan and
// its printing read through.
type ackScan struct {
	c *state.Campaign
	r *Runner
}

// scan runs one finding's in-code acknowledgement scan.
func (a *ackScan) scan(fid string) (ackLine, error) {
	hit, err := findings.RecordAckScan(a.c, fid)
	if err != nil {
		// missing finding: the generic handler (exit 1).
		if _, lerr := findings.LoadFinding(a.c, fid); lerr != nil {
			return ackLine{}, lerr
		}
		// scannability problem: skip with the reason
		return ackLine{fid: fid, skip: err.Error()}, nil
	}
	f, lerr := findings.LoadFinding(a.c, fid)
	if lerr != nil {
		return ackLine{}, lerr
	}
	line := ackLine{fid: fid}
	if hit {
		ack := validation.ObjAt(validation.ObjAt(f, "dedup_meta"), "in_code_ack")
		line.hit = true
		line.file = validation.ObjStr(ack, "file")
		line.lineNo = int(validation.ObjAt(ack, "line").I)
		line.phrase = validation.ObjStr(ack, "phrase")
	}
	return line, nil
}

// print renders one scan line (skipped / ack / clean).
func (a *ackScan) print(line ackLine) {
	switch {
	case line.skip != "":
		fmt.Fprintf(a.r.Out, "%s: skipped — %s\n", line.fid, line.skip)
	case line.hit:
		fmt.Fprintf(a.r.Out, "%s: ack — %s:%d %q (window ±%d)\n",
			line.fid, line.file, line.lineNo, line.phrase,
			findings.AckWindow)
	default:
		fmt.Fprintf(a.r.Out, "%s: clean — no in-code acknowledgement "+
			"in window\n", line.fid)
	}
}

// scanAll scans every live finding and prints the per-finding lines plus the
// summary.
func (a *ackScan) scanAll() error {
	nAck, nClean, nSkip := 0, 0, 0
	all, err := findings.LoadLiveFindings(a.c)
	if err != nil {
		return err
	}
	for _, f := range all {
		line, err := a.scan(validation.ObjStr(f, "finding_id"))
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
		a.print(line)
	}
	fmt.Fprintf(a.r.Out, "%d findings: %d ack, %d clean, %d skipped\n",
		len(all), nAck, nClean, nSkip)
	return nil
}

func ackCmd(root string, args []string, r *Runner) error {
	if helpRequested(r.Out, "ack", args) {
		return nil
	}

	ensureSeams()
	pos, err := ackParseArgs(args)
	if err != nil {
		return err
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	sc := &ackScan{c: c, r: r}
	if len(pos) == 2 {
		line, err := sc.scan(pos[1])
		if err != nil {
			return err
		}
		sc.print(line)
		return nil
	}
	return sc.scanAll()
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
