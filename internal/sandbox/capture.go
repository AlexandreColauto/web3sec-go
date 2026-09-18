// capture.go: capped output capture and the TRUE byte accounting of a
// run's stdout/stderr (r36 F6).
package sandbox

import (
	"bytes"
	"fmt"
	"websec/internal/validation"
)

// CaptureTotal is the true byte accounting of one capped capture (r36 F6).
type CaptureTotal struct {
	// Total is every byte the process wrote to the stream.
	Total int64
	// Kept is the number of bytes retained under the cap.
	Kept int64
}

// outputCaptureLimitBytes is the DELIBERATE cap on captured stdout/stderr,
// per stream (r36 F6: the exec path used to keep everything — a 200MB
// write put ~817MB peak RSS on webv2 with no truncation marker and no
// size accounting). 10MiB per stream (20MiB worst case) is far above any
// meaningful build/test log and keeps memory bounded. The TRUE byte counts
// and the truncation land in the record's `output_capture` object, and the
// in-file marker line means a truncated log can never pass as complete.
// A package var (not a const) so tests can lower it to stay fast; the
// recorded cap_bytes always reflects the value in force.
var outputCaptureLimitBytes int64 = 10 << 20

// cappedWriter captures at most limit bytes while COUNTING everything
// written: the child is never throttled or blocked, excess bytes are
// dropped from memory only.
type cappedWriter struct {
	limit int64
	buf   bytes.Buffer
	total int64
}

func newCappedWriter(limit int64) *cappedWriter { return &cappedWriter{limit: limit} }

func (w *cappedWriter) Write(p []byte) (int, error) {
	w.total += int64(len(p))
	if room := w.limit - int64(w.buf.Len()); room > 0 {
		if int64(len(p)) > room {
			w.buf.Write(p[:room])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil // dropping the excess is not an error for the child
}

func (w *cappedWriter) String() string { return w.buf.String() }

func (w *cappedWriter) cap() CaptureTotal {
	return CaptureTotal{Total: w.total, Kept: int64(w.buf.Len())}
}

// captureStats is the true byte accounting of one execution's captured
// output (r36 F6). Withheld means the bytes were never read (a live
// copier held them) — the totals are unknown, never zero.
type captureStats struct {
	StdoutTotal, StderrTotal int64
	StdoutKept, StderrKept   int64
	Withheld                 bool
}

func (c captureStats) stdoutTruncated() bool {
	return !c.Withheld && c.StdoutTotal > c.StdoutKept
}

func (c captureStats) stderrTruncated() bool {
	return !c.Withheld && c.StderrTotal > c.StderrKept
}

// capsOf maps a ProcResult's capture accounting; faked proc results carry
// no accounting, so the kept strings themselves become the totals (that
// IS what was captured).
func capsOf(res ProcResult) captureStats {
	caps := captureStats{
		StdoutTotal: res.StdoutCap.Total, StdoutKept: res.StdoutCap.Kept,
		StderrTotal: res.StderrCap.Total, StderrKept: res.StderrCap.Kept,
		Withheld: res.OutputWithheld,
	}
	if caps.StdoutTotal == 0 && caps.StdoutKept == 0 && res.Stdout != "" {
		caps.StdoutTotal, caps.StdoutKept =
			int64(len(res.Stdout)), int64(len(res.Stdout))
	}
	if caps.StderrTotal == 0 && caps.StderrKept == 0 && res.Stderr != "" {
		caps.StderrTotal, caps.StderrKept =
			int64(len(res.Stderr)), int64(len(res.Stderr))
	}
	return caps
}

// truncationMarker is the in-file truncation marker: a consumer reading
// stdout.log/stderr.log directly can never mistake a truncated capture
// for a complete one (r36 F6).
func truncationMarker(stream string, kept, total int64) []byte {
	return []byte(fmt.Sprintf(
		"\n[sandbox: %s TRUNCATED — kept the first %d of %d bytes (cap %d); "+
			"the record's output_capture carries the true counts]\n",
		stream, kept, total, outputCaptureLimitBytes))
}

// outputCaptureValue renders the additive `output_capture` object (r36
// F6): the deliberate cap, the TRUE byte counts, and whether any stream
// was truncated. When output was withheld (a live copier held it), the
// totals are null — absence, never a fabricated count.
func outputCaptureValue(caps captureStats) validation.Value {
	stdoutTotal := validation.VInt(caps.StdoutTotal)
	stderrTotal := validation.VInt(caps.StderrTotal)
	if caps.Withheld {
		stdoutTotal = validation.VNull()
		stderrTotal = validation.VNull()
	}
	return validation.VObj(
		validation.KV{K: "cap_bytes", V: validation.VInt(outputCaptureLimitBytes)},
		validation.KV{K: "stdout_total_bytes", V: stdoutTotal},
		validation.KV{K: "stdout_truncated", V: validation.VBool(caps.stdoutTruncated())},
		validation.KV{K: "stderr_total_bytes", V: stderrTotal},
		validation.KV{K: "stderr_truncated", V: validation.VBool(caps.stderrTruncated())},
		validation.KV{K: "output_withheld", V: validation.VBool(caps.Withheld)},
		validation.KV{K: "note", V: validation.VStr(
			"artifact_hashes cover exactly the stdout.log/stderr.log bytes " +
				"kept on disk (the capped payload plus, when truncated, the " +
				"marker line)")},
	)
}
