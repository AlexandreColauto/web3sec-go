// Subprocess seam: subprocess.run with capture + timeout over the shared
// procResult shape, and Python's argv repr for its timeout error.
package envgo

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"websec/internal/validation"
)

// procResult is subprocess.CompletedProcess for the probes here.
type procResult struct {
	ReturnCode int
	Stdout     string
	Stderr     string
}

// realRunProc is subprocess.run(argv, capture_output=True, text=True,
// timeout=t). A timeout is reported as an error (Python's TimeoutExpired,
// a SubprocessError subclass the probes catch).
func realRunProc(argv []string, timeout time.Duration) (procResult, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	var out, errB strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errB
	// r21 F5 (third sibling of the pipe-hold): docker IS a shell shim;
	// killing only the direct child left its daemon-side child holding
	// the pipe and `<-done` hung — the "timeout" never fired. Own
	// process group, group kill, bounded grace, and the grace arm
	// returns EMPTY rather than racing the Builders.
	setProcGroup(cmd)
	if err := cmd.Start(); err != nil {
		return procResult{Stdout: out.String(), Stderr: errB.String()}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		res := procResult{ReturnCode: cmd.ProcessState.ExitCode(),
			Stdout: out.String(), Stderr: errB.String()}
		if err != nil {
			// A non-zero exit is data, not an error, in Python.
			if _, ok := err.(*exec.ExitError); !ok {
				return res, err
			}
		}
		return res, nil
	case <-time.After(timeout):
		killGroup(cmd)
		grace := time.NewTimer(5 * time.Second)
		defer grace.Stop()
		waited := false
		select {
		case <-done:
			waited = true
		case <-grace.C:
		}
		if !waited {
			return procResult{}, fmt.Errorf("Command %s timed out after "+
				"%d seconds", pyArgvRepr(argv), int(timeout.Seconds()))
		}
		return procResult{Stdout: out.String(), Stderr: errB.String()},
			fmt.Errorf("Command %s timed out after %d seconds",
				pyArgvRepr(argv), int(timeout.Seconds()))
	}
}

// pyArgvRepr is Python's repr of the argv list inside TimeoutExpired.
func pyArgvRepr(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, validation.PyReprStr(a))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
