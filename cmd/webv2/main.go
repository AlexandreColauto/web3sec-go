// Command webv2 is the P0 trust-core CLI: init/status/snap/log/audit/
// verify over filesystem-backed campaigns. All output flows through the
// cli Runner's writers; main only maps the exit code.
package main

import (
	"os"

	"websec/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
