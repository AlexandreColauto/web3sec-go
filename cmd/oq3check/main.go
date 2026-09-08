// oq3check — OQ3 checkpoint tool (Task 19): differential validator probe.
//
// Reads lines of "<schema-name>\t<doc-json>" on stdin and prints
// "VALID" or "INVALID" per line, using the exact same parse-and-
// validate path as the production code (validation.ParseOrdered +
// validation.Validate over the embedded schema assets). The Python
// orchestrator (scripts/oq3-check.py) feeds it the same (doc, schema)
// pairs it validates with jsonschema and compares the verdicts.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"websec/internal/validation"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	n := 0
	for in.Scan() {
		name, doc := splitTab(in.Text())
		if name == "" || doc == "" {
			fmt.Fprintln(os.Stderr, "malformed line")
			os.Exit(2)
		}
		v, err := validation.ParseOrdered([]byte(doc))
		if err != nil {
			// Unparseable JSON is INVALID on both sides; the Python
			// orchestrator never sends one, so this is defensive.
			fmt.Println("INVALID")
			n++
			continue
		}
		if err := validation.Validate(v, name, 1); err != nil {
			fmt.Println("INVALID")
		} else {
			fmt.Println("VALID")
		}
		n++
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
}

func splitTab(line string) (string, string) {
	parts := strings.SplitN(line, "\t", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
