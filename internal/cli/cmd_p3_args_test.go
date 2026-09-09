package cli

// T25 argparse-parity tests: every entry in testdata/p3_args_golden.json was
// captured from the LIVE Python CLI (scripts mint them via
// .scratch/t25/gen_cli_golden.py) and pins exit code + stdout + stderr for
// the index/sinks/forkdiff/baseline argument surface: the help action,
// option-arity errors, missing-required ordering, unrecognized-argument
// ordering and the `--` separator's positional-absorption rule.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"websec/internal/forkdiff"
)

type p3ArgCase struct {
	Argv   []string `json:"argv"`
	Code   int      `json:"code"`
	Stdout string   `json:"stdout"`
	Stderr string   `json:"stderr"`
}

func TestP3ArgparseGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "p3_args_golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var cases []p3ArgCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(cases) < 50 {
		t.Fatalf("golden table looks truncated: %d cases", len(cases))
	}
	root := t.TempDir()
	prevBaselines := forkdiff.BaselinesDir
	forkdiff.SetBaselinesDir(filepath.Join(t.TempDir(), "baselines"))
	defer func() { forkdiff.BaselinesDir = prevBaselines }()
	for _, c := range cases {
		args := append([]string{"--root", root}, c.Argv...)
		code, out, errS := run(t, args...)
		if code != c.Code || out != c.Stdout || errS != c.Stderr {
			t.Errorf("argv %q\n got code=%d out=%q err=%q\nwant code=%d out=%q err=%q",
				c.Argv, code, out, errS, c.Code, c.Stdout, c.Stderr)
		}
	}
}

func TestP3PathTextIsPathlibLexical(t *testing.T) {
	cases := map[string]string{
		"":            ".",
		".":           ".",
		"./x":         "x",
		"a//b":        "a/b",
		"x/":          "x",
		"..":          "..",
		"/":           "/",
		"a/../b":      "a/../b",
		"x/.":         "x",
		".//x//y/":    "x/y",
		"a/b/../..":   "a/b/../..",
		"../..":       "../..",
		"/a//b/./c/":  "/a/b/c",
		"/..":         "/..",
		"a/./b/./c":   "a/b/c",
		"./././":      ".",
		"//":          "/",
		"/a/../../b":  "/a/../../b",
		"x/y/z/../w":  "x/y/z/../w",
		"contracts/":  "contracts",
		"./contracts": "contracts",
	}
	for in, want := range cases {
		if got := pyPathText(in); got != want {
			t.Errorf("pyPathText(%q) = %q, want %q", in, got, want)
		}
	}
}
