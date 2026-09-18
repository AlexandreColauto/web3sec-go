package learning

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// Reflection and planner-hint inbox entries (reflection_entry,
// planner_hint) and their JSONL readers. Split from learning.go (same package).

// HINT_KINDS is HINT_KINDS.
var HINT_KINDS = []string{"priority", "exclusion", "detector", "note"}

// ReflectionOpts carries reflection_entry's keyword arguments.
type ReflectionOpts struct {
	Round               int64
	FalseAssumptions    []string
	ToolFailures        []string
	WastedEffort        []string
	WhatWorked          []string
	ProcessImprovements []string
}

// ReflectionEntry is reflection_entry: append one trajectory-reflection
// entry to the learnings inbox (learnings.jsonl).
func ReflectionEntry(c *state.Campaign, o ReflectionOpts) (validation.Value, error) {
	entry := validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("round", validation.VInt(o.Round)),
		kv("at", validation.VStr(state.NowIso())),
		kv("false_assumptions", validation.StrArr(o.FalseAssumptions)),
		kv("tool_failures", validation.StrArr(o.ToolFailures)),
		kv("wasted_effort", validation.StrArr(o.WastedEffort)),
		kv("what_worked", validation.StrArr(o.WhatWorked)),
		kv("process_improvements", validation.StrArr(o.ProcessImprovements)))
	path := filepath.Join(c.Dir, "learnings.jsonl")
	data := validation.VObj(kv("round", validation.VInt(o.Round)))
	if err := state.AppendJsonlThenLog(c, path, validation.DumpsOrdered(entry, false),
		func() error {
			_, lerr := c.Log("reflection.recorded", nil, &data)
			return lerr
		}); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

// HintOpts carries planner_hint's keyword arguments.
type HintOpts struct {
	Kind      string
	Content   string
	SourceRef string
	Actor     string
}

// PlannerHint is planner_hint: a reflection-derived instruction for the
// PLANNER. Append-only, attributed, logged.
func PlannerHint(c *state.Campaign, o HintOpts) (validation.Value, error) {
	if !slices.Contains(HINT_KINDS, o.Kind) {
		return validation.VNull(), fmt.Errorf("invalid hint kind %s; kinds: %s",
			pyReprStr(o.Kind), pyReprTuple(HINT_KINDS))
	}
	if len([]rune(strings.TrimSpace(o.Content))) < 10 {
		return validation.VNull(), errors.New(
			"a planner hint needs substantive content (>=10 chars)")
	}
	if o.Actor == "" {
		o.Actor = "reflection"
	}
	row := validation.VObj(
		kv("hint_id", validation.VStr("HINT-"+idTail(8))),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("kind", validation.VStr(o.Kind)),
		kv("content", validation.VStr(strings.TrimSpace(o.Content))),
		kv("source_ref", validation.VStr(o.SourceRef)),
		kv("actor", validation.VStr(o.Actor)),
		kv("at", validation.VStr(state.NowIso())))
	path := filepath.Join(c.Dir, "planner_hints.jsonl")
	hid := validation.ObjStr(row, "hint_id")
	data := validation.VObj(
		kv("kind", validation.VStr(o.Kind)),
		kv("actor", validation.VStr(o.Actor)))
	if err := state.AppendJsonlThenLog(c, path, validation.DumpsOrdered(row, false),
		func() error {
			_, lerr := c.Log("learning.planner_hint", &hid, &data)
			return lerr
		}); err != nil {
		return validation.VNull(), err
	}
	return row, nil
}

// LoadPlannerHints is load_planner_hints: the JSONL rows, in file order,
// optionally filtered by kind.
func LoadPlannerHints(c *state.Campaign, kind *string) ([]validation.Value, error) {
	path := filepath.Join(c.Dir, "planner_hints.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := []validation.Value{}
	for _, line := range strings.Split(string(raw), "\n") {
		if state.BlankLine(line) {
			continue
		}
		row, err := ReadJSONLine(line)
		if err != nil {
			return nil, err
		}
		if kind != nil && *kind != "" && validation.ObjStr(row, "kind") != *kind {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}

// ReadJSONLine is read_json_line: json.loads(line).
func ReadJSONLine(line string) (validation.Value, error) {
	return validation.ParseOrdered([]byte(line))
}
