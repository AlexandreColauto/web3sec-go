package learning

import (
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// Benchmark-case registration (benchmark_case): the substrate for
// comparing prompt/model/pipeline changes. Split from learning.go (same package).

// BenchmarkOpts carries benchmark_case's keyword arguments.
type BenchmarkOpts struct {
	Name          string
	Repo          string
	Expected      string
	SourceFinding *string
}

// BenchmarkCase is benchmark_case: register a benchmark case from a real
// result — the substrate for comparing prompt/model/pipeline changes.
func BenchmarkCase(c *state.Campaign, o BenchmarkOpts) (validation.Value, error) {
	c4 := validation.VObj(
		kv("case_id", validation.VStr("BENCH-"+idTail(6))),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("name", validation.VStr(o.Name)),
		kv("repo", validation.VStr(o.Repo)),
		kv("expected", validation.VStr(o.Expected)),
		kv("source_finding", strOrNull(o.SourceFinding)),
		kv("created_at", validation.VStr(state.NowIso())))
	path := filepath.Join(c.Dir, "benchmarks.jsonl")
	cid := validation.ObjStr(c4, "case_id")
	data := validation.VObj(kv("name", validation.VStr(o.Name)))
	if err := state.AppendJsonlThenLog(c, path, validation.DumpsOrdered(c4, false),
		func() error {
			_, lerr := c.Log("benchmark.recorded", &cid, &data)
			return lerr
		}); err != nil {
		return validation.VNull(), err
	}
	return c4, nil
}
