// golden_test.go: the cross-twin golden vectors for the orchestrator facade.
//
// internal/orchestrator/testdata/oracles.json is produced by
// .scratch/t13/gen-vectors.py, which runs the LIVE Python twin over fixture
// campaigns and records, for every method: the return value, the raised
// message, the post-state (campaign_state.json) and the event log, all as
// json.dumps(..., ensure_ascii=False, indent=2). This test materializes the
// very same campaign tree, replays the very same calls through the Go twin and
// compares byte-for-byte with validation.DumpIndented.
//
// The three seams a replay must supply (structural index, adapter context,
// independent-evidence minting) are installed with fakes whose recorded
// call-site arguments are compared against the Python recorder's — so the
// contract of the seam, not just its output, is verified.
package orchestrator

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/bounty"
	"websec/internal/completion"
	"websec/internal/findings"
	"websec/internal/pipeline"
	"websec/internal/state"
	"websec/internal/validation"
)

const rootPlaceholder = "<ROOT>"

// goldenRoot is where both twins replay: the generator writes the oracles at
// this exact path, because event hashes cover absolute artifact paths.
const goldenRoot = "/tmp/t13-vectors"

// idMap relabels finding ids in creation order: findings.new_finding_id is a
// raw uuid4 in BOTH twins, so the ids differ run to run and can only be
// compared symbolically. The creation order is a property of the call
// sequence, so both twins assign F-<ID1>, F-<ID2>, ... identically.
type idMap struct {
	byReal  map[string]string
	byPlace map[string]string
	order   []string
}

func newIDMap() *idMap {
	return &idMap{byReal: map[string]string{}, byPlace: map[string]string{}}
}

// note registers a finding value's id and returns it.
func (m *idMap) note(v validation.Value) {
	fid := strAt(v, "finding_id")
	if fid == "" {
		return
	}
	if _, ok := m.byReal[fid]; ok {
		return
	}
	m.order = append(m.order, fid)
	place := "F-<ID" + itoa(len(m.order)) + ">"
	m.byReal[fid] = place
	m.byPlace[place] = fid
}

// real resolves a placeholder (or a literal id) back to the local id.
func (m *idMap) real(s string) string {
	if r, ok := m.byPlace[s]; ok {
		return r
	}
	return s
}

// place relabels every known id in s.
func (m *idMap) place(s string) string {
	for real, ph := range m.byReal {
		s = strings.ReplaceAll(s, real, ph)
	}
	return s
}

type seamRecorder struct {
	calls []validation.Value
}

func (r *seamRecorder) add(seam string, fields ...validation.KV) {
	kv := []validation.KV{kvOf("seam", validation.VStr(seam))}
	r.calls = append(r.calls, validation.VObj(append(kv, fields...)...))
}

func goldenDoc(t *testing.T) validation.Value {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "oracles.json"))
	if err != nil {
		t.Fatalf("read oracles: %v", err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse oracles: %v", err)
	}
	return doc
}

// installGoldenSeams wires the three observable seams to the canned values
// the Python twin returned, recording the same call-site fields.
func installGoldenSeams(t *testing.T, doc, sc validation.Value,
	rec *seamRecorder, ids *idMap) {
	t.Helper()
	installForkPocSeams(t, sc, ids)
	findings.ResetPinnedFindingIDs()
	findings.SetFindingIDSource(findings.PinnedFindingID)
	cannedIndex := objAt(doc, "canned_index")
	cannedCtx := objAt(doc, "canned_context")
	SetStructuralIndex(StructuralIndexAPI{
		IndexSnapshot: func(c *state.Campaign, root string) (validation.Value, error) {
			rec.add("structural_index.index_snapshot",
				kvOf("root", validation.VStr(root)),
				kvOf("campaign", validation.VStr(c.CampaignID)),
				kvOf("backend", validation.VStr("regex")))
			idx := copyObj(cannedIndex)
			idx.O = validation.SetOrAppend(idx.O, "campaign_id", validation.VStr(c.CampaignID))
			snapID, err := c.ActiveSnapshotIDOrNone()
			if err != nil {
				return validation.VNull(), err
			}
			if snapID == nil {
				idx.O = validation.SetOrAppend(idx.O, "snapshot_id", validation.VNull())
			} else {
				idx.O = validation.SetOrAppend(idx.O, "snapshot_id", validation.VStr(*snapID))
			}
			idx.O = validation.SetOrAppend(idx.O, "created_at", validation.VStr(strAt(doc, "now")))
			return idx, nil
		},
		SaveIndex: func(c *state.Campaign, index validation.Value) (string, error) {
			out := filepath.Join(c.ArtifactsDir, "structural_index.json")
			if err := validation.WriteJson(out, index, "structural_index"); err != nil {
				return "", err
			}
			return out, nil
		},
	})
	pipeline.SetAdapter(ctxAdapter{ctx: cannedCtx, rec: rec})
	SetReproduction(ReproductionAPI{
		MintIndependentEvidence: func(_ *state.Campaign, findingID, execID,
			description, verifier string) (validation.Value, error) {
			rec.add("reproduction.mint_independent_evidence",
				kvOf("finding_id", validation.VStr(findingID)),
				kvOf("exec_id", validation.VStr(execID)),
				kvOf("description", validation.VStr(description)),
				kvOf("verifier", validation.VStr(verifier)))
			return validation.VObj(
				kvOf("finding_id", validation.VStr(findingID)),
				kvOf("evidence_id", validation.VStr("EV-canned")),
				kvOf("level", validation.VStr("E6")),
				kvOf("verifier", validation.VStr(verifier)),
			), nil
		},
	})
}

// installForkPocSeams replays fork_poc through the bounty/completion seams:
// the module itself is a later port, so the vectors inject exactly what the
// Python twin returned and keep verifying the orchestrator's relay of the
// proven flag and the reason text.
func installForkPocSeams(t *testing.T, sc validation.Value, ids *idMap) {
	t.Helper()
	status := objAt(objAt(sc, "fork_poc"), "status")
	evidence := objAt(objAt(sc, "fork_poc"), "evidence")
	lookup := func(list validation.Value, fid string) validation.Value {
		for _, row := range list.A {
			if ids.real(strAt(row, "finding_id")) == fid {
				return row
			}
		}
		return validation.VNull()
	}
	bounty.SetForkPocStatus(func(_ *state.Campaign,
		findingID string) (bool, string, error) {
		row := lookup(status, findingID)
		if row.Kind != validation.Obj {
			return false, "no fork PoC proven", nil
		}
		return boolAt(row, "proven"), strAt(row, "reason"), nil
	})
	completion.SetForkPocEvidence(forkPocEvidence{
		evidence: evidence, ids: ids,
	})
}

// forkPocEvidence is the completion-side fork_poc.fork_poc_evidence fake.
type forkPocEvidence struct {
	evidence validation.Value
	ids      *idMap
}

func (f forkPocEvidence) ForkPocEvidence(_ *state.Campaign,
	finding validation.Value) (validation.Value, *string, error) {
	row := validation.VNull()
	for _, cand := range f.evidence.A {
		if f.ids.real(strAt(cand, "finding_id")) ==
			strAt(finding, "finding_id") {
			row = cand
			break
		}
	}
	if row.Kind != validation.Obj {
		return validation.VNull(), nil, nil
	}
	reason := strAt(row, "reason")
	if item := objAt(row, "item"); item.Kind == validation.Obj {
		return item, nil, nil
	}
	return validation.VNull(), &reason, nil
}

// ctxAdapter is the pipeline adapter fake: it returns the canned context and
// records the call site (stage, extra paths, max_chars).
type ctxAdapter struct {
	ctx validation.Value
	rec *seamRecorder
}

func (a ctxAdapter) BuildContext(_ *state.Campaign, stage string,
	extra []string) (validation.Value, error) {
	paths := []validation.Value{}
	for _, p := range extra {
		paths = append(paths, validation.VStr(p))
	}
	a.rec.add("adapter.build_context",
		kvOf("stage", validation.VStr(stage)),
		kvOf("extra_paths", validation.VArr(paths...)),
		kvOf("max_chars", validation.VInt(60000)))
	return copyObj(a.ctx), nil
}

// writeFile writes one fixture file under root.
func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// seedInputs writes the static inputs every scenario shares: the target tree
// and the policy file.
func seedInputs(t *testing.T, root string, doc validation.Value) {
	t.Helper()
	for _, kv := range objAt(doc, "target").O {
		writeFile(t, root, filepath.Join("target", kv.K), kv.V.S)
	}
	writeFile(t, root, "policy.json", validation.DumpIndented(
		objAt(doc, "policy")))
}

func TestGoldenVectors(t *testing.T) {
	doc := goldenDoc(t)
	scenarios := objAt(doc, "scenarios")
	names := make([]string, 0, len(scenarios.O))
	for _, kv := range scenarios.O {
		names = append(names, kv.K)
	}
	sort.Strings(names)
	if len(names) != 11 {
		t.Fatalf("expected 11 scenarios, got %d", len(names))
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			runGoldenScenario(t, doc, name, objAt(scenarios, name))
		})
	}
}

func runGoldenScenario(t *testing.T, doc validation.Value, name string,
	sc validation.Value) {
	t.Helper()
	root := filepath.Join(goldenRoot, name)
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("clean %s: %v", root, err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	seedInputs(t, root, doc)
	t.Setenv("WEBV2_NOW", strAt(doc, "now"))
	t.Setenv("WEBV2_UUID", strAt(doc, "seed"))
	state.ResetIDStream()
	rec := &seamRecorder{}
	ids := newIDMap()
	installGoldenSeams(t, doc, sc, rec, ids)
	defer findings.SetFindingIDSource(nil)
	defer bounty.SetForkPocStatus(nil)
	defer completion.SetForkPocEvidence(nil)
	defer SetStructuralIndex(StructuralIndexAPI{})
	defer SetReproduction(ReproductionAPI{})
	defer pipeline.SetAdapter(nil)

	c, err := state.Init(root, strAt(doc, "program"), state.InitOpts{
		CampaignID: strAt(doc, "campaign_id")})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	o := New(c)
	for _, spec := range objAt(sc, "build").A {
		if _, err := dispatchGolden(t, o, c, doc, spec, ids, root); err != nil {
			t.Fatalf("build op %s: %v", strAt(spec, "op"), err)
		}
	}
	steps := objAt(sc, "steps")
	for i, step := range steps.A {
		runGoldenStep(t, o, c, root, doc, step, ids, i)
	}
	if want := objAt(sc, "finding_placeholders"); len(ids.order) != len(want.A) {
		t.Fatalf("%s: created %d findings, want %d", name, len(ids.order),
			len(want.A))
	}
	gotCalls := validation.VArr(rec.calls...)
	wantCalls := objAt(sc, "seam_calls")
	if len(rec.calls) != len(wantCalls.A) {
		t.Fatalf("%s: recorded %d seam calls, want %d\n got: %s\nwant: %s",
			name, len(rec.calls), len(wantCalls.A),
			ids.place(strings.ReplaceAll(validation.DumpIndented(gotCalls),
				root, rootPlaceholder)),
			validation.DumpIndented(wantCalls))
	}
	for i := range rec.calls {
		got := ids.place(strings.ReplaceAll(
			validation.DumpIndented(rec.calls[i]), root, rootPlaceholder))
		want := validation.DumpIndented(wantCalls.A[i])
		if got != want {
			t.Errorf("%s: seam call %d mismatch\n got: %s\nwant: %s",
				name, i, got, want)
		}
	}
}

// runGoldenStep replays one recorded call and compares value, error, state and
// events with the Python oracle.
func runGoldenStep(t *testing.T, o *Orchestrator, c *state.Campaign,
	root string, doc, step validation.Value, ids *idMap, i int) {
	t.Helper()
	op := strAt(step, "op")
	wantErr := strAt(step, "error")
	got, err := dispatchGolden(t, o, c, doc, step, ids, root)
	if wantErr != "" {
		if err == nil {
			t.Fatalf("step %d %s: want error %q, got %s", i, op, wantErr,
				validation.DumpIndented(got))
		}
		got := ids.place(strings.ReplaceAll(err.Error(), root,
			rootPlaceholder))
		if got != wantErr {
			t.Errorf("step %d %s: error mismatch\n got: %s\nwant: %s", i, op,
				got, wantErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("step %d %s: unexpected error: %v", i, op, err)
	}
	if want := strAt(step, "oracle"); want != "" {
		if got := ids.place(validation.DumpIndented(got)); got != want {
			t.Errorf("step %d %s: value mismatch\n got: %s\nwant: %s", i, op,
				got, want)
		}
	}
	compareFile(t, i, op, "state", strAt(step, "state"),
		filepath.Join(c.Dir, "campaign_state.json"), root, ids)
	compareFile(t, i, op, "events", strAt(step, "events"),
		filepath.Join(c.Dir, "events.jsonl"), root, ids)
}

// compareFile compares a whole artifact against the oracle with the temp root
// normalized back to <ROOT>.
func compareFile(t *testing.T, i int, op, what, want, path, root string,
	ids *idMap) {
	t.Helper()
	if want == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("step %d %s: read %s: %v", i, op, what, err)
	}
	got := ids.place(strings.ReplaceAll(string(raw), root, rootPlaceholder))
	if got != want {
		t.Errorf("step %d %s: %s mismatch\n got: %s\nwant: %s", i, op, what,
			firstDiff(got, want), firstDiff(want, got))
	}
}

// firstDiff renders the first differing line of a byte-exact comparison.
func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return "line " + itoa(i+1) + ":\n  got: " + gl + "\n want: " + wl
		}
	}
	return "(identical)"
}
