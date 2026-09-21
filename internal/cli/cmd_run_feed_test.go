package cli

// `run --feed` — the drop-file transport (v1.6 Part 1). The file stem names the
// stage; an unwired stage and a missing file are exit-2 refusals that say why.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/boundary"
	"websec/internal/state"
	"websec/internal/validation"
)

// inboxDrop writes a drop file where the convention says it lives —
// campaigns/<C>/inbox/<stage>.json — and returns its path.
func inboxDrop(t *testing.T, c *state.Campaign, stage, body string) string {
	t.Helper()
	dir := filepath.Join(c.Dir, "inbox")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, stage+".json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRunFeedRefusesAnEmptyPath: `--feed ""` is a usage error, never a silent
// fall-through to a full pipeline run.
func TestRunFeedRefusesAnEmptyPath(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	code, _, errS := run(t, "--root", root, "run", "--feed", "")
	if code != 2 {
		t.Fatalf("code = %d, want 2 (stderr: %s)", code, errS)
	}
	if !strings.Contains(errS, "--feed requires a path") {
		t.Fatalf("stderr = %q, want the empty-path refusal", errS)
	}
}

// TestRunWithoutACampaignStillNeedsOne: the campaign positional is optional
// only because `--feed` names its campaign through the drop file's path; the
// bare verb keeps argparse's own missing-argument surface.
func TestRunWithoutACampaignStillNeedsOne(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	code, _, errS := run(t, "--root", root, "run")
	if code != 2 {
		t.Fatalf("code = %d, want 2 (stderr: %s)", code, errS)
	}
	if !strings.Contains(errS, "the following arguments are required: campaign") {
		t.Fatalf("stderr = %q, want the missing-campaign error", errS)
	}
}

func TestRunFeedRefusesUnwiredStage(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	drop := inboxDrop(t, c, "hostile-review", "{}")
	code, _, errS := run(t, "--root", root, "run", "--feed", drop)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (stderr: %s)", code, errS)
	}
	if !strings.Contains(errS, "no ingest path for stage") {
		t.Fatalf("stderr = %q, want the unwired-stage refusal", errS)
	}
}

func TestRunFeedRefusesADropOutsideTheInbox(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	stray := filepath.Join(t.TempDir(), "discovery.json")
	if err := os.WriteFile(stray, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "run", "--feed", stray)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (stderr: %s)", code, errS)
	}
	if !strings.Contains(errS, "must live in the campaign inbox") {
		t.Fatalf("stderr = %q, want the inbox-path refusal", errS)
	}
	_ = c
}

// discoveryDrop builds a complete drop file: the request record, the context
// bundle, and the output payload. The bundle's hash is real (computed, not
// pasted) and context_artifacts is absent — the feed derives it, so a drop
// file cannot assert its own cited set.
func discoveryDrop(t *testing.T, cited, declared []string) string {
	t.Helper()
	rows := make([]validation.Value, 0, len(cited))
	for _, id := range cited {
		rows = append(rows, validation.VObj(
			validation.KV{K: "artifact_id", V: validation.VStr(id)}))
	}
	context := validation.VObj(
		validation.KV{K: "role", V: validation.VStr("proposer")},
		validation.KV{K: "context", V: validation.VArr(rows...)})
	decl := make([]validation.Value, 0, len(declared))
	for _, id := range declared {
		decl = append(decl, validation.VObj(
			validation.KV{K: "kind", V: validation.VStr("artifact")},
			validation.KV{K: "id", V: validation.VStr(id)}))
	}
	doc := validation.VObj(
		validation.KV{K: "request", V: validation.VObj(
			validation.KV{K: "role", V: validation.VStr("proposer")},
			validation.KV{K: "model_id", V: validation.VStr("qwen3-14b:local")},
			validation.KV{K: "prompt_version", V: validation.VStr("0123456789abcdef")},
			validation.KV{K: "response_schema", V: validation.VStr("hypothesis")},
			validation.KV{K: "context_hash",
				V: validation.VStr(boundary.ContextHash(context))},
			validation.KV{K: "input_artifacts", V: validation.VArr(decl...)})},
		validation.KV{K: "context", V: context},
		validation.KV{K: "output", V: discoveryOutput()})
	return validation.DumpIndented(doc)
}

func discoveryOutput() validation.Value {
	return validation.VObj(
		validation.KV{K: "title", V: validation.VStr("Attacker drains the vault")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("economic-invariant")},
			validation.KV{K: "description", V: validation.VStr("the mechanism described in detail")})},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/V.sol")},
			validation.KV{K: "function", V: validation.VStr("f")}))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()})},
	)
}

func TestRunFeedIngestsADiscoveryDrop(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	drop := inboxDrop(t, c, "discovery",
		discoveryDrop(t, []string{"ART-aaaa1111"}, []string{"ART-aaaa1111"}))
	code, out, errS := run(t, "--root", root, "run", "--feed", drop)
	if code != 0 {
		t.Fatalf("code = %d, want 0 (stderr: %s)", code, errS)
	}
	if !strings.Contains(out, "ingested F-") {
		t.Fatalf("stdout = %q, want the ingested line", out)
	}
}

// TestRunFeedCampaignPositionalMustAgree: the campaign positional is accepted
// beside --feed, but the drop file's path stays the single source of truth.
func TestRunFeedCampaignPositionalMustAgree(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	drop := inboxDrop(t, c, "discovery",
		discoveryDrop(t, []string{"ART-aaaa1111"}, []string{"ART-aaaa1111"}))
	code, out, errS := run(t, "--root", root, "run", c.CampaignID, "--feed", drop)
	if code != 0 || !strings.Contains(out, "ingested F-") {
		t.Fatalf("agreeing campaign refused: code = %d out=%q err=%q", code, out, errS)
	}
	otherDir := filepath.Join(root, "campaigns", "C-ffffffffffff", "inbox")
	if err := os.MkdirAll(otherDir, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(otherDir, "discovery.json")
	body := discoveryDrop(t, []string{"ART-aaaa1111"}, []string{"ART-aaaa1111"})
	if err := os.WriteFile(other, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS = run(t, "--root", root, "run", c.CampaignID, "--feed", other)
	if code != 2 || !strings.Contains(errS, "belongs to campaign") {
		t.Fatalf("code = %d err=%q, want the campaign-mismatch refusal", code, errS)
	}
}

func TestRunFeedRefusesAnOutOfSetDrop(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	// The bundle cites two artifacts, the declaration covers one: refused, and
	// the refusal is a ledger fact (the check Task 2 adds, on the path an
	// operator drives — and one the file cannot dodge, because the cited set
	// is derived from the bundle it shipped).
	drop := inboxDrop(t, c, "discovery",
		discoveryDrop(t, []string{"ART-aaaa1111", "ART-cccc3333"}, []string{"ART-aaaa1111"}))
	code, out, errS := run(t, "--root", root, "run", "--feed", drop)
	if code != 1 {
		t.Fatalf("code = %d, want 1 (stderr: %s)", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q, want nothing: a refused drop ingests nothing", out)
	}
	if !strings.Contains(errS, "outside its declared input set") {
		t.Fatalf("stderr = %q, want the out-of-set refusal", errS)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	rejected, requested := 0, 0
	for _, e := range evs {
		switch validation.ObjStr(e, "type") {
		case "model.rejected":
			rejected++
		case "model.request":
			requested++
		}
	}
	if rejected != 1 {
		t.Fatalf("model.rejected events = %d, want 1 (the refusal is a ledger fact)",
			rejected)
	}
	// The ORDER the two branches must keep: a refused drop's declaration was
	// never accepted, so it carries no model.request — only the rejection.
	if requested != 0 {
		t.Fatalf("model.request events = %d, want 0 for a refused drop", requested)
	}
}

// TestRunFeedRecordsTheAcceptedInvocation is the I-1 covering test: the drop
// file is the ONLY sanctioned model-stage transport, so a drop the feed ACCEPTS
// must leave its declaration on the ledger as a model.request event — and the
// v16_coverage section the plan added to notice a stopped writer must read 1
// rather than 0 on a campaign built entirely through the CLI.
func TestRunFeedRecordsTheAcceptedInvocation(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	drop := inboxDrop(t, c, "discovery",
		discoveryDrop(t, []string{"ART-aaaa1111"}, []string{"ART-aaaa1111"}))
	code, out, errS := run(t, "--root", root, "run", "--feed", drop)
	if code != 0 {
		t.Fatalf("code = %d, want 0 (stderr: %s)", code, errS)
	}
	if !strings.Contains(out, "ingested F-") {
		t.Fatalf("stdout = %q, want the ingested line", out)
	}
	requireOneDeclaredRequest(t, c, "ART-aaaa1111")
	requireCoverageDeclared(t, root, c.CampaignID, 1)
}

// requireOneDeclaredRequest: exactly one model.request event, declaring the
// artifact the drop declared — with the cited set the feed DERIVED from the
// bundle beside it.
func requireOneDeclaredRequest(t *testing.T, c *state.Campaign, want string) {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	reqs := []validation.Value{}
	for _, e := range evs {
		if validation.ObjStr(e, "type") == "model.request" {
			reqs = append(reqs, e)
		}
	}
	if len(reqs) != 1 {
		t.Fatalf("model.request events = %d, want exactly 1 for an accepted "+
			"drop (the declaration is a ledger fact)", len(reqs))
	}
	data := validation.ObjAt(reqs[0], "data")
	declared := boundary.DeclaredInputArtifacts(data)
	if len(declared) != 1 || declared[0] != want {
		t.Fatalf("input_artifacts = %v, want [%s] (what the drop declared)",
			declared, want)
	}
	cited := []string{}
	for _, v := range validation.ObjAt(data, "context_artifacts").A {
		cited = append(cited, v.S)
	}
	if len(cited) != 1 || cited[0] != want {
		t.Fatalf("context_artifacts = %v, want [%s] (derived from the bundle)",
			cited, want)
	}
}

// requireCoverageDeclared reads the shipped v16_coverage counters over the
// campaign the CLI built: the section exists to make a field that stopped
// being written a visible 0, so a declaration the feed accepted must move
// model_requests and requests_declared off zero.
func requireCoverageDeclared(t *testing.T, root, cid string, want int) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("audit --json (exit %d) not JSON: %v\n%s", code, err, errS)
	}
	secs, ok := rep["sections"].(map[string]any)
	if !ok {
		t.Fatalf("audit --json has no sections object: %s", out)
	}
	sec, ok := secs["v16_coverage"].(map[string]any)
	if !ok {
		t.Fatal("audit --json lacks the v16_coverage section")
	}
	cov, ok := sec["coverage"].(map[string]any)
	if !ok {
		t.Fatal("v16_coverage has no coverage object")
	}
	for _, key := range []string{"model_requests", "requests_declared"} {
		if got := cov[key]; got != float64(want) {
			t.Fatalf("%s = %v, want %d", key, got, want)
		}
	}
}
