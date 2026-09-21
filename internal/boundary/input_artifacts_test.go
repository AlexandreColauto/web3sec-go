package boundary

// v1.6 Part 1: a model stage declares its input artifact set at invocation; the
// framework refuses inputs outside it. The declaration is part of the recorded
// request, so an out-of-set input is a refusal the ledger can show.

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/trajectory"
	"websec/internal/validation"
)

// bundle is a stand-in for what roles.BuildProposerContext emits: nested
// objects and arrays carrying artifact ids — plus prose that happens to quote
// one, which must NOT be collected.
func bundle(ids ...string) validation.Value {
	rows := make([]validation.Value, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, validation.VObj(
			validation.KV{K: "artifact_id", V: validation.VStr(id)},
			validation.KV{K: "note", V: validation.VStr("see ART-99999999 for context")}))
	}
	return validation.VObj(
		validation.KV{K: "role", V: validation.VStr("proposer")},
		validation.KV{K: "task", V: validation.VObj(
			validation.KV{K: "response_schema", V: validation.VStr("hypothesis")})},
		validation.KV{K: "context", V: validation.VArr(rows...)},
	)
}

func declaration(ids ...string) validation.Value {
	decl := make([]validation.Value, 0, len(ids))
	for _, id := range ids {
		decl = append(decl, validation.VObj(
			validation.KV{K: "kind", V: validation.VStr("artifact")},
			validation.KV{K: "id", V: validation.VStr(id)}))
	}
	return validation.VArr(decl...)
}

func builtRequest(t *testing.T, ids []string, declared []string) validation.Value {
	t.Helper()
	return BuildRequest(bundle(ids...), declaration(declared...),
		"proposer", "qwen3-14b:local", "0123456789abcdef", "hypothesis")
}

// declaredFromBundle is the declaration a migrated caller actually had: the
// ids the bundle it is about to send cites.
func declaredFromBundle(b validation.Value) validation.Value {
	return declaration(BundleArtifacts(b)...)
}

// TestBuildRequestDerivesTheCitedSet is the anti-decoration test: the cited
// set comes from the BUNDLE, so no caller can hand-write an empty list and
// make the refusal unreachable. It also pins the walk's SCOPE — the prose id
// in the bundle's `note` field is not a citation, and collecting it would make
// every declaration an "everything" declaration.
func TestBuildRequestDerivesTheCitedSet(t *testing.T) {
	req := builtRequest(t, []string{"ART-aaaa1111", "ART-bbbb2222"}, []string{"ART-aaaa1111"})
	got := validation.ObjAt(req, "context_artifacts")
	if len(got.A) != 2 {
		t.Fatalf("context_artifacts = %d entries, want the 2 ids the bundle cites "+
			"(and NOT the ART-99999999 quoted in prose): %s", len(got.A),
			validation.CanonSpaced(got))
	}
	for _, v := range got.A {
		if v.S == "ART-99999999" {
			t.Fatal("BundleArtifacts collected an id quoted in prose — the walk " +
				"must stay scoped to id-bearing keys")
		}
	}
	if err := ValidateRequest(req); err == nil ||
		!strings.Contains(err.Error(), "outside its declared input set") {
		t.Fatalf("err = %v, want the out-of-set refusal for ART-bbbb2222", err)
	}
}

func TestDeclaredInputSetIsRequired(t *testing.T) {
	// A MISSING declaration is the Go clause's job: the key is absent, so the
	// schema has nothing to check and ValidateRequest refuses by name.
	req := builtRequest(t, []string{"ART-aaaa1111"}, []string{"ART-aaaa1111"})
	req.O = withoutKey(req.O, "input_artifacts")
	err := ValidateRequest(req)
	if err == nil || !strings.Contains(err.Error(), "declares no input artifact set") {
		t.Fatalf("err = %v, want the missing-declaration refusal", err)
	}

	// An EMPTY declaration is the schema's job (minItems: 1). The two clauses
	// are complementary, not redundant: this one proves the schema fires, the
	// one above proves the Go clause fires when the schema cannot.
	empty := builtRequest(t, []string{"ART-aaaa1111"}, []string{"ART-aaaa1111"})
	empty.O = validation.SetOrAppend(empty.O, "input_artifacts", validation.VArr())
	if err := ValidateRequest(empty); err == nil ||
		strings.Contains(err.Error(), "declares no input artifact set") {
		t.Fatalf("err = %v, want the schema's minItems refusal (not the Go clause)", err)
	}
}

// withoutKey drops a key from an object (the tests need a request that never
// declared its input set, not one that declared an empty one).
func withoutKey(o []validation.KV, key string) []validation.KV {
	out := make([]validation.KV, 0, len(o))
	for _, kv := range o {
		if kv.K != key {
			out = append(out, kv)
		}
	}
	return out
}

func TestInSetRequestPasses(t *testing.T) {
	req := builtRequest(t, []string{"ART-aaaa1111", "ART-bbbb2222"},
		[]string{"ART-aaaa1111", "ART-bbbb2222"})
	if err := ValidateRequest(req); err != nil {
		t.Fatalf("in-set request refused: %v", err)
	}
}

func TestInputSetRefusalIsRecorded(t *testing.T) {
	c, err := state.Init(t.TempDir(), "smoke", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	req := builtRequest(t, []string{"ART-aaaa1111", "ART-bbbb2222"}, []string{"ART-aaaa1111"})
	if err := RecordInputSetRefusal(c, req, "out-of-set input"); err != nil {
		t.Fatalf("log: %v", err)
	}
	ev := findModelRejected(t, c)
	if validation.ObjAt(ev, "ref").Kind != validation.Null {
		t.Fatalf("ref = %s, want null (no finding id exists at request time)",
			validation.PyRepr(validation.ObjAt(ev, "ref")))
	}
	if got := len(validation.ObjAt(validation.ObjAt(ev, "data"), "outside").A); got != 1 {
		t.Fatalf("outside = %d entries, want 1", got)
	}
	// The refusal is a LEDGER FACT: verify_trajectory re-validates every
	// model.* event against trajectory.schema.json#model_rejected, so the
	// framework's own refusal event must satisfy that contract.
	report, err := trajectory.VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(report, "ok").B {
		t.Fatalf("verify_trajectory = %s, want ok (the refusal event "+
			"must satisfy model_rejected's own contract)",
			validation.CanonCompact(report))
	}
}

// findModelRejected returns the campaign's first model.rejected event.
func findModelRejected(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if validation.ObjStr(e, "type") == "model.rejected" {
			return e
		}
	}
	t.Fatal("no model.rejected event recorded")
	return validation.VNull()
}

// TestSchemaFailureIsNotRecordedAsARejection pins the boundary of the recorder:
// a request that fails the RECORD contract keeps the pre-v1.6 behaviour (an
// error, no event), because its role/kind may not be model.rejected's
// vocabulary at all — logging it would write an event that violates its own
// schema and turn verify_trajectory red on a healthy campaign.
func TestSchemaFailureIsNotRecordedAsARejection(t *testing.T) {
	c, err := state.Init(t.TempDir(), "smoke", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	bad := validation.VObj(
		validation.KV{K: "role", V: validation.VStr("not-a-role")},
		validation.KV{K: "model_id", V: validation.VStr("qwen3-14b:local")},
		validation.KV{K: "prompt_version", V: validation.VStr("0123456789abcdef")},
		validation.KV{K: "response_schema", V: validation.VStr("hypothesis")})
	if err := logHypothesisRequest(c, bad); err == nil {
		t.Fatal("a request with no context_hash must be refused")
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	rejections := 0
	for _, e := range evs {
		if validation.ObjStr(e, "type") != "model.rejected" {
			continue
		}
		rejections++
	}
	if rejections != 0 {
		t.Fatalf("model.rejected events = %d, want 0 (a record-contract failure "+
			"is not a declared-input-set refusal)", rejections)
	}
}
