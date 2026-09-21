package boundary

// v1.6 Part 1: a model stage declares its input artifact set at invocation; the
// framework refuses inputs outside it. The declaration is part of the recorded
// request, so an out-of-set input is a refusal the ledger can show.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/roles"
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

// realArtifactID mints an artifact id through the REAL path — state's
// RegisterArtifact — so the derivation is tested against the shape the
// framework actually produces, not a fixture's invention.
func realArtifactID(t *testing.T, c *state.Campaign) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("policy", path, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// realBundle mirrors the proposer/reproducer wire shape: the pinned snapshot
// under the keys the role builders emit (`active_snapshot_id`,
// `snapshot.snapshot_id`, and the `snapshot_ids` mapping the critic and
// reproducer carry), an artifact under an evidence entry, and prose that
// quotes an id — which must stay out of the cited set.
func realBundle(artifactID, snapshotID string) validation.Value {
	return validation.VObj(
		validation.KV{K: "role", V: validation.VStr("proposer")},
		validation.KV{K: "target", V: validation.VObj(
			validation.KV{K: "active_snapshot_id", V: validation.VStr(snapshotID)})},
		validation.KV{K: "snapshot", V: validation.VObj(
			validation.KV{K: "snapshot_id", V: validation.VStr(snapshotID)})},
		validation.KV{K: "snapshot_ids", V: validation.VObj(
			validation.KV{K: "source", V: validation.VStr(snapshotID)})},
		validation.KV{K: "evidence", V: validation.VArr(validation.VObj(
			validation.KV{K: "artifact_id", V: validation.VStr(artifactID)},
			validation.KV{K: "note", V: validation.VStr("see ART-99999999 for context")}))},
	)
}

// TestBundleArtifactsReachesRealMintedIDs is the regression test for the
// derivation's reach. The old shape regex listed prefixes no mint path
// produces (artifacts are <KIND3>-<8hex>, snapshots src-content-<12hex>), so
// on a real bundle the cited set was empty and the out-of-set refusal could
// never fire on a stage's real inputs. Both ids here come from the framework:
// the artifact through RegisterArtifact, the snapshot in the documented
// `src-content-<12hex>` shape (internal/snapshot/pin.go:334).
func TestBundleArtifactsReachesRealMintedIDs(t *testing.T) {
	c := newCamp(t)
	artID := realArtifactID(t, c)
	snapID := "src-content-9987fc4e3bed"
	if !strings.HasPrefix(artID, "POL-") {
		t.Fatalf("RegisterArtifact minted %q, want the POL-<8hex> shape", artID)
	}
	b := realBundle(artID, snapID)
	want := []string{snapID, artID} // first-seen order, deduped
	if got := BundleArtifacts(b); !slices.Equal(got, want) {
		t.Fatalf("BundleArtifacts = %q, want %q", got, want)
	}
	for _, id := range BundleArtifacts(b) {
		if id == "ART-99999999" {
			t.Fatal("BundleArtifacts collected an id quoted in prose — the walk " +
				"must stay scoped to id-bearing keys")
		}
	}
	// The refusal fires on those same real ids: declare the artifact only, and
	// the snapshot the bundle pins is outside the declaration.
	req := BuildRequest(b, declaration(artID), "proposer", "qwen3-14b:local",
		"0123456789abcdef", "hypothesis")
	err := ValidateRequest(req)
	if err == nil || !strings.Contains(err.Error(), "outside its declared input set") ||
		!strings.Contains(err.Error(), snapID) {
		t.Fatalf("err = %v, want the out-of-set refusal naming %s", err, snapID)
	}
}

// TestInSetRealIDsPass is the other half: a declaration that covers the real
// ids the bundle carries is accepted, so the refusal above is not firing on
// everything.
func TestInSetRealIDsPass(t *testing.T) {
	c := newCamp(t)
	artID := realArtifactID(t, c)
	snapID := "src-1684fd7b-b868c7cd06e0"
	req := BuildRequest(realBundle(artID, snapID), declaration(snapID, artID),
		"proposer", "qwen3-14b:local", "0123456789abcdef", "hypothesis")
	if err := ValidateRequest(req); err != nil {
		t.Fatalf("in-set request with real ids refused: %v", err)
	}
}

// unpinnedCriticBundle is the re-review's reproducer, on the REAL builder: one
// finding ingested into an UNPINNED campaign, whose critic bundle carries the
// pin slot verbatim (internal/roles/context_critic.go:203).
func unpinnedCriticBundle(t *testing.T) (string, validation.Value) {
	t.Helper()
	c := newCamp(t)
	fid := validation.ObjStr(mustIngest(t, c, validHypothesis()), "finding_id")
	b, err := roles.BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return fid, b
}

// TestBundleArtifactsSkipsTheUnpinnedPinSentinel is the regression test for the
// sentinel leak. `unpinned` is the framework's own "no pin" marker, written
// into snapshot_ids.source on an unpinned campaign — not a cited artifact.
// Collecting it refused an honest drop and wrote a FALSE model.rejected row
// naming a non-artifact (fix-rereview.md, "New Breakage in the Fix Diff").
func TestBundleArtifactsSkipsTheUnpinnedPinSentinel(t *testing.T) {
	fid, b := unpinnedCriticBundle(t)
	if got := BundleArtifacts(b); !slices.Equal(got, []string{fid}) {
		t.Fatalf("BundleArtifacts = %q, want exactly the finding id %q — the pin "+
			"slot's %q sentinel is not a cited artifact", got, fid,
			findings.SourcePinUnpinned)
	}
	// The honest declaration must PASS: the bundle cites one artifact and the
	// stage declares that one. Before the fix the derived set also held the
	// sentinel, so this exact request was refused.
	req := BuildRequest(b, declaration(fid), "critic", "qwen3-14b:local",
		"0123456789abcdef", "critic_verdict")
	if err := ValidateRequest(req); err != nil {
		t.Fatalf("a critic declaring the one id its bundle cites was refused: %v",
			err)
	}
}

// TestBundleArtifactsSkipsTheSentinelUnderAnEvidenceItem covers the sentinel's
// second real producer: the exec-evidence path stamps each item's snapshot_id
// from the finding's pin (internal/findings/exec_evidence.go:205-215), so on an
// unpinned campaign that key holds the sentinel too and the critic bundle
// carries the item verbatim (internal/roles/context_critic.go:85-90).
func TestBundleArtifactsSkipsTheSentinelUnderAnEvidenceItem(t *testing.T) {
	artID := realArtifactID(t, newCamp(t))
	b := validation.VObj(
		validation.KV{K: "snapshot_ids", V: validation.VObj(
			validation.KV{K: "source", V: validation.VStr(findings.SourcePinUnpinned)},
			validation.KV{K: "deployment", V: validation.VNull()},
			validation.KV{K: "chain", V: validation.VNull()})},
		validation.KV{K: "evidence", V: validation.VArr(validation.VObj(
			validation.KV{K: "evidence_id", V: validation.VStr("EV-1")},
			validation.KV{K: "artifact_id", V: validation.VStr(artID)},
			validation.KV{K: "snapshot_id",
				V: validation.VStr(findings.SourcePinUnpinned)}))},
	)
	want := []string{"EV-1", artID} // walk order: evidence_id, artifact_id
	if got := BundleArtifacts(b); !slices.Equal(got, want) {
		t.Fatalf("BundleArtifacts = %q, want %q — the sentinel is skipped under "+
			"every id-bearing key, and the real ids survive", got, want)
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

// emptyDeclarationRequest is a request whose ONLY defect is its declared input
// set: input_artifacts is present but empty, which model_request.schema.json
// refuses at minItems 1 — before ValidateRequest's own "declares no input
// artifact set" clause can see it.
func emptyDeclarationRequest(t *testing.T) validation.Value {
	t.Helper()
	req := builtRequest(t, []string{"POL-171165a6"}, []string{"POL-171165a6"})
	req.O = validation.SetOrAppend(req.O, "input_artifacts", validation.VArr())
	return req
}

// refuseAndVerify refuses a request through the one call site and returns the
// campaign with the model.rejected count, asserting the ledger still verifies.
func refuseAndVerify(t *testing.T, req validation.Value) (*state.Campaign, int) {
	t.Helper()
	c := newCamp(t)
	if err := logHypothesisRequest(c, req); err == nil {
		t.Fatal("request must be refused")
	}
	report, err := trajectory.VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(report, "ok").B {
		t.Fatalf("verify_trajectory = %s, want ok (the refusal event must "+
			"satisfy model_rejected's own contract)", validation.CanonCompact(report))
	}
	return c, len(rejectedEvents(t, c))
}

// TestEmptyDeclarationRefusalIsRecorded is the regression test for the
// recorder's gate: the EMPTY declaration is one of the two refusals this task
// exists to record, and it must reach the ledger even though the schema (not
// the Go clause) is what refuses it.
func TestEmptyDeclarationRefusalIsRecorded(t *testing.T) {
	c, n := refuseAndVerify(t, emptyDeclarationRequest(t))
	if n != 1 {
		t.Fatalf("model.rejected events = %d, want 1 (the empty declaration is "+
			"a declared-input-set refusal, not a silent error)", n)
	}
	ev := findModelRejected(t, c)
	if got := validation.ObjAt(validation.ObjAt(ev, "data"), "declared"); got.Kind != validation.Arr ||
		len(got.A) != 0 {
		t.Fatalf("declared = %s, want []", validation.PyRepr(got))
	}
	msg := validation.ObjAt(validation.ObjAt(ev, "data"), "error").S
	if !strings.Contains(msg, "input_artifacts") {
		t.Fatalf("error = %q, want the schema's input_artifacts failure", msg)
	}
}

// TestDeclarationEntryWithoutIDIsRecorded covers the other schema-side refusal
// the gate used to drop: an entry that declares a kind but no id is read by
// DeclaredInputArtifacts as "declares no input artifact set".
func TestDeclarationEntryWithoutIDIsRecorded(t *testing.T) {
	req := builtRequest(t, []string{"POL-171165a6"}, []string{"POL-171165a6"})
	req.O = validation.SetOrAppend(req.O, "input_artifacts", validation.VArr(
		validation.VObj(validation.KV{K: "kind", V: validation.VStr("artifact")})))
	if _, n := refuseAndVerify(t, req); n != 1 {
		t.Fatalf("model.rejected events = %d, want 1", n)
	}
}

// TestMalformedRecordWithEmptyDeclarationIsNotRecorded keeps the gate's other
// side: a record that ALSO fails the record contract is refused with no event,
// because model.rejected's role/kind enums would make the framework's own
// event violate the schema verify_trajectory re-validates.
func TestMalformedRecordWithEmptyDeclarationIsNotRecorded(t *testing.T) {
	req := emptyDeclarationRequest(t)
	req.O = validation.SetOrAppend(req.O, "role", validation.VStr("not-a-role"))
	if _, n := refuseAndVerify(t, req); n != 0 {
		t.Fatalf("model.rejected events = %d, want 0 (a malformed record must "+
			"not be logged as an event violating model_rejected's own schema)", n)
	}
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
