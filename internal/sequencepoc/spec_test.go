// Port of tests/test_sequence_spec.py — sequence spec schemas + validation
// core, plus the benign-actor value-echo audit.
package sequencepoc

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/validation"
)

// validSpec is VALID_SPEC from test_sequence_spec.py.
func validSpec(t *testing.T) validation.Value {
	t.Helper()
	return mustParse(t, `{
  "spec_id": "SEQ-TEST-01", "finding_id": "F-abc123",
  "actors": {"attacker": "anvil:0", "victim": "`+addr("ab")+`"},
  "steps": [
    {"step": 1, "actor": "attacker", "target": "`+addr("cd")+`",
     "function": "deposit(uint256)", "args": ["1000"]},
    {"step": 2, "actor": "victim", "target": "`+addr("cd")+`",
     "function": "claim()", "mine_blocks": 5, "expect_revert": false}
  ],
  "final_assertions": [
    {"id": "A1", "kind": "balance", "account": "attacker",
     "op": ">=", "value": "2000"}
  ]
}`)
}

// loadErr loads a mutated spec and returns the error text ("" on success).
func loadErr(t *testing.T, spec validation.Value) string {
	t.Helper()
	p := writeSpec(t, t.TempDir(), spec)
	_, err := LoadSequenceSpec(p)
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestValidSpecLoads(t *testing.T) {
	spec, err := LoadSequenceSpec(writeSpec(t, t.TempDir(), validSpec(t)))
	if err != nil {
		t.Fatal(err)
	}
	steps := listOf(objAt(spec, "steps"))
	if got := intOf(objAt(steps[1], "mine_blocks")); got != 5 {
		t.Errorf("mine_blocks = %d", got)
	}
	er := objAt(steps[0], "expect_revert")
	if er.Kind != validation.Bool || er.B {
		t.Errorf("expect_revert = %v", er)
	}
}

func TestSchemaRejectsUnknownField(t *testing.T) {
	bad := validSpec(t)
	bad.O = append(bad.O, validation.KV{K: "extra", V: validation.VInt(1)})
	if got := loadErr(t, bad); !strings.Contains(got, "extra") {
		t.Fatalf("want extra error, got %q", got)
	}
}

func TestFieldRulesFailLoud(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, s validation.Value) validation.Value
		want   string
	}{
		{"ghost-actor", func(t *testing.T, s validation.Value) validation.Value {
			return setPath(t, s, []string{"steps", "0", "actor"},
				validation.VStr("ghost"))
		}, "actor"},
		{"step-gap", func(t *testing.T, s validation.Value) validation.Value {
			dup := cloneStep(t, s, 1)
			dup = setPath(t, dup, []string{"step"}, validation.VInt(7))
			return appendStep(s, dup)
		}, "step"},
		{"step-dup", func(t *testing.T, s validation.Value) validation.Value {
			return appendStep(s, cloneStep(t, s, 0))
		}, "step"},
		{"actors-extra", func(t *testing.T, s validation.Value) validation.Value {
			actors := objAt(s, "actors")
			actors.O = append(actors.O, validation.KV{K: "evil",
				V: validation.VStr("0x123")})
			return setPath(t, s, []string{"actors"}, actors)
		}, "actors"},
		{"target", func(t *testing.T, s validation.Value) validation.Value {
			return setPath(t, s, []string{"steps", "0", "target"},
				validation.VStr("new"))
		}, "target"},
		{"op", func(t *testing.T, s validation.Value) validation.Value {
			return setPath(t, s, []string{"final_assertions", "0", "op"},
				validation.VStr("~="))
		}, "op"},
		{"value", func(t *testing.T, s validation.Value) validation.Value {
			return setPath(t, s, []string{"final_assertions", "0", "value"},
				validation.VStr("1.5"))
		}, "value"},
		{"storage-slot", func(t *testing.T, s validation.Value) validation.Value {
			return setPath(t, s, []string{"final_assertions", "0", "kind"},
				validation.VStr("storage"))
		}, "slot"},
		{"balance-account", func(t *testing.T, s validation.Value) validation.Value {
			return delPath(s, "final_assertions", "0", "account")
		}, "account"},
		{"empty-steps", func(t *testing.T, s validation.Value) validation.Value {
			return setPath(t, s, []string{"steps"}, validation.VArr())
		}, "steps"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := loadErr(t, tc.mutate(t, validSpec(t)))
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in error, got %q", tc.want, got)
			}
		})
	}
}

func TestCallAssertionNeedsTargetAndFunction(t *testing.T) {
	bad := setPath(t, validSpec(t), []string{"final_assertions"},
		mustParse(t, `[{"id": "A1", "kind": "call", "op": "==",
                       "value": "7"}]`))
	if got := loadErr(t, bad); !strings.Contains(got, "target") {
		t.Fatalf("want target error, got %q", got)
	}
}

func TestBalanceAccountAcceptsRawAddressOrActor(t *testing.T) {
	raw := setPath(t, validSpec(t), []string{"final_assertions", "0",
		"account"}, validation.VStr(addr("12")))
	if _, err := LoadSequenceSpec(writeSpec(t, t.TempDir(), raw)); err != nil {
		t.Fatalf("raw address must load: %v", err)
	}
	bad := setPath(t, validSpec(t), []string{"final_assertions", "0",
		"account"}, validation.VStr("ghost-role"))
	if got := loadErr(t, bad); !strings.Contains(got, "account") {
		t.Fatalf("want account error, got %q", got)
	}
}

func TestActorKeysMustBeShellSafeIdentifiers(t *testing.T) {
	bad := setPath(t, validSpec(t), []string{"actors"}, mustParse(t, `{
      "attacker": "anvil:0", "victim": "`+addr("ab")+`",
      "bad-key!": "anvil:1"}`))
	if got := loadErr(t, bad); !strings.Contains(got, "actors") {
		t.Fatalf("want actors error, got %q", got)
	}
}

func TestMalformedJSONIsValueError(t *testing.T) {
	p := writeSpecText(t, t.TempDir(), "{not json")
	_, err := LoadSequenceSpec(p)
	if err == nil || !strings.Contains(err.Error(), "spec") {
		t.Fatalf("want spec ValueError, got %v", err)
	}
}

func TestSpecHashDeterministicAndCanonical(t *testing.T) {
	a := validSpec(t)
	b := reorderKeys(t, a, false)
	if SpecHash(a) != SpecHash(b) {
		t.Error("spec_hash must be key-order independent")
	}
	h := SpecHash(a)
	if !strings.HasPrefix(h, "sha256:") || len(h) != len("sha256:")+64 {
		t.Errorf("spec_hash = %q", h)
	}
}

func TestIsSequenceRequiredBoundaries(t *testing.T) {
	base := `{"finding_id": "F-x", "status": "POSSIBLE"`
	one := mustParse(t, base+`, "exploit_sequence": [{"step": 1, "action": "call a()"}]}`)
	two := mustParse(t, base+`, "exploit_sequence": [{"step": 1, "action": "call a()"}, {"step": 2, "action": "call b()"}]}`)
	twoActors := mustParse(t, base+`, "exploit_sequence": [{"step": 1, "actor": "alice", "action": "a"}, {"step": 2, "actor": "bob", "action": "b"}]}`)
	sameActor := mustParse(t, base+`, "exploit_sequence": [{"step": 1, "actor": "alice", "action": "a"}, {"step": 2, "actor": "alice", "action": "b"}]}`)
	noSeq := mustParse(t, base+"}")
	if IsSequenceRequired(one) {
		t.Error("one step must be false")
	}
	for name, f := range map[string]validation.Value{"two": two,
		"two-actors": twoActors, "same-actor": sameActor} {
		if !IsSequenceRequired(f) {
			t.Errorf("%s must be true", name)
		}
	}
	if IsSequenceRequired(noSeq) {
		t.Error("no sequence must be false")
	}
}

func TestIsSequenceRequiredDirtyInputReturnsFalse(t *testing.T) {
	cases := []validation.Value{
		validation.VNull(),
		validation.VStr("x"),
		validation.VObj(),
		mustParse(t, `{"exploit_sequence": "x"}`),
		mustParse(t, `{"exploit_sequence": [null]}`),
		mustParse(t, `{"exploit_sequence": ["x"]}`),
		mustParse(t, `{"exploit_sequence": [{"step": 1}]}`),
	}
	for i, c := range cases {
		if IsSequenceRequired(c) {
			t.Errorf("case %d must be false", i)
		}
	}
}

func TestDuplicateAssertionIDsFailLoud(t *testing.T) {
	bad := setPath(t, validSpec(t), []string{"final_assertions"},
		mustParse(t, `[
      {"id": "A1", "kind": "balance", "account": "attacker",
       "op": ">=", "value": "2000"},
      {"id": "A1", "kind": "balance", "account": "victim",
       "op": ">=", "value": "1"}]`))
	got := loadErr(t, bad)
	if !strings.Contains(got, "final_assertions") ||
		!strings.Contains(got, "id") {
		t.Fatalf("want duplicate-id error, got %q", got)
	}
}

func TestUndecodableBytesFailLoud(t *testing.T) {
	p := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(p, []byte{0xff, 0xfe, ' ', 0x80}, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSequenceSpec(p)
	if err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("want unreadable ValueError, got %v", err)
	}
}

func TestZeroValueAndLeadingZeroAnvilAccepted(t *testing.T) {
	for _, value := range []string{"0", "00"} {
		spec := setPath(t, validSpec(t), []string{"final_assertions", "0",
			"value"}, validation.VStr(value))
		if _, err := LoadSequenceSpec(writeSpec(t, t.TempDir(), spec)); err != nil {
			t.Fatalf("value %q must load: %v", value, err)
		}
	}
	spec := setPath(t, validSpec(t), []string{"actors"}, mustParse(t, `{
      "attacker": "anvil:0", "victim": "`+addr("ab")+`",
      "deployer": "anvil:007"}`))
	if _, err := LoadSequenceSpec(writeSpec(t, t.TempDir(), spec)); err != nil {
		t.Fatalf("anvil:007 must load: %v", err)
	}
}

func TestSpecHashCanonicalizesNestedKeys(t *testing.T) {
	a := validSpec(t)
	b := reorderKeys(t, a, true)
	if SpecHash(a) != SpecHash(b) {
		t.Error("spec_hash must canonicalize nested keys")
	}
}

func TestArtifactKindRegistered(t *testing.T) {
	raw, err := validation.ReadSchemaFile("campaign_state")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	kinds := objAt(objAt(objAt(objAt(objAt(doc, "properties"), "artifacts"),
		"items"), "properties"), "kind")
	if !enumHas(kinds, "sequence-poc") {
		t.Error("campaign_state kinds must include sequence-poc")
	}
	if !enumHas(kinds, "sequence-result") {
		t.Error("campaign_state kinds must include sequence-result")
	}
}

func TestKnownSchemasRegistered(t *testing.T) {
	// load_schema rejects unknown names; a successful validate proves both
	// sequence schemas are registered (KNOWN_SCHEMAS membership).
	emptySpec := mustParse(t, `{"spec_id": "SEQ-A-1", "finding_id": "F-1",
      "actors": {"a": "anvil:0"},
      "steps": [{"step": 1, "actor": "a", "target": "`+addr("cd")+`",
                 "function": "f()"}]}`)
	if err := validation.Validate(emptySpec, "sequence_poc", 1); err != nil {
		t.Fatalf("sequence_poc schema: %v", err)
	}
	emptyResult := mustParse(t, `{"spec_hash": "sha256:`+strings.Repeat("0", 64)+
		`", "steps": [], "final_assertions": [], "overall": "fail",
      "generated_at": "x"}`)
	if err := validation.Validate(emptyResult, "sequence_result", 1); err != nil {
		t.Fatalf("sequence_result schema: %v", err)
	}
}

// cast is CAST from the audit fixtures.
var cast = map[string]string{"attacker": "adversarial",
	"victim": "benign-rational"}

func TestValueEchoFlagged(t *testing.T) {
	seq := mustParse(t, `[
      {"step": 1, "actor": "attacker", "function": "deposit",
       "args": [1000000000000000]},
      {"step": 2, "actor": "attacker", "function": "transfer",
       "args": ["0xVault", 10000000000000000000000000]},
      {"step": 3, "actor": "victim", "function": "deposit",
       "args": [10000000000000000000000000]}]`)
	flags := BenignActorAudit(seq, cast)
	if len(flags) != 1 {
		t.Fatalf("flags = %d, want 1", len(flags))
	}
	f := flags[0]
	if intOf(objAt(f, "step")) != 3 || objStr(f, "actor") != "victim" {
		t.Errorf("flag = %v", f)
	}
	if intOf(objAt(f, "arg_index")) != 0 {
		t.Errorf("arg_index = %v", objAt(f, "arg_index"))
	}
	if intOf(objAt(f, "echoes_attacker_step")) != 2 {
		t.Errorf("echoes = %v", objAt(f, "echoes_attacker_step"))
	}
	if !strings.Contains(objStr(f, "note"), "public information") {
		t.Errorf("note = %q", objStr(f, "note"))
	}
}

func TestPublicInformationNotFlagged(t *testing.T) {
	seq := mustParse(t, `[
      {"step": 1, "actor": "attacker", "function": "deposit",
       "args": [1000000000000000]},
      {"step": 2, "actor": "victim", "function": "deposit",
       "args": [100000000000000000000000000]}]`)
	if got := BenignActorAudit(seq, cast); len(got) != 0 {
		t.Errorf("flags = %v, want none", got)
	}
}

func TestSingleActorAndUnknownActorsNoFlags(t *testing.T) {
	seq := mustParse(t, `[
      {"step": 1, "actor": "solo", "function": "deposit", "args": [5]},
      {"step": 2, "actor": "victim", "function": "deposit", "args": [5]}]`)
	if got := BenignActorAudit(seq, cast); len(got) != 0 {
		t.Errorf("flags = %v, want none", got)
	}
}

func TestNonDictStepsIgnored(t *testing.T) {
	seq := mustParse(t, `["garbage", {"step": 1, "actor": "victim", "args": [1]}]`)
	if got := BenignActorAudit(seq, cast); len(got) != 0 {
		t.Errorf("flags = %v, want none", got)
	}
}

// --- fixture helpers -------------------------------------------------------

// enumHas is `"x" in schema-enum`.
func enumHas(kinds validation.Value, want string) bool {
	for _, v := range listOf(objAt(kinds, "enum")) {
		if v.Kind == validation.Str && v.S == want {
			return true
		}
	}
	return false
}

// cloneStep deep-copies step i of the spec (json round-trip in Python).
func cloneStep(t *testing.T, spec validation.Value, i int) validation.Value {
	t.Helper()
	steps := listOf(objAt(spec, "steps"))
	raw := validation.DumpIndented(steps[i])
	v, err := validation.ParseOrdered([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// appendStep appends a step to the spec's steps array.
func appendStep(spec, step validation.Value) validation.Value {
	for i, kv := range spec.O {
		if kv.K == "steps" {
			spec.O[i].V.A = append(spec.O[i].V.A, step)
		}
	}
	return spec
}

// delPath deletes a key at the given object path (Python's `pop`).
func delPath(v validation.Value, path ...string) validation.Value {
	if len(path) == 1 {
		for i, kv := range v.O {
			if kv.K == path[0] {
				v.O = append(v.O[:i], v.O[i+1:]...)
				return v
			}
		}
		return v
	}
	head := path[0]
	if head[0] >= '0' && head[0] <= '9' {
		idx := int(head[0] - '0')
		v.A[idx] = delPath(v.A[idx], path[1:]...)
		return v
	}
	for i, kv := range v.O {
		if kv.K == head {
			v.O[i].V = delPath(kv.V, path[1:]...)
		}
	}
	return v
}

// reorderKeys rebuilds the value with keys in reverse-sorted order at the
// top level (nested too when deep).
func reorderKeys(t *testing.T, v validation.Value, deep bool) validation.Value {
	t.Helper()
	out := validation.VObj()
	keys := objKeys(v)
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, k := range keys {
		val := objAt(v, k)
		if deep && val.Kind == validation.Arr {
			items := make([]validation.Value, len(val.A))
			for i, it := range val.A {
				if it.Kind == validation.Obj {
					items[i] = reorderKeys(t, it, false)
				} else {
					items[i] = it
				}
			}
			val = validation.VArr(items...)
		}
		out.O = append(out.O, validation.KV{K: k, V: val})
	}
	return out
}
