package floors

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- fixtures ------------------------------------------------------------

// camp is the conftest `camp` fixture: Campaign.init(tmp_path, "test-program").
func camp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "test-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ptr is a string pointer for the floor-override reads.
func ptr(s string) *string { return &s }

// setPolicy is the happy-path set_floor_policy with a valid actor/reason.
func setPolicy(t *testing.T, c *state.Campaign, class, floor string) validation.Value {
	t.Helper()
	entry, err := SetFloorPolicy(c, class, floor, "op", "a written reason of length")
	if err != nil {
		t.Fatalf("set_floor_policy(%q, %q): %v", class, floor, err)
	}
	return entry
}

// rowOf is the floor_table_report row for one class.
func rowOf(t *testing.T, report validation.Value, class string) validation.Value {
	t.Helper()
	for _, r := range objAt(report, "rows").A {
		if objStr(r, "class") == class {
			return r
		}
	}
	t.Fatalf("no report row for class %q", class)
	return validation.VNull()
}

// eventTypes counts the campaign's events of one type.
func eventTypes(t *testing.T, c *state.Campaign, kind string) []validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var out []validation.Value
	for _, e := range events {
		if objStr(e, "type") == kind {
			out = append(out, e)
		}
	}
	return out
}

// ---- tests/test_floors.py ------------------------------------------------

func TestSetRequiresActorAndReason(t *testing.T) {
	c := camp(t)
	_, err := SetFloorPolicy(c, "reentrancy", "E4", "", "reason")
	if err == nil || !strings.Contains(err.Error(), "actor") {
		t.Errorf("empty actor: want an actor error, got %v", err)
	}
	_, err = SetFloorPolicy(c, "reentrancy", "E4", "op", "short")
	if err == nil || !strings.Contains(err.Error(), "reason") {
		t.Errorf("short reason: want a reason error, got %v", err)
	}
}

func TestSetClearEffective(t *testing.T) {
	c := camp(t)
	ov, err := FloorOverride(c, "reentrancy")
	if err != nil || ov != nil {
		t.Fatalf("fresh campaign override = %v, %v; want nil, nil", ov, err)
	}
	if got := EffectiveFloor(c, "CONFIRMED", "reentrancy"); got != "E4" {
		t.Fatalf("built-in CONFIRMED floor = %q, want E4", got)
	}

	SetFloorPolicy(c, "reentrancy", "E5", "lead", "deployed mainnet fork available")
	ov, err = FloorOverride(c, "reentrancy")
	if err != nil || ov == nil || *ov != "E5" {
		t.Fatalf("override = %v, %v; want E5", ov, err)
	}
	if got := EffectiveFloor(c, "CONFIRMED", "reentrancy"); got != "E5" {
		t.Errorf("effective floor after set = %q, want E5", got)
	}

	// the gate for the class follows the override, not the hardcoded table
	if got := findings.RequiredLevelForCampaign(c, "CONFIRMED", "reentrancy"); got != "E5" {
		t.Errorf("required_level_for_campaign(camp) = %q, want E5", got)
	}
	if got := findings.RequiredLevelForCampaign(nil, "CONFIRMED", "reentrancy"); got != "E4" {
		t.Errorf("required_level_for_campaign(nil) = %q, want E4", got)
	}

	if err := ClearFloorPolicy(c, "reentrancy", "lead", "override no longer needed"); err != nil {
		t.Fatalf("clear_floor_policy: %v", err)
	}
	ov, err = FloorOverride(c, "reentrancy")
	if err != nil || ov != nil {
		t.Fatalf("override after clear = %v, %v; want nil, nil", ov, err)
	}
	if got := EffectiveFloor(c, "CONFIRMED", "reentrancy"); got != "E4" {
		t.Errorf("effective floor after clear = %q, want E4", got)
	}
}

func TestClearUnknownClassRaises(t *testing.T) {
	c := camp(t)
	err := ClearFloorPolicy(c, "reentrancy", "op", "no override to clear")
	if err == nil {
		t.Fatal("clearing an unknown class must fail")
	}
	if !errors.Is(err, ErrNoFloorOverride) {
		t.Errorf("error %v does not wrap ErrNoFloorOverride", err)
	}
	want := "no floor override for class 'reentrancy' in this campaign"
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}
}

func TestEffectiveFloorIgnoresOverrideForOtherStatuses(t *testing.T) {
	// Overrides are a CONFIRMED-floor decision; POSSIBLE keeps its own ladder
	// (E2) — an override must never leak into a status it wasn't made for.
	c := camp(t)
	SetFloorPolicy(c, "reentrancy", "E6", "op", "stress the boundary")
	if got := findings.RequiredLevelForCampaign(c, "POSSIBLE", "reentrancy"); got != "E2" {
		t.Errorf("POSSIBLE floor = %q, want E2", got)
	}
	if got := findings.RequiredLevelForCampaign(c, "CONFIRMED", "reentrancy"); got != "E6" {
		t.Errorf("CONFIRMED floor = %q, want E6", got)
	}
}

func TestGateRequirementsUseEffectiveFloor(t *testing.T) {
	// The economic 3-clause gate's fork clause follows the campaign's
	// effective floor (the previous code hardcoded E5).
	c := camp(t)
	SetFloorPolicy(c, "oracle-manipulation", "E4", "op",
		"no fork infra in this campaign")
	clauses := findings.GateRequirements("CONFIRMED", "oracle-manipulation", c)
	if len(clauses) != 3 {
		t.Fatalf("gate clauses = %d, want 3", len(clauses))
	}
	// clause 1 (fork-poc | independent-repro) minimum = effective floor
	if clauses[1].MinLevel != "E4" {
		t.Errorf("fork clause min_level = %q, want E4", clauses[1].MinLevel)
	}
	builtin := findings.GateRequirements("CONFIRMED", "oracle-manipulation", nil)
	if builtin[1].MinLevel != "E5" {
		t.Errorf("built-in fork clause min_level = %q, want E5", builtin[1].MinLevel)
	}
}

func TestFloorTableReportMixesDefaultsAndOverrides(t *testing.T) {
	c := camp(t)
	SetFloorPolicy(c, "reentrancy", "E5", "lead", "mainnet fork is available")
	rep, err := FloorTableReport(c)
	if err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, rep, "reentrancy")
	if got := objStr(row, "default_floor"); got != "E4" {
		t.Errorf("reentrancy default_floor = %q, want E4", got)
	}
	if got := objStr(row, "effective_floor"); got != "E5" {
		t.Errorf("reentrancy effective_floor = %q, want E5", got)
	}
	if got := objStr(objAt(row, "override"), "actor"); got != "lead" {
		t.Errorf("reentrancy override actor = %q, want lead", got)
	}
	// a class with no override shows the default
	other := rowOf(t, rep, "oracle-manipulation")
	if objAt(other, "override").Kind != validation.Null {
		t.Errorf("oracle-manipulation override = %v, want None",
			validation.PyRepr(objAt(other, "override")))
	}
	if got := objStr(other, "effective_floor"); got != "E5" {
		t.Errorf("oracle-manipulation effective_floor = %q, want E5", got)
	}
}

func TestPolicyFileSeedsAtInit(t *testing.T) {
	// PORT-NOTE: Python's Campaign.init(..., floor_policy_path=...) is not
	// modelled by state.InitOpts yet (see the seam report), so the portable
	// part drives ApplyPolicyFile directly — the same call init makes, in the
	// same order, and the same events.
	dir := t.TempDir()
	pol := filepath.Join(dir, "floors.json")
	body := `{"overrides": [
  {"class": "reentrancy", "floor": "E5", "reason": "playground has a public fork endpoint"},
  {"class": "bridge-message", "floor": "E4", "reason": "bridge is a local simulation rig"}
]}`
	if err := os.WriteFile(pol, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := state.Init(filepath.Join(dir, "root"), "test-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyPolicyFile(c, pol); err != nil {
		t.Fatal(err)
	}
	if got := EffectiveFloor(c, "CONFIRMED", "reentrancy"); got != "E5" {
		t.Errorf("reentrancy floor = %q, want E5", got)
	}
	if got := EffectiveFloor(c, "CONFIRMED", "bridge-message"); got != "E4" {
		t.Errorf("bridge-message floor = %q, want E4", got)
	}
	if got := EffectiveFloor(c, "CONFIRMED", "access-control"); got != "E4" {
		t.Errorf("access-control floor = %q, want E4", got)
	}
	// every seed is logged with the same attribution as a runtime decision
	events := eventTypes(t, c, "floor_policy.set")
	if len(events) != 2 {
		t.Fatalf("floor_policy.set events = %d, want 2", len(events))
	}
	for _, e := range events {
		if got := objStr(objAt(e, "data"), "actor"); got != "campaign-init" {
			t.Errorf("seeded event actor = %q, want campaign-init", got)
		}
	}
}

func TestAuditCatchesHandEditedPolicy(t *testing.T) {
	// PORT-NOTE: the Python test asserts
	// AUDIT.audit_campaign(camp)["sections"]["floor_policy"]["ok"]; the Go
	// audit registry has no floor_policy section yet (KNOWN_DIVERGENCES D2).
	// The portable part is the evidence that section consumes: the LOG holds
	// the real decision, so a hand-edited projection is visible as drift.
	c := camp(t)
	SetFloorPolicy(c, "reentrancy", "E5", "lead", "mainnet fork available")

	// hand-edit the state projection, bypassing the API — the reason must
	// stay schema-valid; the point is the LOG has no matching event
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	forged := validation.VObj(
		kv("class", validation.VStr("reentrancy")),
		kv("floor", validation.VStr("E6")),
		kv("actor", validation.VStr("malicious")),
		kv("reason", validation.VStr("forged entry of sufficient length")),
		kv("at", validation.VStr("2026-01-01T00:00:00Z")),
	)
	st.O = setOrAppend(st.O, "floor_policy", validation.VArr(forged))
	if err := saveStateFunc(c, st); err != nil {
		t.Fatal(err)
	}
	events := eventTypes(t, c, "floor_policy.set")
	if len(events) != 1 {
		t.Fatalf("floor_policy.set events = %d, want 1", len(events))
	}
	// the log says E5, the projection says E6 — drift is the diagnosis
	if got := objStr(objAt(events[0], "data"), "floor"); got != "E5" {
		t.Errorf("logged floor = %q, want E5", got)
	}
	ov, err := FloorOverride(c, "reentrancy")
	if err != nil || ov == nil || *ov != "E6" {
		t.Fatalf("projection floor = %v, %v; want E6", ov, err)
	}
}

func TestAuditCatchesProjectionDrift(t *testing.T) {
	// PORT-NOTE: see TestAuditCatchesHandEditedPolicy — the audit section is
	// unported, so this asserts the log-vs-projection drift itself.
	c := camp(t)
	SetFloorPolicy(c, "reentrancy", "E5", "lead", "mainnet fork available")
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	policy := objAt(st, "floor_policy")
	policy.A[0].O[1].V = validation.VStr("E4")
	st.O = setOrAppend(st.O, "floor_policy", policy)
	if err := saveStateFunc(c, st); err != nil {
		t.Fatal(err)
	}
	events := eventTypes(t, c, "floor_policy.set")
	if got := objStr(objAt(events[0], "data"), "floor"); got != "E5" {
		t.Errorf("logged floor = %q, want E5", got)
	}
	ov, err := FloorOverride(c, "reentrancy")
	if err != nil || ov == nil || *ov != "E4" {
		t.Fatalf("projection floor = %v, %v; want E4", ov, err)
	}
}

func TestStateSchemaAcceptsFloorPolicy(t *testing.T) {
	// the state must stay schema-valid after a set (campaign._save runs it)
	c := camp(t)
	SetFloorPolicy(c, "reentrancy", "E4", "op",
		"regression guard for the schema field")
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(objAt(st, "floor_policy").A[0], "class"); got != "reentrancy" {
		t.Errorf("floor_policy[0].class = %q, want reentrancy", got)
	}
}

// ---- byte-exact vectors --------------------------------------------------

type kebabCase struct {
	Value string `json:"value"`
	Match bool   `json:"match"`
}

func TestKebabClassRegexVectors(t *testing.T) {
	var vectors []kebabCase
	loadVectors(t, "kebab_regex.json", &vectors)
	if len(vectors) < 30 {
		t.Fatalf("vector table too small: %d", len(vectors))
	}
	for _, v := range vectors {
		if got := classRe.MatchString(v.Value); got != v.Match {
			t.Errorf("classRe.MatchString(%q) = %v, want %v",
				v.Value, got, v.Match)
		}
	}
}

type floorErrorCase struct {
	Kind      string  `json:"kind"`
	Name      string  `json:"name"`
	Cls       *string `json:"cls"`
	Floor     *string `json:"floor"`
	Actor     *string `json:"actor"`
	Reason    *string `json:"reason"`
	Text      string  `json:"text"`
	ErrorKind string  `json:"error_kind"`
	Error     string  `json:"error"`
}

func TestFloorPolicyErrorVectors(t *testing.T) {
	var vectors []floorErrorCase
	loadVectors(t, "floors_errors.json", &vectors)
	if len(vectors) < 25 {
		t.Fatalf("vector table too small: %d", len(vectors))
	}
	c := camp(t)
	for i, v := range vectors {
		var err error
		switch v.Kind {
		case "set":
			_, err = SetFloorPolicy(c, orDefault(v.Cls, "reentrancy"),
				orDefault(v.Floor, "E4"), orDefault(v.Actor, "op"),
				orDefault(v.Reason, "a good reason"))
		case "clear":
			err = ClearFloorPolicy(c, orDefault(v.Cls, "reentrancy"),
				orDefault(v.Actor, "op"), orDefault(v.Reason, "a good reason"))
		case "file":
			dir := t.TempDir()
			p := filepath.Join(dir, v.Name)
			if werr := os.WriteFile(p, []byte(v.Text), 0o644); werr != nil {
				t.Fatal(werr)
			}
			_, err = LoadPolicyFile(p)
			if v.ErrorKind == "ValueError" {
				v.Error = strings.ReplaceAll(v.Error, "{dir}", dir)
			}
		default:
			t.Fatalf("vector %d: unknown kind %q", i, v.Kind)
		}
		if v.ErrorKind == "" {
			if err != nil {
				t.Errorf("vector %d (%s %s): unexpected error %v", i, v.Kind, v.Name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("vector %d (%s %s): want %s, got no error",
				i, v.Kind, vectorLabel(v), v.Error)
			continue
		}
		want := v.Error
		if v.ErrorKind == "KeyError" {
			// Python's str(KeyError(msg)) is the repr of the argument; the
			// Go twin's Error() is the message itself.
			want = strings.TrimSuffix(strings.TrimPrefix(want, `"`), `"`)
			if !errors.Is(err, ErrNoFloorOverride) {
				t.Errorf("vector %d: error does not wrap ErrNoFloorOverride", i)
			}
		}
		if err.Error() != want {
			t.Errorf("vector %d (%s %s):\n got %q\nwant %q",
				i, v.Kind, vectorLabel(v), err.Error(), want)
		}
	}
}

// vectorLabel names a vector case for failure output.
func vectorLabel(v floorErrorCase) string {
	if v.Kind == "file" {
		return v.Name
	}
	return orDefault(v.Cls, "reentrancy")
}

// TestTrailingNewlineClassSchemaDivergence pins the one RE2-vs-Python gap
// around the kebab-case contract: classRe accepts "abc\n" (Python's $ matches
// before a trailing newline, and the RE2 transcription keeps that with "\n?"),
// while the campaign_state schema pattern is applied by the Go jsonschema
// engine with RE2 semantics, where "abc\n" does not match ^[a-z0-9-]{3,64}$.
func TestTrailingNewlineClassSchemaDivergence(t *testing.T) {
	if !classRe.MatchString("abc\n") {
		t.Fatal(`classRe must accept "abc\n" (Python re.match does)`)
	}
	c := camp(t)
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	entry := validation.VObj(
		kv("class", validation.VStr("abc\n")),
		kv("floor", validation.VStr("E4")),
		kv("actor", validation.VStr("op")),
		kv("reason", validation.VStr("a good reason of length")),
		kv("at", validation.VStr("2026-01-01T00:00:00.000000+00:00")),
	)
	st.O = setOrAppend(st.O, "floor_policy", validation.VArr(entry))
	if err := validation.Validate(st, "campaign_state", 1); err == nil {
		t.Error("the Go schema unexpectedly accepts a trailing-newline class; " +
			"drop the divergence note")
	}
}

// TestFloorPolicyGoldenBytes is the cross-twin byte check: the same pinned
// sequence run by the Python twin must produce byte-identical
// campaign_state.json and events.jsonl. The golden files were generated by
// the Python reference with WEBV2_NOW / WEBV2_UUID pinned.
func TestFloorPolicyGoldenBytes(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	t.Setenv("WEBV2_UUID", "floors-golden")
	c, err := state.Init(t.TempDir(), "test-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	mustSet := func(class, floor, actor, reason string) {
		t.Helper()
		if _, err := SetFloorPolicy(c, class, floor, actor, reason); err != nil {
			t.Fatal(err)
		}
	}
	mustSet("reentrancy", "E5", "lead", "deployed mainnet fork available")
	mustSet("bridge-message", "E4", "op", "bridge is a local simulation rig")
	if err := ClearFloorPolicy(c, "reentrancy", "lead", "override no longer needed"); err != nil {
		t.Fatal(err)
	}
	mustSet("reentrancy", "E4", "lead", "back to the default floor")
	mustSet("reentrancy", "E6", "lead", "re-set replaces the previous entry")

	if got := c.CampaignID; got != "C-59aab5aadb" {
		t.Errorf("campaign id = %q, want the pinned C-59aab5aadb", got)
	}
	compareBytes(t, c.StatePath, filepath.Join("testdata", "golden", "campaign_state.json"))
	compareBytes(t, c.EventsPath, filepath.Join("testdata", "golden", "events.jsonl"))
}

// ---- local helpers -------------------------------------------------------

// loadVectors decodes a committed vector table (generated by the Python twin).
func loadVectors(t *testing.T, name string, out any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
}

// compareBytes asserts a produced file is byte-identical to its golden.
func compareBytes(t *testing.T, got, want string) {
	t.Helper()
	gotBytes, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBytes) != string(wantBytes) {
		t.Errorf("%s differs from %s\n got:\n%s\nwant:\n%s",
			got, want, gotBytes, wantBytes)
	}
}

// orDefault models Python's keyword default: absent is the zero value, an
// explicitly empty string stays empty.
func orDefault(v *string, fallback string) string {
	if v == nil {
		return fallback
	}
	return *v
}

// TestFloorTableReportGolden pins the report's bytes (key order, null
// overrides, pinned timestamps) against the Python twin's json.dumps.
func TestFloorTableReportGolden(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	t.Setenv("WEBV2_UUID", "report-golden")
	c, err := state.Init(t.TempDir(), "test-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SetFloorPolicy(c, "reentrancy", "E5", "lead",
		"mainnet fork is available"); err != nil {
		t.Fatal(err)
	}
	if _, err := SetFloorPolicy(c, "bridge-message", "E4", "op",
		"bridge is a local simulation rig"); err != nil {
		t.Fatal(err)
	}
	rep, err := FloorTableReport(c)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes, err := os.ReadFile(filepath.Join("testdata", "vectors",
		"floor_table_report.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSuffix(string(wantBytes), "\n")
	if got := validation.CanonCompact(rep); got != want {
		t.Errorf("floor_table_report = %s\n want %s", got, want)
	}
}

type applyVector struct {
	Name            string          `json:"name"`
	Override        json.RawMessage `json:"override"`
	Error           *string         `json:"error"`
	FloorPolicyJSON *string         `json:"floor_policy_json"`
}

// TestApplyPolicyFileVectors pins apply_policy_file's isinstance contract for
// values that arrive from JSON: a non-string class/floor/reason is rendered
// with CPython's repr in the error, and a truthy non-string reason becomes
// str(value) before the >= 10 char rule applies.
func TestApplyPolicyFileVectors(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	var vectors []applyVector
	loadVectors(t, "floors_apply.json", &vectors)
	if len(vectors) < 20 {
		t.Fatalf("vector table too small: %d", len(vectors))
	}
	ok, failed := 0, 0
	for _, v := range vectors {
		c := camp(t)
		body := `{"overrides": [` + string(v.Override) + `]}`
		// the Python generator wrote every case to "policy.json": the
		// fallback reason names the file, so the name is part of the vector
		p := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := ApplyPolicyFile(c, p)
		if v.Error == nil {
			if err != nil {
				t.Errorf("%s: unexpected error %v", v.Name, err)
				continue
			}
			ok++
			st, err := c.State()
			if err != nil {
				t.Fatal(err)
			}
			if got := validation.CanonCompact(objAt(st, "floor_policy")); got != *v.FloorPolicyJSON {
				t.Errorf("%s: floor_policy = %s\n want %s",
					v.Name, got, *v.FloorPolicyJSON)
			}
			continue
		}
		failed++
		if err == nil {
			t.Errorf("%s: want %q, got no error", v.Name, *v.Error)
			continue
		}
		if err.Error() != *v.Error {
			t.Errorf("%s:\n got %q\nwant %q", v.Name, err.Error(), *v.Error)
		}
	}
	if ok < 5 || failed < 8 {
		t.Errorf("vector mix = %d ok / %d failed; want both cases", ok, failed)
	}
}

// TestClockAndSaveSeams pins the two seams the Python module reaches for
// through state/campaign: now_iso() and campaign._save(st).
func TestClockAndSaveSeams(t *testing.T) {
	c := camp(t)
	SetNowIso(func() string { return "2030-01-01T00:00:00.000000+00:00" })
	defer SetNowIso(nil)
	entry := setPolicy(t, c, "reentrancy", "E5")
	if got := objStr(entry, "at"); got != "2030-01-01T00:00:00.000000+00:00" {
		t.Errorf("seam clock not used: at = %q", got)
	}

	calls := 0
	SetSaveState(func(*state.Campaign, validation.Value) error {
		calls++
		return nil
	})
	defer SetSaveState(nil)
	if _, err := SetFloorPolicy(c, "reentrancy", "E6", "op",
		"another written reason"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("save seam calls = %d, want 1", calls)
	}
	// the seam really replaced the writer: the state file still holds E5
	ov, err := FloorOverride(c, "reentrancy")
	if err != nil || ov == nil || *ov != "E5" {
		t.Errorf("persisted override = %v, %v; want the pre-seam E5", ov, err)
	}
}
