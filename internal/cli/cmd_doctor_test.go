// T26 cmd_doctor tests: the CLI-level tests of tests/test_doctor.py and
// tests/test_doctor_preflight.py (Python wins), plus the argparse surface.
package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"websec/internal/envgo"
	"websec/internal/state"
	"websec/internal/validation"
)

// bloat is test_doctor.py's _bloat: write an oversized stage note directly,
// bypassing the cap that set_stage applies.
func bloat(t *testing.T, root, cid, stage string, chars int) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	stages := validation.ObjAt(st, "stages")
	stages.O = validation.SetOrAppend(stages.O, stage, validation.VObj(
		validation.KV{K: "status", V: validation.VStr("done")},
		validation.KV{K: "note", V: validation.VStr(strings.Repeat("x", chars))},
		validation.KV{K: "executor", V: validation.VStr("pipeline")}))
	st.O = validation.SetOrAppend(st.O, "stages", stages)
	if err := validation.WriteJson(c.StatePath, st, ""); err != nil {
		t.Fatal(err)
	}
}

// healthyEnv is test_doctor_preflight.py's _up: a healthy docker environment.
func healthyEnv(t *testing.T) {
	t.Helper()
	envgo.SetDockerDaemonOK(func() bool { return true })
	envgo.SetDockerImageProbe(func(*string) validation.Value {
		return validation.VObj(
			validation.KV{K: "image", V: validation.VStr("ghcr.io/test/img")},
			validation.KV{K: "daemon", V: validation.VBool(true)},
			validation.KV{K: "present", V: validation.VBool(true)},
			validation.KV{K: "digest", V: validation.VStr("sha256:abcd0123")},
			validation.KV{K: "pinned", V: validation.VBool(true)},
			validation.KV{K: "detail", V: validation.VStr("digest-pinned")})
	})
	envgo.SetSolcDir(func() *string { return nil })
	t.Cleanup(func() {
		envgo.SetDockerDaemonOK(nil)
		envgo.SetDockerImageProbe(nil)
		envgo.SetSolcDir(nil)
	})
}

func TestCLIDoctorRunsAndReports(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	bloat(t, root, cid, "campaign-planning", 80_000)
	code, out, errS := run(t, "--root", root, "doctor", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	for _, want := range []string{"state", "snapshot", "campaign-planning"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want %q", out, want)
		}
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestCLIDoctorJSON(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "doctor", cid, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if _, ok := data["state"]; !ok {
		t.Errorf("json = %s, want a state key", out)
	}
	if _, ok := data["snapshot"]; !ok {
		t.Errorf("json = %s, want a snapshot key", out)
	}
}

func TestCLIDoctorPrintsPreflight(t *testing.T) {
	healthyEnv(t)
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "doctor", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(strings.ToLower(out), "preflight") {
		t.Fatalf("stdout = %q, want a preflight section", out)
	}
}

func TestCLIDoctorStateOnlyAndSnapshotOnly(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, _ := run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("--state-only exit %d", code)
	}
	if !strings.Contains(out, "state:") || strings.Contains(out, "snapshot") {
		t.Errorf("--state-only stdout = %q", out)
	}
	code, out, _ = run(t, "--root", root, "doctor", cid, "--snapshot-only")
	if code != 0 {
		t.Fatalf("--snapshot-only exit %d", code)
	}
	if !strings.Contains(out, "snapshot") || strings.Contains(out, "state:") {
		t.Errorf("--snapshot-only stdout = %q", out)
	}
}

func TestCLIDoctorArgparse(t *testing.T) {
	code, out, errS := run(t, "doctor")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	want := t26DoctorUsage + "webv2 doctor: error: the following arguments " +
		"are required: campaign\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	code, out, errS = run(t, "doctor", "C-abc", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("help exit %d err=%q", code, errS)
	}
	if out != t26DoctorHelp {
		t.Fatalf("help = %q, want %q", out, t26DoctorHelp)
	}
}

// TestDoctorRejectsBothModes pins the exclusion: passing both modes used to
// resolve silently to --snapshot-only, so a requested repair never ran and
// the exit status said everything was fine.
func TestDoctorRejectsBothModes(t *testing.T) {
	root := mkroot(t)
	code, out, errS := run(t, "--root", root, "doctor", "C-1",
		"--state-only", "--snapshot-only")
	if code != 2 {
		t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "argument --snapshot-only: not allowed with "+
		"argument --state-only") {
		t.Errorf("stderr = %q, want the mutual-exclusion message", errS)
	}
}
