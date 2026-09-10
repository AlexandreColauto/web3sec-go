// T26 cmd_env tests: the human view of `env doctor` (line for line against
// cli.py cmd_env_doctor) and the --json exit-code quirk. The synthetic
// report pins the rendering without needing a docker daemon.
package cli

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// t26EnvReport is a report shaped like env.doctor's: healthy docker, an
// unpinned image, no fork, one profile missing, a campaign section, an
// absent solc, and issues (so ok=false).
func t26EnvReport() validation.Value {
	return validation.VObj(
		validation.KV{K: "docker", V: validation.VObj(
			validation.KV{K: "cli", V: validation.VBool(true)},
			validation.KV{K: "daemon", V: validation.VBool(true)},
			validation.KV{K: "image", V: validation.VObj(
				validation.KV{K: "image", V: validation.VStr("ghcr.io/x/img")},
				validation.KV{K: "present", V: validation.VBool(true)},
				validation.KV{K: "pinned", V: validation.VBool(false)},
				validation.KV{K: "digest", V: validation.VStr("sha256:ab")},
			)},
		)},
		validation.KV{K: "fork_rpc", V: validation.VObj(
			validation.KV{K: "url", V: validation.VNull()},
			validation.KV{K: "reachable", V: validation.VBool(false)},
			validation.KV{K: "error", V: validation.VStr("not set")},
		)},
		validation.KV{K: "profiles", V: validation.VObj(
			validation.KV{K: "host-readonly", V: validation.VBool(true)},
			validation.KV{K: "docker-networkless", V: validation.VBool(true)},
			validation.KV{K: "vm-snapshot", V: validation.VBool(false)},
		)},
		validation.KV{K: "campaign", V: validation.VObj(
			validation.KV{K: "max_confirm_floor",
				V: validation.VStr("E6")},
			validation.KV{K: "chain_pin", V: validation.VBool(false)},
		)},
		validation.KV{K: "solc", V: validation.VObj(
			validation.KV{K: "required", V: validation.VStr("0.8.24")},
			validation.KV{K: "present", V: validation.VBool(false)},
			validation.KV{K: "checked", V: validation.VBool(true)},
		)},
		validation.KV{K: "issues", V: validation.VArr(
			validation.VStr("fork RPC unreachable"),
			validation.VStr("solc missing"),
		)},
		validation.KV{K: "ok", V: validation.VBool(false)},
		// feedback-triage A7: the floor cross-check. docker-networkless is
		// available but E4-only against this campaign's E6 floor;
		// vm-snapshot is unavailable and so absent from the fit.
		validation.KV{K: "profile_fit", V: validation.VObj(
			validation.KV{K: "docker-networkless",
				V: validation.VStr("E4-only (campaign floor E6)")},
		)},
	)
}

func TestPrintEnvDoctorText(t *testing.T) {
	var out strings.Builder
	printEnvDoctor(&Runner{Out: &out}, t26EnvReport())
	want := "" +
		"docker:        cli=yes  daemon=yes\n" +
		"image:         ghcr.io/x/img — present (tag reference!)\n" +
		"  local digest: sha256:ab\n" +
		"fork RPC:      (unset) — UNREACHABLE (not set)\n" +
		"profiles:      host-readonly=ok docker-networkless=E4-only " +
		"(campaign floor E6) vm-snapshot=NO\n" +
		"campaign:      max CONFIRMED floor E6, chain pin NO\n" +
		"solc:          0.8.24 — ABSENT from image\n" +
		"\nISSUES:\n" +
		"  - fork RPC unreachable\n" +
		"  - solc missing\n"
	if out.String() != want {
		t.Fatalf("text = %q, want %q", out.String(), want)
	}
}

func TestPrintEnvDoctorNoIssues(t *testing.T) {
	report := t26EnvReport()
	report.O = validation.SetOrAppend(report.O, "issues", validation.VArr())
	report.O = validation.SetOrAppend(report.O, "ok", validation.VBool(true))
	var out strings.Builder
	printEnvDoctor(&Runner{Out: &out}, report)
	if !strings.HasSuffix(out.String(), "\nno issues — the environment "+
		"can back the evidence this campaign requires\n") {
		t.Fatalf("text = %q", out.String())
	}
}

func TestEnvDoctorJSONExitsZeroOnIssues(t *testing.T) {
	// cli.py's --json branch prints and returns: exit 0 even when the
	// report is not ok (the text surface carries the CI exit code).
	root := mkroot(t)
	code, out, errS := run(t, "--root", root, "env", "doctor", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "{\n") || !strings.Contains(out, "\"ok\":") {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestEnvDoctorBadCampaign(t *testing.T) {
	root := mkroot(t)
	code, _, errS := run(t, "--root", root, "env", "doctor", "C-nope")
	if code != 1 {
		t.Fatalf("exit %d err=%q", code, errS)
	}
	if !strings.Contains(errS, "C-nope") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestEnvBarePrintsOwnHelp(t *testing.T) {
	// KNOWN DIVERGENCE D23: the reference's bare `webv2 env` runs a
	// late-bound lambda whose `s` has been rebound to the LAST parser built
	// (today `sft`), so it prints the wrong help; the Go twin prints the env
	// usage block. Recorded in KNOWN_DIVERGENCES.md.
	code, out, errS := run(t, "env")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err=%q", code, errS)
	}
	if out != t26EnvHelp {
		t.Fatalf("stdout = %q, want %q", out, t26EnvHelp)
	}
	code, out, errS = run(t, "env", "nope")
	if code != 2 || out != "" {
		t.Fatalf("bad action: exit %d out=%q err=%q", code, out, errS)
	}
	want := t26EnvUsage + "webv2 env: error: argument env_action: invalid " +
		"choice: 'nope' (choose from 'doctor')\n"
	if errS != want {
		t.Fatalf("bad action stderr = %q, want %q", errS, want)
	}
}
