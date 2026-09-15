package cli

// zz_r38a_test.go: r38 pins at the WIRED seam. r36 made the sandbox
// default classifier honest (per-profile / per-evidence exit 125/126/127),
// but ensureSeams installs envgo.ClassifyFailure OVER that seam, so the
// shipped binary still spoke the stale transcription. The sandbox-side
// test (internal/sandbox/zz_r36_test.go) exercises the in-package default
// and therefore passed vacuously; everything here drives the classifier
// exactly as the CLI carries it:
//
//   - TestR38ExecVerbHost127Honest: the `exec` verb end-to-end with a
//     missing command / a non-executable file on host-readonly (no docker
//     involved) — the "classified:" line the operator actually reads.
//   - TestR38ClassifyVerbContainerShapes: the `classify` verb end-to-end
//     over ledger records — container 127 with in-container "not found"
//     evidence, container 127 with docker's own error text, container 125,
//     and the no-output inconclusive shape.
//   - TestR38SeamAuditWiredCopies: the ensureSeams seam audit (see the
//     table at the bottom of this file) — behavioral pins for the three
//     seams whose envgo side is a COPY of a sandbox default (the only
//     seams where a stale transcription can exist), plus the wired==source
//     differential for each.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/envgo"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// r38Camp initializes a campaign and returns root + id.
func r38Camp(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	return root, initOne(t, root)
}

// TestR38ExecVerbHost127Honest drives the exec verb end-to-end: a missing
// command must classify as the host-shell "could not find the command"
// note, never the docker sentence; a found-but-not-executable file must
// get the 126 note.
func TestR38ExecVerbHost127Honest(t *testing.T) {
	root, cid := r38Camp(t)
	ensureSeams()
	code, out, errS := run(t, "--root", root, "exec", cid,
		"--profile", "host-readonly", "--command", "nonexistent-cmd-xyz-r38")
	if code != 0 {
		t.Fatalf("exec exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "classified: ENVIRONMENT") {
		t.Fatalf("exec output lacks the classification line: %q", out)
	}
	if !strings.Contains(out, "could not find the command") {
		t.Errorf("host 127 must name the missing command: %q", out)
	}
	if strings.Contains(out, "docker itself failed before the command ran") {
		t.Errorf("host 127 still lies about docker: %q", out)
	}

	// exit 126: the command exists but is not executable.
	noexec := filepath.Join(t.TempDir(), "not-executable-r38")
	if err := os.WriteFile(noexec, []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS = run(t, "--root", root, "exec", cid,
		"--profile", "host-readonly", "--command", noexec)
	if code != 0 {
		t.Fatalf("exec 126 exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "not executable") {
		t.Errorf("host 126 must name the permission problem: %q", out)
	}
	if strings.Contains(out, "docker itself failed before the command ran") {
		t.Errorf("host 126 still lies about docker: %q", out)
	}
}

// TestR38ClassifyVerbContainerShapes registers container-profile records
// in the exec ledger and drives the classify verb end-to-end over them.
func TestR38ClassifyVerbContainerShapes(t *testing.T) {
	root, cid := r38Camp(t)
	ensureSeams()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	reg := func(name, stdout, stderr string, exit int) string {
		t.Helper()
		rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
			Profile: "docker-networkless", Command: "nonexistent-cmd-xyz",
			ReportedBy: "harness", ExitStatus: exit,
			StdoutText: stdout, StderrText: stderr})
		if err != nil {
			t.Fatal(err)
		}
		return objStr(rec, "exec_id")
	}
	cases := []struct {
		name        string
		stdout      string
		exit        int
		wantSignals []string
		wantNote    string
		notNote     string
	}{
		{"container-127-command-ran",
			"sh: 1: nonexistent-cmd-xyz: not found\n", 127,
			[]string{"exit 127 with captured output present", "the command ran"},
			"RAN inside the container", "docker itself failed before"},
		{"container-127-docker-error-text",
			"Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n",
			127,
			[]string{"docker-level exit code 127",
				"docker/daemon error text in the captured output"},
			"docker client/runtime failed", "RAN inside the container"},
		{"container-127-no-output", "", 127,
			[]string{"exit 127 with no captured output — inconclusive"},
			"inconclusive", ""},
		{"container-125-daemon-level", "", 125,
			[]string{"docker-level exit code 125"},
			"docker itself failed before the command ran", ""},
	}
	for _, tc := range cases {
		execID := reg(tc.name, tc.stdout, "", tc.exit)
		code, out, errS := run(t, "--root", root, "classify", cid, execID)
		if code != 0 {
			t.Fatalf("%s: classify exit %d: out=%q err=%q", tc.name, code, out, errS)
		}
		if !strings.Contains(out, "ENVIRONMENT") {
			t.Errorf("%s: class line = %q", tc.name, out)
		}
		for _, sig := range tc.wantSignals {
			if !strings.Contains(out, "signal: "+sig) {
				t.Errorf("%s: output lacks signal %q: %q", tc.name, sig, out)
			}
		}
		if !strings.Contains(out, tc.wantNote) {
			t.Errorf("%s: note lacks %q: %q", tc.name, tc.wantNote, out)
		}
		if tc.notNote != "" && strings.Contains(out, tc.notNote) {
			t.Errorf("%s: note must not contain %q: %q", tc.name, tc.notNote, out)
		}
	}
}

// TestR38SeamAuditWiredCopies pins the three ensureSeams entries whose
// target is a COPY of a sandbox default. sandbox.ClassifyFailure /
// SandboxPreflight / DockerImageProbe are the functions the exec and
// classify verbs read; after ensureSeams they must behave exactly like the
// envgo copies that were installed over the defaults.
func TestR38SeamAuditWiredCopies(t *testing.T) {
	ensureSeams() // the production wiring, verbatim

	root, cid := r38Camp(t)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}

	// --- classify seam ------------------------------------------------------
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "host-readonly", Command: "nonexistent-cmd-xyz",
		ReportedBy: "harness", ExitStatus: 127})
	if err != nil {
		t.Fatal(err)
	}
	wired := sandbox.ClassifyFailure(rec)
	direct := envgo.ClassifyFailure(rec)
	if validation.CanonCompact(wired) != validation.CanonCompact(direct) {
		t.Errorf("wired classify seam != envgo.ClassifyFailure:\n  wired:  %s\n"+
			"  direct: %s", validation.CanonCompact(wired),
			validation.CanonCompact(direct))
	}
	if note := objStr(wired, "note"); !strings.Contains(note,
		"could not find the command") {
		t.Errorf("wired classifier still carries the stale docker text: %q", note)
	}

	// --- preflight seam -----------------------------------------------------
	profile := "host-readonly"
	preWired, err := sandbox.SandboxPreflight(c, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	preDirect, err := envgo.SandboxPreflight(c, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonCompact(preWired) != validation.CanonCompact(preDirect) {
		t.Errorf("wired preflight seam != envgo.SandboxPreflight:\n"+
			"  wired:  %s\n  direct: %s", validation.CanonCompact(preWired),
			validation.CanonCompact(preDirect))
	}
	// The envgo copy's honest host-profile shape (the sandbox default would
	// still run the container solc block for a host profile): every
	// container check stays "na" on a host profile, nothing is a warn/fail.
	checks := objAt(preWired, "checks")
	for _, name := range []string{"docker", "image", "solc"} {
		if got := objStr(objAt(checks, name), "status"); got != "na" {
			t.Errorf("host-readonly preflight check %s = %q, want na", name, got)
		}
	}
	if !r38BoolAt(preWired, "ok") {
		t.Errorf("host-readonly preflight not ok: %s", validation.CanonCompact(preWired))
	}

	// --- image-probe seam (needs the daemon; skips cleanly without docker) --
	img := "websec-r38-probe@sha256:" + strings.Repeat("0", 64)
	wiredProbe := sandbox.DockerImageProbe(&img)
	directProbe := envgo.DockerImageProbe(&img)
	if validation.CanonCompact(wiredProbe) != validation.CanonCompact(directProbe) {
		t.Errorf("wired image-probe seam != envgo.DockerImageProbe:\n"+
			"  wired:  %s\n  direct: %s", validation.CanonCompact(wiredProbe),
			validation.CanonCompact(directProbe))
	}
	if r38StrAt(wiredProbe, "image") != img {
		t.Errorf("wired probe image = %q, want %q",
			r38StrAt(wiredProbe, "image"), img)
	}
	if !r38BoolAt(wiredProbe, "pinned") {
		t.Errorf("wired probe pinned = false for a digest reference: %s",
			validation.CanonCompact(wiredProbe))
	}
	if sandbox.DockerDaemonOK() && !r38BoolAt(wiredProbe, "daemon") {
		t.Errorf("wired probe daemon = false while the daemon answers: %s",
			validation.CanonCompact(wiredProbe))
	}
}

// r38StrAt/r38BoolAt are the field readers the cli package does not carry.
func r38StrAt(v validation.Value, key string) string {
	return objStr(v, key)
}

func r38BoolAt(v validation.Value, key string) bool {
	b := objAt(v, key)
	return b.Kind == validation.Bool && b.B
}

// r38 ensureSeams seam audit. Every entry ensureSeams installs, with the
// wiring class that determines whether a "stale transcription" (a second,
// drifted copy of an algorithm) can exist at all:
//
//	direct  = the setter receives the owning package's function value
//	          itself — there is ONE copy; a stale transcription is
//	          structurally impossible, so the wired-path check is that the
//	          seam is installed (any behavioral pin would just re-test the
//	          source package, whose own tests already pin it).
//	adapter = a thin closure/struct in cmd_dedup.go (docMapSeam,
//	          intentMapSeam, reportAdapter, queueMemoryT28, the bounty
//	          resolver, the compat-classes closure) that FORWARDS to the
//	          owning package's implementation — no algorithm of its own.
//	copy    = a full algorithm transcribed into envgo; this is the only
//	          class where r36's bug (default fixed, copy stale) can recur.
//	          All three are pinned behaviorally by TestR38SeamAuditWiredCopies.
//
// dedup.SetMarkDuplicate(findings.MarkDuplicate)            direct
// dedup.SetFlagPossibleDuplicate(findings.FlagPossibleDuplicate) direct
// dedup.SetFoldIntoLineage(findings.FoldIntoLineage)        direct
// taxonomy.SetCompatClasses(closure over dedup groups)      adapter
// findings.SetInvariantGuard(invariants.AssertInvariantsVerified)  direct
// findings.SetNormalizeInvID(invariants.NormalizeInvID)     direct
// findings.SetLoadInvariantLinks(invariants.LoadLinks)      direct
// findings.SetDocumentedInvariants(docMapSeam)              adapter
// findings.SetInvariantVerified(invariants.IsVerified)      direct
// findings.SetIntentClaims(intentMapSeam)                   adapter
// findings.SetReproductionTierOrder(closure over reproduction.TierOrder) adapter
// orchestrator.SetReproduction(reproduction fns)            direct
// findings.SetOnchainSequenceRequired(sequencepoc…)         direct
// findings.SetVerifySequenceCoverage(sequencepoc…)          direct
// forkpoc.SetOnchainSequenceRequired(sequencepoc…)          direct
// forkpoc.SetVerifySequenceCoverage(sequencepoc…)           direct
// orchestrator.SetSequencePOC(sequencepoc.IsSequenceRequired)      direct
// sandbox.SetClassifyFailure(envgo.ClassifyFailure)         copy (r36 bug — FIXED)
// sandbox.SetSandboxPreflight(envgo.SandboxPreflight)       copy (no exit-code
//
//	logic; audited: envgo's host-profile solc guard is NEWER than the
//	sandbox default, not stale — pinned above)
//
// sandbox.SetDockerImageProbe(envgo.DockerImageProbe)       copy (audited: text
//
//	matches the sandbox default; only divergence is the timeout branch,
//	where envgo reports the timeout error and the default falls through
//	— unreachable through the wired seam without a hung docker inspect)
//
// pipeline.SetCosts(costs.API{})                            direct (struct of fns)
// pipeline.SetReport(reportAdapter{})                       adapter
// structidx.Wire()                                          direct bundles
// histmining.SetIndexAPI(structidx fns)                     direct
// bounty.SetContractPathResolver(closure)                   adapter
// forkdiff.Wire()                                           direct (seam struct)
// archetypes.WireScopePlant()                               direct bundles
// wireT28Seams()                                            direct + queueMemoryT28 adapter
// wireT33Seams()                                            direct
// wireT34Seams()                                            direct
const _ = "r38 seam audit table (documentation)"
