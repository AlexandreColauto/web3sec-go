// Package histmining is webv2/history_mining.py: history mining, VCS
// archaeology, and deployment-vs-source verification.
//
// The cheapest place to find a bug is the neighborhood of a known one:
//
//   - git history: past fixes reveal what the team gets wrong, and fix-commits
//     create "patch-delta" hypotheses — what neighboring paths did the fix NOT
//     change?
//   - deployment verification: does the deployed bytecode actually match the
//     source under audit? An excellent theoretical report against the wrong
//     code is worthless.
//
// This package produces structured inputs; the E-trajectory (historical) and
// G-trajectory (drift) agents consume them.
package histmining

import (
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

var fixPatterns = regexp.MustCompile(
	`(?i)\b(fix|patch|resolve|mitigate|cve|vulnerab|exploit|security|overflow|` +
		`reentranc|access control|bounds|round)`)

// Git is _git: run git -C target ARGS, capturing stdout. Any git failure
// (missing repo, no commits, no git binary) is swallowed — the mining is
// advisory.
// gitLogFormat is git log's pretty format: %x00 is git's own escape for a NUL
// byte, and it is what the reference passes (the literal four characters, not
// a real NUL).
const gitLogFormat = `--pretty=format:%H%x00%h%x00%ad%x00%s`

func Git(target string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	argv := append([]string{"-C", target}, args...)
	out, err := exec.CommandContext(ctx, "git", argv...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// MineGitHistory is mine_git_history: extract security-relevant commits with
// changed files and the diff scope. Output feeds the E-trajectory and the
// patch-delta hunter.
func MineGitHistory(c *state.Campaign, target string, maxCommits int) (
	validation.Value, error) {
	log := Git(target, "log", "-n", strconv.Itoa(maxCommits), gitLogFormat,
		"--date=short")
	commits := []validation.Value{}
	for _, line := range splitLines(log) {
		if !strings.Contains(line, "\x00") {
			continue
		}
		parts := strings.SplitN(line, "\x00", 4)
		if len(parts) < 4 {
			continue
		}
		full, short, date, subject := parts[0], parts[1], parts[2], parts[3]
		if !fixPatterns.MatchString(subject) {
			continue
		}
		files := []validation.Value{}
		for _, f := range splitLines(Git(target, "show", "--name-only",
			"--pretty=format:", short)) {
			if s := strings.TrimSpace(f); s != "" {
				files = append(files, validation.VStr(s))
			}
		}
		commits = append(commits, validation.VObj(
			validation.KV{K: "commit", V: validation.VStr(short)},
			validation.KV{K: "full_hash", V: validation.VStr(full)},
			validation.KV{K: "date", V: validation.VStr(date)},
			validation.KV{K: "subject", V: validation.VStr(subject)},
			validation.KV{K: "files", V: validation.VArr(files...)},
		))
	}
	report := validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "generated_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "security_relevant_commits",
			V: validation.VArr(commits...)},
		validation.KV{K: "note", V: validation.VStr("each fix-commit " +
			"generates patch-delta hypotheses: what neighboring paths were " +
			"NOT changed by this fix?")},
	)
	out := filepath.Join(c.ArtifactsDir, "history_mining.json")
	if err := validation.WriteJson(out, report, ""); err != nil {
		return validation.VNull(), err
	}
	// fixed-path living document: re-mine refreshes instead of ghosting
	reason := "history mined (" + strconv.Itoa(len(commits)) + " commits)"
	if _, err := c.RegisterOrRefresh("history-mining", out, "", nil, reason); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(validation.KV{K: "commits",
		V: validation.VInt(int64(len(commits)))})
	if _, err := c.Log("history.mined", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return report, nil
}

// PatchDeltaHypotheses is patch_delta_hypotheses: for each security fix,
// produce deterministic hypotheses (sibling functions in the same file with
// the same pre-fix pattern; same-pattern call paths the fix did not cover).
// The LLM specializes each into a concrete check.
func PatchDeltaHypotheses(history validation.Value) []validation.Value {
	out := []validation.Value{}
	commits := objAt(history, "security_relevant_commits")
	for i, c := range commits.A {
		for _, fv := range objAt(c, "files").A {
			f := fv.S
			id := "PD-" + pad3(i+1) + "-" + pyStem(f)
			out = append(out, validation.VObj(
				validation.KV{K: "hypothesis_id", V: validation.VStr(id)},
				validation.KV{K: "fix_commit", V: objAt(c, "commit")},
				validation.KV{K: "fix_subject", V: objAt(c, "subject")},
				validation.KV{K: "file", V: validation.VStr(f)},
				validation.KV{K: "question", V: validation.VStr("Commit " +
					objStr(c, "commit") + " fixed " +
					validation.PyReprStr(objStr(c, "subject")) + " in " + f +
					". Do sibling functions/paths in the same file still " +
					"carry the pre-fix pattern?")},
			))
		}
	}
	return out
}

// VerifyDeploymentSource is verify_deployment_source: compare deployed
// bytecode hashes with locally compiled artifacts, and write the deployment
// pin onto the snapshot with honest per-contract source_match verdicts.
func VerifyDeploymentSource(c *state.Campaign, snapshotID string,
	deployed []validation.Value, localArtifacts map[string]string) (
	validation.Value, error) {
	contracts := []validation.Value{}
	verified := 0
	for _, d := range deployed {
		name := objStr(d, "name")
		local, ok := localArtifacts[name]
		var verdict string
		switch {
		case !ok:
			verdict = "unverified"
		case objAt(d, "bytecode_hash").Kind == validation.Str &&
			objAt(d, "bytecode_hash").S == local:
			verdict = "verified"
		default:
			verdict = "mismatch"
		}
		role := objStr(d, "role")
		if role == "" {
			role = "core"
		}
		if verdict == "verified" {
			verified++
		}
		contracts = append(contracts, validation.VObj(
			validation.KV{K: "name", V: validation.VStr(name)},
			validation.KV{K: "address", V: objAt(d, "address")},
			validation.KV{K: "role", V: validation.VStr(role)},
			validation.KV{K: "bytecode_hash", V: objAt(d, "bytecode_hash")},
			validation.KV{K: "source_match", V: validation.VStr(verdict)},
		))
	}
	var ratio validation.Value = validation.VNull()
	if len(contracts) > 0 {
		ratio = validation.VFloat(validation.PythonRound(
			float64(verified)/float64(len(contracts)), 3))
	}
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	network := "unknown-network"
	if v, ok := lookupKey(st, "program"); ok && v.Kind == validation.Str {
		network = v.S
	}
	deployment := validation.VObj(
		validation.KV{K: "network", V: validation.VStr(network)},
		validation.KV{K: "contracts", V: validation.VArr(contracts...)},
		validation.KV{K: "verification_ratio", V: ratio},
	)
	snap, err := snapshot.AttachDeploymentPin(c, snapshotID, deployment)
	if err != nil {
		return validation.VNull(), err
	}
	mismatches := []validation.Value{}
	for _, ct := range contracts {
		if objStr(ct, "source_match") == "mismatch" {
			mismatches = append(mismatches, objAt(ct, "name"))
		}
	}
	data := validation.VObj(
		validation.KV{K: "verified", V: validation.VInt(int64(verified))},
		validation.KV{K: "total", V: validation.VInt(int64(len(contracts)))},
		validation.KV{K: "mismatches", V: validation.VArr(mismatches...)},
	)
	if _, err := c.Log("deployment.verified", &snapshotID, &data); err != nil {
		return validation.VNull(), err
	}
	return snap, nil
}

// DeploymentRiskNotes is deployment_risk_notes: human-readable risk notes
// from a deployment pin.
func DeploymentRiskNotes(snap validation.Value) []string {
	dep := objAt(snap, "deployment")
	if dep.Kind != validation.Obj {
		return []string{"no deployment pin attached — source audit may be " +
			"against code that is not what is deployed"}
	}
	notes := []string{}
	ratio := objAt(dep, "verification_ratio")
	if ratio.Kind == validation.Flt || ratio.Kind == validation.Int {
		if floatField(dep, "verification_ratio") < 1.0 {
			notes = append(notes, "only "+
				pyPercent(floatField(dep, "verification_ratio"))+
				" of deployed contracts verified against source — "+
				"findings on unverified contracts must be re-validated "+
				"against bytecode")
		}
	}
	for _, c := range objAt(dep, "contracts").A {
		name := objStr(c, "name")
		switch objStr(c, "source_match") {
		case "mismatch":
			notes = append(notes, name+": DEPLOYED BYTECODE DIFFERS FROM "+
				"SOURCE — audit the deployed code, not the repository")
		case "unverified":
			notes = append(notes, name+": unverified — treat repository "+
				"source as unconfirmed for this address")
		}
		if objStr(c, "role") == "proxy" &&
			objAt(c, "implementation_address").Kind == validation.Null {
			notes = append(notes, name+": proxy without recorded "+
				"implementation — resolve before trusting any source-level "+
				"finding")
		}
	}
	return notes
}

// --- helpers ----------------------------------------------------------------

// notWiredErr is the absent-module seam error (Python has no such path).
type notWiredErr string

func (e notWiredErr) Error() string { return string(e) }

func notWiredError(msg string) error { return notWiredErr(msg) }

// splitLines is Python's str.splitlines for git output.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// pyStem is Path(f).stem.
func pyStem(f string) string {
	base := filepath.Base(f)
	i := strings.LastIndex(base, ".")
	if i <= 0 {
		return base
	}
	return base[:i]
}

// pad3 is Python's f"{n:03d}".
func pad3(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

// pyPercent is Python's f"{x:.0%}".
func pyPercent(x float64) string {
	return strconv.FormatFloat(x*100, 'f', 0, 64) + "%"
}

func floatField(v validation.Value, key string) float64 {
	f := objAt(v, key)
	switch f.Kind {
	case validation.Flt:
		return f.F
	case validation.Int:
		if f.Big != "" {
			out, _ := strconv.ParseFloat(f.Big, 64)
			return out
		}
		return float64(f.I)
	}
	return 0
}

func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	f := objAt(v, key)
	if f.Kind == validation.Str {
		return f.S
	}
	return ""
}

// lookupKey distinguishes an absent key from a present null (Python's
// dict.get default only fires when the key is missing).
func lookupKey(v validation.Value, key string) (validation.Value, bool) {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}
