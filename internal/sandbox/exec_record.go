// exec_record.go: rendering the sandbox_execution record and its
// environment/filesystem labels.
package sandbox

import (
	"sort"
	"websec/internal/validation"
)

// record builds the sandbox_execution record in Python's key order.
func (s *Sandbox) record(execID, command string, opts RunOpts,
	verdict, container validation.Value, started, stdoutPath,
	stderrPath string) validation.Value {
	keys := make([]validation.Value, 0, len(opts.Env))
	for _, e := range opts.Env {
		keys = append(keys, validation.VStr(e.Key))
	}
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].S < keys[j].S })
	var workdir validation.Value = validation.VNull()
	var workdirResolved validation.Value = validation.VNull()
	if opts.Workdir != nil {
		workdir = validation.VStr(*opts.Workdir)
		// r36 F4: the record must also name the RESOLVED directory the
		// process actually ran in — the operator's string is kept in
		// `workdir` (pinned shape), `workdir_resolved` is additive.
		workdirResolved = validation.VStr(resolvedPath(*opts.Workdir))
	}
	return validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(execID)},
		validation.KV{K: "campaign_id", V: validation.VStr(s.Campaign.CampaignID)},
		validation.KV{K: "profile", V: validation.VStr(s.Profile)},
		validation.KV{K: "finding_id", V: optStrValue(opts.FindingID)},
		validation.KV{K: "artifact_id", V: optStrValue(opts.ArtifactID)},
		validation.KV{K: "command", V: validation.VStr(command)},
		validation.KV{K: "workdir", V: workdir},
		validation.KV{K: "workdir_resolved", V: workdirResolved},
		validation.KV{K: "policy_verdict", V: verdict},
		validation.KV{K: "environment", V: environmentValue(
			toolVersions(), keys, s.Profile)},
		validation.KV{K: "container", V: container},
		validation.KV{K: "origin", V: validation.VStr("locally-executed")},
		validation.KV{K: "reported_by", V: validation.VNull()},
		validation.KV{K: "input_hashes", V: hashDir(opts.Workdir)},
		validation.KV{K: "started_at", V: validation.VStr(started)},
		validation.KV{K: "finished_at", V: validation.VNull()},
		validation.KV{K: "exit_status", V: validation.VNull()},
		validation.KV{K: "stdout_path", V: validation.VStr(stdoutPath)},
		validation.KV{K: "stderr_path", V: validation.VStr(stderrPath)},
		validation.KV{K: "artifact_hashes", V: validation.VObj()},
	)
}

// environmentValue renders the environment sub-dict.
func environmentValue(tools validation.Value, envKeys []validation.Value,
	profile string) validation.Value {
	if envKeys == nil {
		envKeys = []validation.Value{}
	}
	return validation.VObj(
		validation.KV{K: "tool_versions", V: tools},
		validation.KV{K: "env_keys", V: validation.VArr(envKeys...)},
		validation.KV{K: "network_access",
			V: validation.VStr(networkLabel(profile))},
		validation.KV{K: "filesystem",
			V: validation.VStr(profileFilesystemLabel(profile))},
	)
}

// profileFilesystemLabel is the HONEST filesystem label for a profile
// (r36 F5): a host profile executes UNCONFINED on this host — nothing
// enforces readonly (the deny rules are static tripwires, not a
// boundary) — so the record must not assert "readonly" while the run
// writes the host filesystem. Container profiles keep their label (the
// container IS the enforcement mechanism).
func profileFilesystemLabel(profile string) string {
	if HostProfile(profile) {
		return "host (unconfined — nothing enforces readonly; deny-rule " +
			"tripwires only)"
	}
	return profileFilesystem[profile]
}
