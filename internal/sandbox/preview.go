// preview.go: Sandbox.preview — what run WOULD do, without running it.
package sandbox

import (
	"fmt"
	"websec/internal/validation"
)

// Preview is Sandbox.preview: what run WOULD do — argv, env keys, network,
// workdir mode — without running, without an EXEC record, and without
// requiring the profile to be available.
func Preview(profile, command string, workdir *string,
	env []EnvVar) (validation.Value, error) {
	if !inProfiles(profile) {
		return validation.VNull(), fmt.Errorf("unknown profile %s",
			validation.PyReprStr(profile))
	}
	keys := envKeyValues(env)
	var wd validation.Value = validation.VNull()
	if workdir != nil {
		wd = validation.VStr(*workdir)
	}
	base := []validation.KV{
		{K: "profile", V: validation.VStr(profile)},
		{K: "available", V: validation.VBool(ProfileAvailable(profile))},
		{K: "command", V: validation.VStr(command)},
		{K: "env_keys", V: validation.VArr(keys...)},
		{K: "workdir", V: wd},
		{K: "network", V: validation.VStr(networkLabel(profile))},
	}
	if HostProfile(profile) {
		base = append(base, validation.KV{K: "note", V: validation.VStr(
			"runs on the HOST (no container): this exec can never back E4+ " +
				"evidence — use a container profile (docker-networkless, " +
				"fork-runner, ...) for reproduction evidence")})
		return validation.VObj(base...), nil
	}
	argv, meta, err := BuildContainerArgv(profile, command, workdir, env)
	if err != nil {
		return validation.VNull(), err
	}
	argvVals := make([]validation.Value, 0, len(argv))
	for _, a := range argv {
		argvVals = append(argvVals, validation.VStr(a))
	}
	out := validation.VObj(base...)
	// Python assigns base["env_keys"] = meta["env_keys"], which REPLACES the
	// value in place (the key keeps its position).
	out = setKey(out, "env_keys",
		validation.VArr(envKeyValues2(meta.EnvKeys)...))
	out.O = append(out.O,
		validation.KV{K: "argv", V: validation.VArr(argvVals...)},
		validation.KV{K: "image", V: validation.VStr(meta.Image)},
		validation.KV{K: "workdir_mode", V: validation.VStr(meta.Workdir)},
		validation.KV{K: "svm_mount", V: optStrValue(meta.SvmMount)},
		validation.KV{K: "note", V: validation.VStr(
			"entrypoint is pinned to /bin/sh -c (the image's entrypoint is " +
				"never used) — the command runs verbatim as a shell string")},
	)
	return out, nil
}

// EvidenceProfile is Sandbox.evidence_profile.
func (s *Sandbox) EvidenceProfile() string { return s.Profile }
