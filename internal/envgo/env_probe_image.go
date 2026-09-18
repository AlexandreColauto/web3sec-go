// Docker image digest probe (docker_image_probe): daemon reachability,
// local presence, and whether the reference is digest-pinned.
package envgo

import (
	"os/exec"
	"strings"
	"time"

	"websec/internal/validation"
)

// DockerImageProbe is docker_image_probe: probe the daemon for the exact
// image the container profiles would run. `digest` is the sha256 image id;
// `pinned` is true only when the reference itself is a digest
// (name@sha256:...) — a tag (even a version tag) can float, a digest cannot.
func DockerImageProbe(image *string) validation.Value {
	name := dockerImage()
	if image != nil {
		name = *image
	}
	daemon, present, pinned := false, false, false
	var digest *string
	detail := ""
	base := name
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	pinned = strings.Contains(base, "@")
	if _, err := exec.LookPath("docker"); err != nil {
		detail = "docker CLI not found"
		return imageProbeValue(name, daemon, present, digest, pinned, detail)
	}
	if !dockerDaemonOK() {
		detail = "docker daemon not answering"
		return imageProbeValue(name, daemon, present, digest, pinned, detail)
	}
	daemon = true
	r, err := runProc([]string{"docker", "image", "inspect", "--format",
		"{{.Id}}", name}, 20*time.Second)
	if err != nil {
		detail = "docker image inspect failed: " + err.Error()
		return imageProbeValue(name, daemon, present, digest, pinned, detail)
	}
	if r.ReturnCode != 0 {
		stderr := strings.TrimSpace(r.Stderr)
		if len([]rune(stderr)) > 120 {
			stderr = string([]rune(stderr)[:120])
		}
		detail = "image not present locally (" + stderr + ") — the first " +
			"E4+ run will pull it, and a floating tag may pull a different " +
			"build than your PoC assumes"
		return imageProbeValue(name, daemon, present, digest, pinned, detail)
	}
	present = true
	d := strings.TrimSpace(r.Stdout)
	digest = &d
	head := d
	if len([]rune(head)) > 19 {
		head = string([]rune(head)[:19])
	}
	if !pinned {
		detail = "tag reference — local digest " + head + "...; pin by " +
			"digest (name@sha256:...) for drift-proof runs"
	} else {
		detail = "digest-pinned — " + head + "..."
	}
	return imageProbeValue(name, daemon, present, digest, pinned, detail)
}

func imageProbeValue(name string, daemon, present bool, digest *string,
	pinned bool, detail string) validation.Value {
	var digestV validation.Value = validation.VNull()
	if digest != nil {
		digestV = validation.VStr(*digest)
	}
	return validation.VObj(
		validation.KV{K: "image", V: validation.VStr(name)},
		validation.KV{K: "daemon", V: validation.VBool(daemon)},
		validation.KV{K: "present", V: validation.VBool(present)},
		validation.KV{K: "digest", V: digestV},
		validation.KV{K: "pinned", V: validation.VBool(pinned)},
		validation.KV{K: "detail", V: validation.VStr(detail)},
	)
}
