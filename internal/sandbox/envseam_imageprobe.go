// envseam_imageprobe.go: the transcribed default docker image probe
// (env.docker_image_probe).
package sandbox

import (
	"os/exec"
	"strings"
	"websec/internal/validation"
)

// defaultDockerImageProbe is the transcription env.py's docker_image_probe
// (the seam default until internal/envgo is wired over it).
func defaultDockerImageProbe(image *string) validation.Value {
	name := DockerImage()
	if image != nil {
		name = *image
	}
	base := name
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	pinned := strings.Contains(base, "@")
	daemon, present := false, false
	digest := ""
	detail := ""
	if _, err := exec.LookPath("docker"); err != nil {
		detail = "docker CLI not found"
	} else if !dockerDaemonOK() {
		detail = "docker daemon not answering"
	} else {
		daemon = true
		res, err := runProc([]string{"docker", "image", "inspect", "--format",
			"{{.Id}}", name}, "", nil, 20*timeSecond)
		if err != nil && err != errTimeout {
			detail = "docker image inspect failed: " + err.Error()
		} else if res.ReturnCode != 0 {
			stderr := strings.TrimSpace(res.Stderr)
			if len([]rune(stderr)) > 120 {
				stderr = string([]rune(stderr)[:120])
			}
			detail = "image not present locally (" + stderr + ") — the " +
				"first E4+ run will pull it, and a floating tag may pull a " +
				"different build than your PoC assumes"
		} else {
			present = true
			digest = strings.TrimSpace(res.Stdout)
			head := digest
			if len([]rune(head)) > 19 {
				head = string([]rune(head)[:19])
			}
			if !pinned {
				detail = "tag reference — local digest " + head + "...; " +
					"pin by digest (name@sha256:...) for drift-proof runs"
			} else {
				detail = "digest-pinned — " + head + "..."
			}
		}
	}
	var digestV validation.Value = validation.VNull()
	if digest != "" {
		digestV = validation.VStr(digest)
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
