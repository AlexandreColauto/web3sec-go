// envseam_preflight.go: the transcribed default sandbox preflight
// (env.sandbox_preflight) — the sandbox's readiness as a checkable
// precondition.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

// defaultSandboxPreflight is env.sandbox_preflight verbatim.
func defaultSandboxPreflight(c *state.Campaign, workdir, profile *string) (
	validation.Value, error) {
	p := &preflightRun{c: c, workdir: workdir, profile: profile}
	p.container = profile != nil && !HostProfile(*profile)
	p.preflightCheckContainer()
	p.preflightCheckForkRPC()
	p.preflightCheckCompiler()
	p.preflightCheckWorkdir()
	return p.preflightResult(), nil
}

// preflightRun carries the shared state of one sandbox_preflight across
// the preflightXxx helpers below — the former defaultSandboxPreflight
// locals, verbatim, in the former order.
type preflightRun struct {
	c         *state.Campaign
	workdir   *string
	profile   *string
	container bool
	checks    []validation.KV
	issues    []validation.Value
	warnings  []validation.Value
}

// check appends one named check and, for a fail/warn, its operator-facing
// issue/warning line (the former defaultSandboxPreflight closure).
func (p *preflightRun) check(name, status, detail string, fix *string) {
	var fixV validation.Value = validation.VNull()
	if fix != nil {
		fixV = validation.VStr(*fix)
	}
	p.checks = append(p.checks, validation.KV{K: name, V: validation.VObj(
		validation.KV{K: "status", V: validation.VStr(status)},
		validation.KV{K: "detail", V: validation.VStr(detail)},
		validation.KV{K: "fix", V: fixV})})
	if status == "fail" || status == "warn" {
		line := name + ": " + detail
		if fix != nil {
			line += " — fix: " + *fix
		}
		if status == "fail" {
			p.issues = append(p.issues, validation.VStr(line))
		} else {
			p.warnings = append(p.warnings, validation.VStr(line))
		}
	}
}

// preflightCheckContainer runs the docker/image checks: na on a host
// profile, the daemon and image probes on a container profile.
func (p *preflightRun) preflightCheckContainer() {
	if !p.container {
		host := "host-readonly"
		if p.profile != nil {
			host = *p.profile
		}
		p.check("docker", "na",
			host+" executes on the host — no container involved", nil)
		p.check("image", "na", "no container image involved", nil)
		p.check("solc", "na", "no container to compile in", nil)
	} else {
		daemon := dockerDaemonOK()
		if daemon {
			p.check("docker", "ok", "daemon answering", nil)
		} else {
			p.check("docker", "fail", "docker daemon not answering", strPtr(
				"start the docker daemon (container profiles are the only "+
					"honest execution path — evidence produced un-sandboxed "+
					"cannot be minted at E4+)"))
		}
		if daemon {
			img := DockerImageProbe(nil)
			if boolAt(img, "present") {
				detail := strAt(img, "image") + " present locally" +
					map[bool]string{true: " (digest-pinned)",
						false: " (tag reference — may float)"}[boolAt(img, "pinned")]
				p.check("image", "ok", detail, nil)
			} else {
				fix := "docker pull " + strAt(img, "image")
				if !boolAt(img, "pinned") {
					fix += " and pin by digest"
				}
				p.check("image", "warn", strAt(img, "image")+
					" not present locally — the first run will pull it "+
					"(a floating tag may pull a different build than the PoC "+
					"assumes)", &fix)
			}
		} else {
			p.check("image", "na", "daemon down — image check skipped", nil)
		}
	}
}

// preflightCheckForkRPC runs the fork-runner fork_rpc probe row (nil row
// = no row: only fork-runner injects FORK_RPC_URL, so only fork-runner is
// probed here — envgo/preflight.go's wired copy calls the same
// ForkRPCPreflight, so the two transcriptions cannot drift).
func (p *preflightRun) preflightCheckForkRPC() {
	row := ForkRPCPreflight(p.profile)
	if row == nil {
		return
	}
	p.check("fork_rpc", row.Status, row.Detail, row.Fix)
}

// preflightCheckCompiler runs the solc checks against the active
// snapshot's compiler pin.
func (p *preflightRun) preflightCheckCompiler() {
	version, perr := pinnedCompiler(p.c)
	if perr != nil {
		p.check("solc", "fail", "the active snapshot's pin manifest cannot be "+
			"read, so the compiler pin cannot be judged: "+perr.Error(), nil)
	} else if version == nil {
		p.check("solc", "na", "no compiler pinned by the active snapshot — "+
			"nothing to check against", nil)
	} else if !SolcVersionPin(*version) {
		// The pin is target-repo input: it may not be joined into a host path.
		fix := "set foundry.toml's solc to a release (for example 0.8.24) — " +
			"webv2 only uses a version as the svm cache path component"
		p.check("solc", "fail", "the active snapshot pins compiler "+
			SolcPinText(*version)+", which is not a solc version — "+
			"refusing to treat it as an svm cache path", &fix)
	} else {
		svm := SolcDir()
		if svm == nil {
			fix := "set WEBV2_SOLC_DIR to a host dir with the svm layout (" +
				*version + "/solc-" + *version + ") or preinstall the image"
			p.check("solc", "warn", "solc "+*version+" pinned by foundry.toml "+
				"but WEBV2_SOLC_DIR is unset — an offline container cannot "+
				"download it; the image must ship it (`webv2 env doctor` "+
				"probes that)", &fix)
		} else {
			binary := filepath.Join(*svm, *version, "solc-"+*version)
			if fileExists(binary) {
				p.check("solc", "ok", "solc "+*version+
					" present in the svm cache "+*svm, nil)
			} else {
				fix := "place the solc binary at " + binary + " (svm layout: " +
					*version + "/solc-" + *version + ") or preinstall it in " +
					"the image (`webv2 env doctor` probes the image)"
				if p.profile != nil && *p.profile == "fork-runner" {
					p.check("solc", "warn", "solc "+*version+
						" missing from the svm cache "+*svm+" — the "+
						"fork-runner bridge may still reach the registry, "+
						"but that is not guaranteed", &fix)
				} else {
					p.check("solc", "fail", "solc "+*version+" pinned by "+
						"foundry.toml but missing from the svm cache "+
						*svm+" — this profile's container has no network "+
						"and cannot download it", &fix)
				}
			}
		}
	}
}

// preflightCheckWorkdir validates the bind source (a nil workdir is na).
func (p *preflightRun) preflightCheckWorkdir() {
	if p.workdir == nil {
		detail := "no workdir given — "
		if p.container {
			detail += "container uses a tmpfs"
		} else {
			detail += "the host shell uses the current directory"
		}
		p.check("workdir", "na", detail, nil)
	} else {
		wd := *p.workdir
		if !pathExists(wd) {
			p.check("workdir", "fail", "workdir "+wd+" does not exist — a "+
				"missing bind source fails the whole run", strPtr(
				"create "+wd+" or point --workdir at an existing directory"))
		} else if !isDirPath(wd) {
			p.check("workdir", "fail", "workdir "+wd+" is not a directory",
				strPtr("point --workdir at a directory ("+wd+" is a file)"))
		} else {
			p.check("workdir", "ok", "binds "+resolvedPath(wd), nil)
		}
	}
}

// preflightResult renders the sandbox_preflight object.
func (p *preflightRun) preflightResult() validation.Value {
	var profileV validation.Value = validation.VNull()
	if p.profile != nil {
		profileV = validation.VStr(*p.profile)
	}
	return validation.VObj(
		validation.KV{K: "profile", V: profileV},
		validation.KV{K: "checks", V: validation.VObj(p.checks...)},
		validation.KV{K: "issues", V: validation.VArr(p.issues...)},
		validation.KV{K: "warnings", V: validation.VArr(p.warnings...)},
		validation.KV{K: "ok", V: validation.VBool(len(p.issues) == 0)},
	)
}

// pinnedCompiler is the compiler version the active snapshot's toolchain
// detection pinned (str(compiler).split(",")[0].strip()), or nil.
func pinnedCompiler(c *state.Campaign) (*string, error) {
	if c == nil {
		return nil, nil
	}
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		// r44: this used to fold a read failure into "no active snapshot",
		// i.e. into "no compiler pinned" — the r42/r43 error-class blunder
		// on the compiler-pin rail. A pin the tool could not read is not a
		// pin that does not exist.
		return nil, err
	}
	if sid == nil {
		return nil, nil
	}
	pinPath := filepath.Join(c.Dir, "snapshots", *sid, "snapshot.json")
	if st, serr := os.Stat(pinPath); serr != nil {
		if os.IsNotExist(serr) {
			return nil, nil
		}
		return nil, fmt.Errorf("the active snapshot's pin manifest %s "+
			"cannot be read: %v", pinPath, serr)
	} else if st.IsDir() {
		return nil, fmt.Errorf("the active snapshot's pin manifest %s is a "+
			"directory", pinPath)
	}
	pin, err := validation.ReadJson(pinPath)
	if err != nil {
		return nil, fmt.Errorf("the active snapshot's pin manifest %s "+
			"cannot be read: %v", pinPath, err)
	}
	compiler := validation.ObjAt(validation.ObjAt(pin, "config"), "compiler")
	// Python's `if compiler:` truthiness — validation.PyTruthy is the
	// canonical predicate, so a FALSY-BUT-PRESENT pin (0, false, "", 0.0) is
	// no pin and str() renders a truthy scalar ("0.8.24", "0.8.24, --opt",
	// 1.5). r45b: envgo/preflight.go and sandbox/envseam.go carry this one
	// transcription twice; they had drifted (truthy() vs Null-only) and are
	// reconciled here to the canonical predicate, pinned by the r45b
	// differential test.
	if !validation.PyTruthy(compiler) {
		return nil, nil
	}
	text := scalarText(compiler)
	if text == "" {
		return nil, nil
	}
	first := strings.TrimSpace(strings.SplitN(text, ",", 2)[0])
	return &first, nil
}

// scalarText is Python's str() for the JSON scalars a compiler pin can hold.
// Byte-identical to envgo/preflight.go's copy (r45b differential).
func scalarText(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Int:
		return validation.IntText(v)
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Flt:
		return validation.PythonFloat(v.F)
	default:
		return ""
	}
}

func strPtr(s string) *string { return &s }

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func isDirPath(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
