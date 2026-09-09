// preflight.go: env.sandbox_preflight — the sandbox's readiness as a
// CHECKABLE PRECONDITION, checked BEFORE the first exec pays for it.
package envgo

import (
	"path/filepath"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// SandboxPreflight is sandbox_preflight: daemon, the configured image, the
// svm/solc cache versus the compiler foundry.toml pinned, and the workdir
// bind-mount sanity. Deliberately cheap and read-only: no `docker run` (the
// image-INTERNAL solc check is SolcProbe), no pulls, no writes. FAILs block
// (issues — every one names the exact fix); WARNs are advisory. `profile`
// nil means "container readiness" — what `webv2 doctor` reports.
func SandboxPreflight(c *state.Campaign, workdir, profile *string) (
	validation.Value, error) {
	checks := validation.VObj()
	var issues, warnings []validation.Value

	check := func(name, status, detail string, fix *string) {
		var fixV validation.Value = validation.VNull()
		if fix != nil {
			fixV = validation.VStr(*fix)
		}
		checks.O = append(checks.O, validation.KV{K: name, V: validation.VObj(
			validation.KV{K: "status", V: validation.VStr(status)},
			validation.KV{K: "detail", V: validation.VStr(detail)},
			validation.KV{K: "fix", V: fixV})})
		if status == "fail" || status == "warn" {
			line := name + ": " + detail
			if fix != nil {
				line += " — fix: " + *fix
			}
			if status == "fail" {
				issues = append(issues, validation.VStr(line))
			} else {
				warnings = append(warnings, validation.VStr(line))
			}
		}
	}

	container := profile == nil || *profile != "host-readonly"
	if !container {
		check("docker", "na",
			"host-readonly executes on the host — no container involved", nil)
		check("image", "na", "no container image involved", nil)
		check("solc", "na", "no container to compile in", nil)
	} else {
		daemon := dockerDaemonOK()
		if daemon {
			check("docker", "ok", "daemon answering", nil)
		} else {
			check("docker", "fail", "docker daemon not answering", strPtr(
				"start the docker daemon (container profiles are the only "+
					"honest execution path — evidence produced un-sandboxed "+
					"cannot be minted at E4+)"))
		}
		if daemon {
			img := dockerProbe(nil)
			if boolAt(img, "present") {
				detail := strAt(img, "image") + " present locally"
				if boolAt(img, "pinned") {
					detail += " (digest-pinned)"
				} else {
					detail += " (tag reference — may float)"
				}
				check("image", "ok", detail, nil)
			} else {
				fix := "docker pull " + strAt(img, "image")
				if !boolAt(img, "pinned") {
					fix += " and pin by digest"
				}
				check("image", "warn", strAt(img, "image")+" not present "+
					"locally — the first run will pull it (a floating tag "+
					"may pull a different build than the PoC assumes)", &fix)
			}
		} else {
			check("image", "na", "daemon down — image check skipped", nil)
		}
	}

	version := pinnedCompiler(c)
	if version == nil {
		check("solc", "na", "no compiler pinned by the active snapshot — "+
			"nothing to check against", nil)
	} else {
		svm := solcDir()
		if svm == nil {
			fix := "set WEBV2_SOLC_DIR to a host dir with the svm layout (" +
				*version + "/solc-" + *version + ") or preinstall the image"
			check("solc", "warn", "solc "+*version+" pinned by foundry.toml "+
				"but WEBV2_SOLC_DIR is unset — an offline container cannot "+
				"download it; the image must ship it (`webv2 env doctor` "+
				"probes that)", &fix)
		} else {
			binary := filepath.Join(*svm, *version, "solc-"+*version)
			if fileExists(binary) {
				check("solc", "ok", "solc "+*version+" present in the svm "+
					"cache "+*svm, nil)
			} else {
				fix := "place the solc binary at " + binary + " (svm layout: " +
					*version + "/solc-" + *version + ") or preinstall it in " +
					"the image (`webv2 env doctor` probes the image)"
				if profile != nil && *profile == "fork-runner" {
					check("solc", "warn", "solc "+*version+" missing from "+
						"the svm cache "+*svm+" — the fork-runner bridge "+
						"may still reach the registry, but that is not "+
						"guaranteed", &fix)
				} else {
					check("solc", "fail", "solc "+*version+" pinned by "+
						"foundry.toml but missing from the svm cache "+
						*svm+" — this profile's container has no network "+
						"and cannot download it", &fix)
				}
			}
		}
	}

	if workdir == nil {
		detail := "no workdir given — "
		if container {
			detail += "container uses a tmpfs"
		} else {
			detail += "the host shell uses the current directory"
		}
		check("workdir", "na", detail, nil)
	} else {
		p := *workdir
		if !pathExists(p) {
			check("workdir", "fail", "workdir "+p+" does not exist — a "+
				"missing bind source fails the whole run", strPtr(
				"create "+p+" or point --workdir at an existing directory"))
		} else if !isDirPath(p) {
			check("workdir", "fail", "workdir "+p+" is not a directory",
				strPtr("point --workdir at a directory ("+p+" is a file)"))
		} else {
			check("workdir", "ok", "binds "+resolvedPath(p), nil)
		}
	}

	var profileV validation.Value = validation.VNull()
	if profile != nil {
		profileV = validation.VStr(*profile)
	}
	return validation.VObj(
		validation.KV{K: "profile", V: profileV},
		validation.KV{K: "checks", V: checks},
		validation.KV{K: "issues", V: validation.VArr(issues...)},
		validation.KV{K: "warnings", V: validation.VArr(warnings...)},
		validation.KV{K: "ok", V: validation.VBool(len(issues) == 0)},
	), nil
}

// pinnedCompiler is the compiler version the active snapshot's toolchain
// detection pinned (str(compiler).split(",")[0].strip()), or nil. Python's
// `if compiler:` truthiness applies (an empty pin is no pin).
func pinnedCompiler(c *state.Campaign) *string {
	if c == nil {
		return nil
	}
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		return nil
	}
	pinPath := filepath.Join(c.Dir, "snapshots", *sid, "snapshot.json")
	if !pathExists(pinPath) {
		return nil
	}
	pin, err := validation.ReadJson(pinPath)
	if err != nil {
		return nil
	}
	compiler := objAt(objAt(pin, "config"), "compiler")
	if !truthy(compiler) {
		return nil
	}
	text := scalarText(compiler)
	if text == "" {
		return nil
	}
	first := strings.TrimSpace(strings.SplitN(text, ",", 2)[0])
	return &first
}

// scalarText is Python's str() for the JSON scalars a compiler pin can hold.
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
