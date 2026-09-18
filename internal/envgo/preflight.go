// preflight.go: env.sandbox_preflight — the sandbox's readiness as a
// CHECKABLE PRECONDITION, checked BEFORE the first exec pays for it.
package envgo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// preflightState carries the shared check-recording context of
// SandboxPreflight's sections.
type preflightState struct {
	c         *state.Campaign
	workdir   *string
	profile   *string
	container bool
	checks    validation.Value
	issues    []validation.Value
	warnings  []validation.Value
}

// preflightCheck records one check row and, for fail/warn, the matching
// issue/warning line.
func (pf *preflightState) preflightCheck(name, status, detail string,
	fix *string) {
	var fixV validation.Value = validation.VNull()
	if fix != nil {
		fixV = validation.VStr(*fix)
	}
	pf.checks.O = append(pf.checks.O, validation.KV{K: name,
		V: validation.VObj(
			validation.KV{K: "status", V: validation.VStr(status)},
			validation.KV{K: "detail", V: validation.VStr(detail)},
			validation.KV{K: "fix", V: fixV})})
	if status == "fail" || status == "warn" {
		line := name + ": " + detail
		if fix != nil {
			line += " — fix: " + *fix
		}
		if status == "fail" {
			pf.issues = append(pf.issues, validation.VStr(line))
		} else {
			pf.warnings = append(pf.warnings, validation.VStr(line))
		}
	}
}

// preflightContainer checks the docker daemon and the configured image.
func (pf *preflightState) preflightContainer() {
	if !pf.container {
		host := "host-readonly"
		if pf.profile != nil {
			host = *pf.profile
		}
		pf.preflightCheck("docker", "na",
			host+" executes on the host — no container involved", nil)
		pf.preflightCheck("image", "na", "no container image involved", nil)
		pf.preflightCheck("solc", "na", "no container to compile in", nil)
	} else {
		daemon := dockerDaemonOK()
		if daemon {
			pf.preflightCheck("docker", "ok", "daemon answering", nil)
		} else {
			pf.preflightCheck("docker", "fail",
				"docker daemon not answering", strPtr(
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
				pf.preflightCheck("image", "ok", detail, nil)
			} else {
				fix := "docker pull " + strAt(img, "image")
				if !boolAt(img, "pinned") {
					fix += " and pin by digest"
				}
				pf.preflightCheck("image", "warn", strAt(img, "image")+
					" not present "+
					"locally — the first run will pull it (a floating tag "+
					"may pull a different build than the PoC assumes)", &fix)
			}
		} else {
			pf.preflightCheck("image", "na",
				"daemon down — image check skipped", nil)
		}
	}
}

// preflightSolc checks the svm/solc cache against the compiler foundry.toml
// pinned. The solc cache only exists for a CONTAINER run: host-readonly
// executes the binary the host has, so a missing svm cache is not its
// problem. The earlier "na" row for host-readonly used to be overwritten here
// (the block ran for every profile), which reported a container requirement to
// a profile that has none — and a FAIL at that.
func (pf *preflightState) preflightSolc() {
	if !pf.container {
		// host-readonly: the "na" row set above stands.
	} else if version, perr := pinnedCompiler(pf.c); perr != nil {
		pf.preflightCheck("solc", "fail",
			"the active snapshot's pin manifest cannot be "+
				"read, so the compiler pin cannot be judged: "+perr.Error(),
			nil)
	} else if version == nil {
		pf.preflightCheck("solc", "na",
			"no compiler pinned by the active snapshot — "+
				"nothing to check against", nil)
	} else if !sandbox.SolcVersionPin(*version) {
		// Untrusted input from the target repo's foundry.toml: it must not be
		// joined into a host path (a pin of "../../etc" would probe outside
		// the cache) or handed to a shell.
		fix := "set foundry.toml's solc to a release (for example 0.8.24) — " +
			"webv2 only uses a version as the svm cache path component"
		pf.preflightCheck("solc", "fail", "the active snapshot pins compiler "+
			sandbox.SolcPinText(*version)+", which is not a solc version — "+
			"refusing to treat it as an svm cache path", &fix)
	} else {
		svm := solcDir()
		if svm == nil {
			fix := "set WEBV2_SOLC_DIR to a host dir with the svm layout (" +
				*version + "/solc-" + *version + ") or preinstall the image"
			pf.preflightCheck("solc", "warn",
				"solc "+*version+" pinned by foundry.toml "+
					"but WEBV2_SOLC_DIR is unset — an offline container cannot "+
					"download it; the image must ship it (`webv2 env doctor` "+
					"probes that)", &fix)
		} else {
			binary := filepath.Join(*svm, *version, "solc-"+*version)
			if fileExists(binary) {
				pf.preflightCheck("solc", "ok",
					"solc "+*version+" present in the svm "+
						"cache "+*svm, nil)
			} else {
				fix := "place the solc binary at " + binary +
					" (svm layout: " +
					*version + "/solc-" + *version + ") or preinstall it in " +
					"the image (`webv2 env doctor` probes the image)"
				if pf.profile != nil && *pf.profile == "fork-runner" {
					pf.preflightCheck("solc", "warn",
						"solc "+*version+" missing from "+
							"the svm cache "+*svm+" — the fork-runner bridge "+
							"may still reach the registry, but that is not "+
							"guaranteed", &fix)
				} else {
					pf.preflightCheck("solc", "fail",
						"solc "+*version+" pinned by "+
							"foundry.toml but missing from the svm cache "+
							*svm+" — this profile's container has no network "+
							"and cannot download it", &fix)
				}
			}
		}
	}
}

// preflightWorkdir checks the workdir bind-mount sanity.
func (pf *preflightState) preflightWorkdir() {
	if pf.workdir == nil {
		detail := "no workdir given — "
		if pf.container {
			detail += "container uses a tmpfs"
		} else {
			detail += "the host shell uses the current directory"
		}
		pf.preflightCheck("workdir", "na", detail, nil)
	} else {
		p := *pf.workdir
		if !pathExists(p) {
			pf.preflightCheck("workdir", "fail",
				"workdir "+p+" does not exist — a "+
					"missing bind source fails the whole run", strPtr(
					"create "+p+" or point --workdir at an existing directory"))
		} else if !isDirPath(p) {
			pf.preflightCheck("workdir", "fail",
				"workdir "+p+" is not a directory",
				strPtr("point --workdir at a directory ("+p+" is a file)"))
		} else {
			pf.preflightCheck("workdir", "ok",
				"binds "+resolvedPath(p), nil)
		}
	}
}

// preflightResult assembles the sandbox_preflight result object.
func (pf *preflightState) preflightResult() validation.Value {
	var profileV validation.Value = validation.VNull()
	if pf.profile != nil {
		profileV = validation.VStr(*pf.profile)
	}
	return validation.VObj(
		validation.KV{K: "profile", V: profileV},
		validation.KV{K: "checks", V: pf.checks},
		validation.KV{K: "issues", V: validation.VArr(pf.issues...)},
		validation.KV{K: "warnings", V: validation.VArr(pf.warnings...)},
		validation.KV{K: "ok", V: validation.VBool(len(pf.issues) == 0)},
	)
}

// SandboxPreflight is sandbox_preflight: daemon, the configured image, the
// svm/solc cache versus the compiler foundry.toml pinned, and the workdir
// bind-mount sanity. Deliberately cheap and read-only: no `docker run` (the
// image-INTERNAL solc check is SolcProbe), no pulls, no writes. FAILs block
// (issues — every one names the exact fix); WARNs are advisory. `profile`
// nil means "container readiness" — what `webv2 doctor` reports.
func SandboxPreflight(c *state.Campaign, workdir, profile *string) (
	validation.Value, error) {
	pf := preflightState{c: c, workdir: workdir, profile: profile,
		checks: validation.VObj()}
	pf.container = profile == nil || !sandbox.HostProfile(*profile)
	pf.preflightContainer()
	pf.preflightSolc()
	pf.preflightWorkdir()
	return pf.preflightResult(), nil
}

// pinnedCompiler is the compiler version the active snapshot's toolchain
// detection pinned (str(compiler).split(",")[0].strip()), or nil. Python's
// `if compiler:` truthiness applies (an empty pin is no pin).
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
