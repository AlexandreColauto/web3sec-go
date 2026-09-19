package cli

// A11 (F14): `brief` discloses a framework-build skew on STDERR — the cockpit's
// stdout bytes (text and --json alike) are untouched, which is why the absent
// case is pinned byte-for-byte below. The stamp lives on the newest
// snapshot.pinned event (state/campaign_snapshot.go's emitEvent); a campaign
// with no pin, or a pin from before the key existed, stays silent.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
	"websec/internal/version"
)

// a11Pin logs a snapshot.pinned event for sid with framework_build=build
// (withKey=false is the pre-stamp campaign shape: no key at all). Crafting
// the event — not PinSnapshot — is the right level: the production stamp path
// is pinned by cmd_snap_build_test.go, while these tests own the READING and
// DISCLOSURE side.
func a11Pin(t *testing.T, c *state.Campaign, sid, build string, withKey bool) {
	t.Helper()
	data := validation.VObj(kv("ladder", validation.VStr("no-vcs")))
	if withKey {
		data.O = append(data.O, kv("framework_build", validation.VStr(build)))
	}
	if _, err := c.Log("snapshot.pinned", &sid, &data); err != nil {
		t.Fatal(err)
	}
}

// a11WantLine is the mandated disclosure, byte for byte.
func a11WantLine(recorded string) string {
	return fmt.Sprintf("framework: campaign last recorded under build %s, "+
		"this binary is %s — behavior above may reflect the newer "+
		"scheduler\n", recorded, version.Commit())
}

func TestBriefBuildSkewWarnsOnStderrOnly(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	// ABSENT CASE, pinned: a campaign with no recorded pin prints the same
	// bytes it always did, and nothing on stderr.
	code, baseOut, baseErr := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("baseline brief exit = %d: %q", code, baseErr)
	}
	if baseErr != "" {
		t.Fatalf("a campaign with no pin must stay silent on stderr: %q",
			baseErr)
	}
	a11Pin(t, c, "src-a11skew01", "bbbbbbbbbbbb", true)
	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("skewed brief exit = %d: %q", code, errS)
	}
	if out != baseOut {
		t.Fatalf("the disclosure moved stdout:\n--- before ---\n%s\n"+
			"--- after ---\n%s", baseOut, out)
	}
	if errS != a11WantLine("bbbbbbbbbbbb") {
		t.Fatalf("stderr = %q\nwant  = %q", errS, a11WantLine("bbbbbbbbbbbb"))
	}
	if n := strings.Count(errS, "framework:"); n != 1 {
		t.Fatalf("warn-once violated: %d disclosure lines in %q", n, errS)
	}
}

// TestBriefBuildSkewSilentCases pins the presence gates: a matching build, a
// pre-stamp pin (grandfather), and no pin at all are all silence — never a
// guess about a stamp the record does not carry.
func TestBriefBuildSkewSilentCases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sid     string
		build   string
		withKey bool
	}{
		{"matching build", "src-a11same01", version.Commit(), true},
		{"pre-stamp pin", "src-a11old001", "bbbbbbbbbbbb", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := mkroot(t)
			cid := initOne(t, root)
			c, err := state.Open(root, cid)
			if err != nil {
				t.Fatal(err)
			}
			a11Pin(t, c, tc.sid, tc.build, tc.withKey)
			code, out, errS := run(t, "--root", root, "brief", cid)
			if code != 0 {
				t.Fatalf("brief exit = %d: %q", code, errS)
			}
			if errS != "" {
				t.Fatalf("%s must stay silent, got stderr %q", tc.name, errS)
			}
			if strings.Contains(out, "framework:") {
				t.Fatalf("%s: the disclosure leaked into stdout:\n%s",
					tc.name, out)
			}
		})
	}
}

// TestBriefBuildSkewReadsNewestPin: the log is append-only, so the LAST pin's
// stamp is the campaign's latest word — an older pin never speaks for it, and
// a newest pin that carries no stamp is silence (the grandfather shape).
func TestBriefBuildSkewReadsNewestPin(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	a11Pin(t, c, "src-a11new001", "aaaaaaaaaaaa", true)
	a11Pin(t, c, "src-a11new002", "bbbbbbbbbbbb", true)
	code, _, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit = %d: %q", code, errS)
	}
	if errS != a11WantLine("bbbbbbbbbbbb") {
		t.Fatalf("stderr = %q\nwant the NEWEST pin's stamp: %q", errS,
			a11WantLine("bbbbbbbbbbbb"))
	}
	// A newer pin with no stamp: the campaign's latest word is silence.
	a11Pin(t, c, "src-a11new003", "cccccccccccc", false)
	code, _, errS = run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit = %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("an unstamped newest pin must stay silent, got %q", errS)
	}
}

// TestBriefBuildSkewJSONModeStaysJSON: --json keeps stdout a parseable brief
// and carries the disclosure on stderr alone.
func TestBriefBuildSkewJSONModeStaysJSON(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	a11Pin(t, c, "src-a11json01", "bbbbbbbbbbbb", true)
	code, out, errS := run(t, "--root", root, "brief", cid, "--json")
	if code != 0 {
		t.Fatalf("brief --json exit = %d: %q", code, errS)
	}
	var doc any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not JSON (%v):\n%s", err, out)
	}
	if errS != a11WantLine("bbbbbbbbbbbb") {
		t.Fatalf("stderr = %q\nwant  = %q", errS, a11WantLine("bbbbbbbbbbbb"))
	}
}
