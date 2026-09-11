package briefing

// M6 + skew-detector tests (framework eval follow-up).
//
// M6: an untouched lens must name its mechanical table in next_actions —
// the G-01 miss showed a brief can nag "questions worked 0/48" while never
// routing the operator to the unworked lens's street. Skew: a snapshot
// pinned with one build and briefed with another must say so.

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// m6Lens is one divergence lens row: id, plan status, and probe closure
// counts (nil probe = the surface carries none of the lens's axes).
func m6Lens(id, status string, probe validation.Value) validation.Value {
	return validation.VObj(
		kv("id", validation.VStr(id)),
		kv("lens", validation.VStr("lens-of-"+id)),
		kv("status", validation.VStr(status)),
		kv("probe", probe))
}

func m6Probe(rows, disp, open int64, closed bool) validation.Value {
	return validation.VObj(
		kv("rows", validation.VInt(rows)),
		kv("dispositioned", validation.VInt(disp)),
		kv("open", validation.VInt(open)),
		kv("closed", validation.VBool(closed)))
}

// m6Brief is a NextActions-ready brief carrying the given lens rows. The
// gate deficit keeps a generic action on the list so the orchestrator
// fallback (which needs a live campaign) never fires under a nil campaign.
func m6Brief(lenses ...validation.Value) validation.Value {
	return validation.VObj(
		kv("campaign", validation.VObj(
			kv("closed", validation.VBool(false)),
			kv("campaign_id", validation.VStr(t35ProbeCID)))),
		kv("criticality", validation.VNull()),
		kv("divergence", validation.VObj(
			kv("closed", validation.VBool(false)),
			kv("lenses", validation.VArr(lenses...)))),
		kv("integrity", validation.VObj(kv("ok", validation.VBool(true)))),
		kv("economics", validation.VObj(
			kv("budget", validation.VObj(
				kv("status", validation.VStr("within")))))),
		kv("findings", validation.VObj(
			kv("materializable_chains", validation.VArr()),
			kv("memory_recall_pending", validation.VArr()),
			kv("structurally_unreachable", validation.VArr()),
			kv("gate_deficits", validation.VArr(validation.VObj(
				kv("finding_id", validation.VStr("F-1")),
				kv("status", validation.VStr("POSSIBLE")),
				kv("level", validation.VStr("E3")),
				kv("deficit", validation.VStr("needs E5"))))))),
		kv("independent_verification_queue", validation.VArr()),
		kv("bounty", validation.VObj(kv("evaluated", validation.VArr()))),
		kv("pending_memory", validation.VArr()),
		kv("terminals", validation.VArr()),
		kv("probe_surface", validation.VObj(
			kv("rows", validation.VInt(3)),
			kv("dispositioned", validation.VInt(0)),
			kv("open", validation.VInt(3)),
			kv("stale", validation.VBool(false)),
			kv("open_rows", validation.VArr()))))
}

func m6Actions(t *testing.T, brief validation.Value) []string {
	t.Helper()
	actions, err := NextActions(brief, nil)
	if err != nil {
		t.Fatal(err)
	}
	return actions
}

func hasPrefixAction(actions []string, prefix string) string {
	for _, a := range actions {
		if strings.HasPrefix(a, prefix) {
			return a
		}
	}
	return ""
}

func TestUntouchedL03RoutesToEnforce(t *testing.T) {
	actions := m6Actions(t, m6Brief(
		m6Lens("L-03", "open", m6Probe(3, 0, 3, false))))
	got := hasPrefixAction(actions, "L-03 open with 0/3 rows dispositioned")
	if got == "" {
		t.Fatalf("no L-03 routing line: %v", actions)
	}
	if !strings.Contains(got, "webv2 enforce "+t35ProbeCID) {
		t.Fatalf("L-03 line does not name the enforce table: %q", got)
	}
}

func TestUntouchedL04WithoutSurfaceRoutesToSymmetry(t *testing.T) {
	actions := m6Actions(t, m6Brief(
		m6Lens("L-04", "open", validation.VNull())))
	got := hasPrefixAction(actions, "L-04 has no probe surface")
	if got == "" {
		t.Fatalf("no L-04 routing line: %v", actions)
	}
	if !strings.Contains(got, "webv2 symmetry "+t35ProbeCID) {
		t.Fatalf("L-04 line does not name the symmetry matrix: %q", got)
	}
}

func TestWorkedClosedAndTablelessLensesStaySilent(t *testing.T) {
	actions := m6Actions(t, m6Brief(
		// dispositioned rows: per-row actions already route the operator
		m6Lens("L-01", "open", m6Probe(4, 2, 2, false)),
		// closed lens: nothing to route
		m6Lens("L-03", "answered", m6Probe(3, 3, 0, true)),
		// L-02 has no table verb: its trust rows ride the per-row actions
		m6Lens("L-02", "open", m6Probe(2, 0, 2, false))))
	for _, a := range actions {
		if strings.HasPrefix(a, "L-01 ") || strings.HasPrefix(a, "L-02 ") ||
			strings.HasPrefix(a, "L-03 ") {
			t.Fatalf("unexpected lens routing line: %q (all: %v)", a, actions)
		}
	}
}

func TestNoDivergenceMeansNoRouting(t *testing.T) {
	brief := m6Brief()
	brief.O = validation.SetOrAppend(brief.O, "divergence", validation.VNull())
	actions := m6Actions(t, brief)
	for _, a := range actions {
		if strings.HasPrefix(a, "L-0") {
			t.Fatalf("routing line without divergence data: %q", a)
		}
	}
}

// skewCampaign crafts a snapshot.pinned event for sid carrying pinBuild
// as its framework_build (withKey=false reproduces the pre-stamp campaign
// shape: no key at all). Event crafting — not PinSnapshot — is the right
// level here: the production stamp path is pinned by the CLI snap test,
// while these tests own the READING side (pinBuild/skewAction). Callers
// set the RUNNING build via t.Setenv("WEBV2_BUILD", ...) before
// NextActions, so pin and running builds vary independently exactly like
// two different binaries.
func skewCampaign(t *testing.T, sid, pinBuild string, withKey bool) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Skew", state.InitOpts{
		CampaignID: t35ProbeCID})
	if err != nil {
		t.Fatal(err)
	}
	data := validation.VObj(kv("ladder", validation.VStr("no-vcs")))
	if withKey {
		data.O = append(data.O,
			validation.KV{K: "framework_build", V: validation.VStr(pinBuild)})
	}
	if _, err := c.Log("snapshot.pinned", &sid, &data); err != nil {
		t.Fatal(err)
	}
	return c
}

func skewBrief(sid string) validation.Value {
	brief := m6Brief()
	brief.O = validation.SetOrAppend(brief.O, "divergence", validation.VNull())
	brief.O = validation.SetOrAppend(brief.O, "probe_surface", validation.VNull())
	camp := objAt(brief, "campaign")
	camp.O = validation.SetOrAppend(camp.O, "active_snapshot",
		validation.VStr(sid))
	brief.O = validation.SetOrAppend(brief.O, "campaign", camp)
	return brief
}

func TestSkewWarnsOnBuildMismatch(t *testing.T) {
	t.Setenv("WEBV2_BUILD", "aaaaaaaaaaaa")
	c := skewCampaign(t, "src-skew0001", "bbbbbbbbbbbb", true)
	actions, err := NextActions(skewBrief("src-skew0001"), c)
	if err != nil {
		t.Fatal(err)
	}
	got := hasPrefixAction(actions, "framework skew:")
	if got == "" {
		t.Fatalf("no skew line for a mismatched pin: %v", actions)
	}
	for _, want := range []string{"src-skew0001", "bbbbbbbbbbbb",
		"aaaaaaaaaaaa"} {
		if !strings.Contains(got, want) {
			t.Fatalf("skew line %q lacks %q", got, want)
		}
	}
}

func TestSkewSilentOnMatchAndGrandfather(t *testing.T) {
	// same build: silent
	t.Setenv("WEBV2_BUILD", "aaaaaaaaaaaa")
	c := skewCampaign(t, "src-skew0002", "aaaaaaaaaaaa", true)
	actions, err := NextActions(skewBrief("src-skew0002"), c)
	if err != nil {
		t.Fatal(err)
	}
	if got := hasPrefixAction(actions, "framework skew:"); got != "" {
		t.Fatalf("skew line for a matching pin: %q", got)
	}
	// pre-stamp campaign (no key): silent — the grandfather rule
	old := skewCampaign(t, "src-skew0003", "bbbbbbbbbbbb", false)
	actions, err = NextActions(skewBrief("src-skew0003"), old)
	if err != nil {
		t.Fatal(err)
	}
	if got := hasPrefixAction(actions, "framework skew:"); got != "" {
		t.Fatalf("skew line for a pre-stamp pin: %q", got)
	}
}
