package reproduction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// --- G15 PoC quality gate at mint (Task 23) ---------------------------------
//
// Two fail-open advisories ride the minted evidence item as metadata. They
// never block the mint: every degraded path below resolves to "mint
// without the advisory" (or a not-applicable marker), never to a refusal.
//
//   - reruns: opt-in via VerifyReruns (`mint --verify-reruns`, default OFF)
//     and only for E4-capable profiles. The recorded command is re-run
//     rerunAttempts times; exit-vector (exit status + stdout hash) equality
//     across runs decides "3/3" vs "flaky n/3", with the rerun exec ids
//     appended as the audit join ("3/3 (execs EXEC-a,EXEC-b,EXEC-c)").
//     A missing container runtime resolves to "not-applicable" plus a
//     CLI warning line.
//   - fork_stale: always on (freshness is data, not judgment). The pinned
//     snapshot's fork_timestamp (fallback: created_at) is compared against
//     the exec's started_at; age beyond forkStaleDays, or a null
//     fork_timestamp, marks the item stale with a reason marker first
//     ("stale: no snapshot data recorded" / "stale: fork timestamp
//     missing" / "stale: pinned N days ago"). Fresh snapshots gain no key.

// rerunAttempts is the G15 rerun count (policy-tunable = code const).
const rerunAttempts = 3

// forkStaleDays is the G15 fork-freshness threshold in days
// (policy-tunable = code const for now; campaign_state wiring is G13's
// budget block's job later).
const forkStaleDays = 7

// VerifyReruns gates the 3x-rerun variance advisory. Set by
// `mint --verify-reruns`; default false (flag OFF = zero behavior change
// on the reruns half).
var VerifyReruns bool

// ErrRerunUnavailable is the docker-absent sentinel: the rerun seam
// reports it (via errors.Is) when no container runtime can run the rerun.
var ErrRerunUnavailable = errors.New(
	"container runtime unavailable for reruns")

// defaultRerunExecutor is the real sandbox.Run call behind the seam. It
// returns the rerun's own exec_id first: the audit join for variance
// reruns lives on the EVIDENCE item (`reruns:"3/3 (execs EXEC-a,...)"`),
// never on the exec record (see rerunAdvisory).
var defaultRerunExecutor = func(c *state.Campaign, profile,
	command string) (string, int, []byte, error) {
	sb, err := sandbox.NewSandbox(c, profile)
	if err != nil {
		var ue *sandbox.UnavailableError
		if errors.As(err, &ue) {
			return "", 0, nil, ErrRerunUnavailable
		}
		return "", 0, nil, err
	}
	rec, err := sb.Run(command, sandbox.RunOpts{})
	if err != nil {
		return "", 0, nil, err
	}
	exit := 0
	if e := validation.ObjAt(rec, "exit_status"); e.Kind == validation.Int {
		exit = int(e.I)
	}
	out, err := os.ReadFile(validation.ObjStr(rec, "stdout_path"))
	if err != nil {
		out = []byte(sandbox.ExecOutput(rec))
	}
	return validation.ObjStr(rec, "exec_id"), exit, out, nil
}

// rerunExecutor is the G15 executor seam: re-run command under profile,
// reporting the rerun's exec_id, exit status and captured stdout.
// Tests swap it for stubbed flaky/deterministic outputs (stubs return
// synthetic EXEC- ids so the evidence join is exercised); a docker-absent
// runtime surfaces as ErrRerunUnavailable.
var rerunExecutor = defaultRerunExecutor

// SetRerunExecutor installs the rerun seam (nil restores the default).
// Cross-package CLI tests use this; in-package tests swap the var.
func SetRerunExecutor(fn func(*state.Campaign, string,
	string) (string, int, []byte, error)) {
	if fn == nil {
		fn = defaultRerunExecutor
	}
	rerunExecutor = fn
}

// sha256Hex is _sha's digest half: hex sha256 over bytes (the same hashing
// the exec record's artifact_hashes use).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// execStdoutHash is the cited exec's stdout hash: the recorded
// artifact_hashes entry when present (byte-identical to what the ledger
// hashed), else the hash of the given bytes. Both the rerun gate and the
// post-patch verdict share this preference.
func execStdoutHash(rec validation.Value, raw []byte) string {
	if h := validation.ObjStr(validation.ObjAt(rec, "artifact_hashes"), "stdout.log"); h != "" {
		return h
	}
	return sha256Hex(raw)
}

// origStdoutHash is the cited exec's stdout hash over the captured output.
func origStdoutHash(rec validation.Value) string {
	return execStdoutHash(rec, []byte(sandbox.ExecOutput(rec)))
}

// rerunsText renders the variance value with its audit join: the base
// verdict plus the rerun exec ids in run order, so an auditor can walk
// from the evidence item to the exact EXEC records that back it. With no
// ids (only possible when every rerun errored before producing an exec)
// the bare base verdict stands alone.
func rerunsText(match int, ids []string) string {
	base := fmt.Sprintf("flaky %d/%d", match, rerunAttempts)
	if match == rerunAttempts {
		base = fmt.Sprintf("%d/%d", rerunAttempts, rerunAttempts)
	}
	if len(ids) == 0 {
		return base
	}
	return base + " (execs " + strings.Join(ids, ",") + ")"
}

// rerunAdvisory runs the variance gate. It returns the advisory string for
// the evidence item ("3/3 (execs ...)", "flaky n/3 (execs ...)",
// "not-applicable", or "" when the gate does not apply) and whether the
// docker-absent warning line is owed.
// "" with warn=false means flag off or a non-E4 profile: no key gained,
// no warning.
//
// Provenance rail (fix round 1): sandbox.RunOpts offers NO
// provenance-capable field — its exact shape is {Workdir *string,
// FindingID *string, ArtifactID *string, Timeout int, Env []EnvVar} — and
// a locally-executed record hardcodes origin="locally-executed" with
// reported_by=null. FindingID/ArtifactID are linkage ids (repurposing
// them corrupts joins), Env/Workdir change execution semantics, and the
// command text must not be mutated. So rerun execs carry no per-record
// marker; the audit join is the exec-id list in the evidence value, and
// the cited original exec record is never rewritten by the mint path.
func rerunAdvisory(c *state.Campaign, rec validation.Value) (string, bool) {
	if !VerifyReruns {
		return "", false
	}
	profile := validation.ObjStr(rec, "profile")
	if _, ok := sandbox.E4_PROFILES[profile]; !ok {
		return "", false
	}
	command := validation.ObjStr(rec, "command")
	wantExit := 0
	if e := validation.ObjAt(rec, "exit_status"); e.Kind == validation.Int {
		wantExit = int(e.I)
	}
	wantHash := origStdoutHash(rec)
	match := 0
	ids := []string{}
	for i := 0; i < rerunAttempts; i++ {
		execID, exit, out, err := rerunExecutor(c, profile, command)
		if err != nil {
			if errors.Is(err, ErrRerunUnavailable) {
				return "not-applicable", true
			}
			continue // fail-open: a failed rerun is a non-match
		}
		if execID != "" {
			ids = append(ids, execID)
		}
		if exit == wantExit && sha256Hex(out) == wantHash {
			match++
		}
	}
	return rerunsText(match, ids), false
}

// parseStamp parses the twin-clock timestamps (WEBV2_NOW pins them
// verbatim; else UTC microseconds with +00:00).
func parseStamp(s string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05.999999999Z07:00", s)
}

// forkBlockText renders the snapshot's fork_block, or "unknown" when the
// pin carries none (null chain, absent key, non-numeric).
func forkBlockText(chain validation.Value) string {
	b := validation.ObjAt(chain, "fork_block")
	if b.Kind == validation.Int {
		return strconv.FormatInt(b.I, 10)
	}
	if b.Kind == validation.Str && b.S != "" {
		return b.S
	}
	return "unknown"
}

// forkStaleText renders the fork_stale message: a reason marker FIRST
// (so null-chain, null-timestamp and genuine-age staleness are mutually
// distinguishable) followed by the detail text. Reason is one of:
// "no snapshot data recorded" (null/absent chain), "fork timestamp
// missing" (chain pin without fork_timestamp), "pinned N days ago"
// (genuine age beyond the window), or "pinned <raw timestamp>" (a present
// but unparseable timestamp — stale by the fail-open law, with no day
// count claimed).
func forkStaleText(reason, date, block string) string {
	return fmt.Sprintf("stale: %s \u2014 snapshot pinned %s fork_block "+
		"%s \u2014 re-pin with snap + re-mint", reason, date, block)
}

// forkStaleAdvisory is the always-on freshness half: "" when the pinned
// snapshot is fresh (no key is gained), else the fork_stale message. It
// never errors and never blocks the mint — without a source pin, or with
// an unreadable snapshot file, there is nothing to judge against, so the
// item stays silent.
func forkStaleAdvisory(c *state.Campaign, f,
	rec validation.Value) string {
	srcID := validation.ObjStr(validation.ObjAt(f, "snapshot_ids"), "source")
	if srcID == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(c.Dir, "snapshots", srcID,
		"snapshot.json"))
	if err != nil {
		return ""
	}
	snap, err := validation.ParseOrdered(raw)
	if err != nil {
		return ""
	}
	chain := validation.ObjAt(snap, "chain")
	block := forkBlockText(chain)
	pinned := ""
	if ts := validation.ObjAt(chain, "fork_timestamp"); ts.Kind == validation.Str &&
		ts.S != "" {
		pinned = ts.S
	}
	if pinned == "" {
		// Null chain or null fork_timestamp: stale, dated by what the
		// pin does carry (created_at) or "unknown" — with the reason
		// named so the two data-absent shapes stay distinguishable.
		date := validation.ObjStr(snap, "created_at")
		if date == "" {
			date = "unknown"
		}
		reason := "fork timestamp missing"
		if chain.Kind != validation.Obj {
			reason = "no snapshot data recorded"
		}
		return forkStaleText(reason, date, block)
	}
	tFork, err := parseStamp(pinned)
	tExec, err2 := parseStamp(validation.ObjStr(rec, "started_at"))
	if err != nil || err2 != nil {
		return forkStaleText("pinned "+pinned, pinned, block)
	}
	age := tExec.Sub(tFork)
	if age > time.Duration(forkStaleDays)*24*time.Hour {
		return forkStaleText(fmt.Sprintf("pinned %d days ago",
			int(age.Hours()/24)), pinned, block)
	}
	return ""
}

var mintNoticeMu sync.Mutex
var lastMintNotice string

func setMintNotice(n string) {
	mintNoticeMu.Lock()
	defer mintNoticeMu.Unlock()
	lastMintNotice = n
}

// TakeMintNotice returns the fail-open advisory notice from the most
// recent mint on this process ("" when none) and clears it. cmd_mint
// prints it as a stderr warning line.
func TakeMintNotice() string {
	mintNoticeMu.Lock()
	defer mintNoticeMu.Unlock()
	n := lastMintNotice
	lastMintNotice = ""
	return n
}

// applyMintAdvisories attaches the G15 advisories to a fresh evidence
// item: reruns only when the flag + profile gates hold, fork_stale
// whenever the pin reads stale. It returns the item and the CLI warning
// line ("" when none is owed).
func applyMintAdvisories(c *state.Campaign, item, f,
	rec validation.Value) (validation.Value, string) {
	warn := ""
	if r, w := rerunAdvisory(c, rec); r != "" {
		item = setKey(item, "reruns", validation.VStr(r))
		if w {
			warn = "warning: reruns not-applicable " +
				"(container runtime unavailable) \u2014 evidence " +
				"minted without variance data"
		}
	}
	if s := forkStaleAdvisory(c, f, rec); s != "" {
		item = setKey(item, "fork_stale", validation.VStr(s))
	}
	return item, warn
}
