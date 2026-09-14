// processlock.go — r13: cross-process integrity of one campaign. Until
// now every guard was IN-process (c.mu) and every write was atomic
// per-CALL (tmp+rename). Two webv2 processes racing the same campaign
// corrupted it silently: concurrent `hint`s interleaved Log()'s read →
// append → save and produced duplicate/missing seqs (a ledger both
// processes reported success for, one event short), and two `snap`s
// last-writer-wined the state so a pin dir + its event survived with no
// row — invisible to the state->event projection check. Filesystem
// atomicity is not concurrency control; an OS advisory lock is.
//
// The law: any sequence that READS ledger or state and APPENDS/WITES it
// must hold the campaign lock for its whole duration — r14 found that
// locking only the WRITE half (SaveState) still lost updates when the
// State() load happened outside; so the load-modify-write windows
// (floors Set/Clear, probes SetBlank, evalscore Record, orchestrator
// scope) take LockProcess at entry and the depth count rides through
// SaveState/Log re-entry. That is Log (read
// tail → append → mirror-save) and every save (read-modify-write via
// State()). Lock discipline mirrors the rest of this package: loud
// failure, never silent skip — a lock that cannot be taken within the
// budget returns an error naming the cause.
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// lockBudget is how long a writer waits for another process before it
// gives up loudly. Log/save windows are milliseconds; five seconds is
// orders of magnitude beyond any honest hold, so a timeout means a real
// stuck or hostile holder — retry beats hang.
const lockBudget = 5 * time.Second

type processLock struct {
	mu    sync.Mutex
	fd    int
	open  bool
	depth int
}

func (l *processLock) lock(path, campaignID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.depth > 0 { // same-process re-entry: one OS lock, counted
		l.depth++
		return nil
	}
	if !l.open {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR, 0o644)
		if err != nil {
			return err
		}
		l.fd, l.open = fd, true
	}
	deadline := time.Now().Add(lockBudget)
	for {
		err := syscall.Flock(l.fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			l.depth = 1
			// Name the holder for anyone who times out (advisory,
			// best-effort — the pid may have exited; still beats "who
			// knows what"): pid + human-readable command line.
			info := fmt.Sprintf("%d %s", os.Getpid(),
				strings.ReplaceAll(strings.Join(os.Args, " "), "\n", " "))
			if _, werr := syscall.Pwrite(l.fd, []byte(info), 0); werr == nil {
				_ = syscall.Ftruncate(l.fd, int64(len(info)))
			}
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return fmt.Errorf("campaign lock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			holder := "unknown holder"
			if raw, rerr := os.ReadFile(path); rerr == nil && len(raw) > 0 {
				holder = string(raw)
			}
			return fmt.Errorf("campaign %s is locked by another process "+
				"(waited %s; holder: %s) — let the running webv2 finish "+
				"and retry; do NOT edit the ledger or state by hand",
				campaignID, lockBudget, holder)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (l *processLock) unlock() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.depth == 0 {
		return
	}
	l.depth--
	if l.depth == 0 {
		_ = syscall.Flock(l.fd, syscall.LOCK_UN)
		// The fd survives for the next acquisition; the kernel releases
		// the lock on process exit either way.
	}
}

// LockProcess takes the cross-process campaign lock (re-entrant per
// process, counted). Writers that span multiple files — a waiver row
// plus its event, a snapshot dir plus manifest — wrap the WHOLE unit,
// not each write.
func (c *Campaign) LockProcess() error {
	return c.plock.lock(c.lockPath(), c.CampaignID)
}

// UnlockProcess releases one held depth. Always paired with
// LockProcess via defer.
func (c *Campaign) UnlockProcess() { c.plock.unlock() }

// lockPath is campaign-dir/campaign.lock — deliberately NOT a registered
// artifact and never validated: it is OS metadata, like a lockfile in
// any package manager. It appears in no state projection.
func (c *Campaign) lockPath() string {
	return filepath.Join(c.Dir, "campaign.lock")
}

// rawState is the pre-write snapshot bytes for the unwind discipline
// (r16: the r9 PinSnapshot law — save-then-log is only atomic if a
// failed Log RESTORES the exact pre-pin bytes — generalized to every
// state-mutating method): read campaign_state.json as bytes before the
// first save; on ledger refusal, write them back and report the save
// undone. had=false when the file did not exist yet (unwind removes it).
func (c *Campaign) rawState() ([]byte, bool) {
	raw, err := os.ReadFile(c.StatePath)
	if err != nil {
		return nil, false
	}
	return raw, true
}
