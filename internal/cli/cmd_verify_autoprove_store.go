// cmd_verify_autoprove_store: the content-addressed report
// copy store — digest-named immutable rows inside the campaign, with the
// shape, race and durability rails.
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"websec/internal/state"
	"websec/internal/validation"
)

// storeReportCopy writes the mapped bytes into the campaign store at a
// digest-named path (idempotent: an existing copy is verified, never
// overwritten — the rows are immutable by construction).
//
// r26 F2: the tmp+rename dance has a crash seam. A process killed after
// the write and before the rename leaves a tmp on disk; while that tmp
// was created 0444, the NEXT bind of the same digest opened it for
// writing, took EACCES as the owner, and refused that digest FOREVER — a
// transient crash became a permanent unavailability. The tmp is written
// 0600 so a leftover is always overwritable by its owner (the 0444 lands
// on the FINAL name only, after the rename), and a leftover LEGACY tmp is
// SWEPT rather than trusted — bytes that already hash to the digest are
// renamed into place (the crash cost nothing) and anything else is
// scratch, removed and rewritten. The tmp is fsynced and closed before
// the rename, matching validation.WriteJson: without it the rename can
// land before the bytes do, and a power loss publishes a zero-length or
// partial file under a content-addressed name the registry will then
// refuse.
//
// r27 hardening (F2/F3/F4/F5/F6), all in this one function:
//   - the store NEVER operates through a link (F2/F3). A symlink at the
//     tmp or the final name is a REFUSAL naming the shape: os.Rename
//     moves the LINK into place and the following os.Chmod FOLLOWS it,
//     which rewrote a victim's mode outside the campaign (observed
//     0644 -> 0444), and a link at the final name let a matching-bytes
//     target masquerade as the immutable copy. A directory/fifo/device
//     at either name is the same refusal class (F5) — a non-empty
//     directory at the tmp name used to wedge that digest forever
//     behind a message that misdiagnosed it as crash scratch.
//   - the scratch name is PER-CALL unique (F4), so two processes binding
//     one digest never share it; a rename that loses to a writer which
//     published the same digest is accepted only after re-reading the
//     final path and hashing it back to the digest.
//   - the durability step is CHECKED, not swallowed (F6): a directory
//     that cannot be opened for fsync is surfaced with its path and its
//     error, and the 0444 mode itself is fsynced after the chmod.
//
// r28 hardening (F4 + adoption sealing) adds the two halves the same
// discipline was missing:
//   - the DIRECTORY the store writes in is verified BEFORE anything is
//     written (F4). storeRefuseNonRegular guards the two names, but
//     os.MkdirAll follows a symlink, so a link at artifacts/reports made
//     this function write (and chmod 0444) a file in a directory outside
//     the campaign. A symlink/non-directory at the reports dir — or at
//     the artifacts dir above it — is refused by shape; the store must
//     live inside the campaign.
//   - an ADOPTED copy (bytes already at the final name) is sealed 0444
//     after its bytes are verified, exactly like a written one; a bind
//     that found a planted 0646 file used to hand that path back as the
//     read-only copy the docs promise. A failed seal is a refusal, never
//     an unsealed path.
func storeReportCopy(c *state.Campaign, digest string,
	raw []byte) (string, error) {
	dir := filepath.Join(c.ArtifactsDir, "reports")
	// r28 F4: the DIRECTORY the store writes in is checked before any
	// write, not just the two names inside it. os.MkdirAll FOLLOWS a
	// symlink, so a link at <campaign>/artifacts/reports pointing at
	// /tmp/victimDir made this function create /tmp/victimDir/report-
	// <sha>.json (mode 0444) — a write AND a chmod outside the campaign,
	// with no audit-visible trace: storeRefuseNonRegular lstat-checks the
	// final and the scratch NAMES, and the directory above them was never
	// inspected. The store is a directory the campaign owns: lstat both
	// levels, create what is absent, refuse any symlink (or non-directory)
	// by shape instead of resolving through it.
	if err := storeEnsureStoreDir(c.ArtifactsDir, "artifacts directory"); err != nil {
		return "", err
	}
	if err := storeEnsureStoreDir(dir, "report store"); err != nil {
		return "", err
	}
	// Full digest in the NAME, not a 12-hex prefix: a content-addressed
	// store whose name is truncated can collide, and the collision arm
	// REFUSES a legitimate bind (availability hazard for zero benefit).
	p := filepath.Join(dir, "report-"+digest+".json")
	// r27 F3: the FINAL name must be a REGULAR file the store itself
	// owns. os.ReadFile follows a link, so a symlink here whose target
	// held the digest was accepted as the immutable copy — and
	// rewriting that target later made §11 burn the honest bind with
	// "cannot be re-read from the store".
	if err := storeRefuseNonRegular(p); err != nil {
		return "", err
	}
	if cur, err := os.ReadFile(p); err == nil {
		if validation.Sha256Hex(cur) == digest {
			// r28 (adoption sealing): a pre-existing copy whose bytes
			// match is ADOPTED, and adoption owes the copy the same 0444
			// the write path publishes. The audit planted a matching-
			// bytes file at the final name with mode 0646 and it
			// survived the bind: the row said "immutable copy", the
			// docs promised read-only, and the bytes on disk said
			// otherwise. Seal it after verifying the bytes, and refuse
			// when the seal fails — a path this call could not seal is
			// not one it can hand back as the immutable copy.
			if serr := storeSeal(dir, p); serr != nil {
				return "", serr
			}
			return p, nil // the honest copy already stands
		}
		return "", fmt.Errorf("%s exists with foreign bytes (impossible "+
			"under a sha-named path: a prior collision or a tamper)", p)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	// Sweep the crash seam of the LEGACY fixed tmp name: a leftover tmp
	// whose bytes ARE the digest was written by an earlier run of this
	// very call — finish its rename instead of redoing the write.
	// r27 F2/F5 run FIRST: a link, directory, fifo or device at that
	// name is not scratch, it is a refusal.
	legacy := p + ".tmp"
	if err := storeRefuseNonRegular(legacy); err != nil {
		return "", err
	}
	if cur, err := os.ReadFile(legacy); err == nil &&
		validation.Sha256Hex(cur) == digest {
		if rerr := os.Rename(legacy, p); rerr == nil {
			if err := storeSeal(dir, p); err != nil {
				return "", err
			}
			return p, nil
		} else if !os.IsNotExist(rerr) {
			return "", rerr
		}
		// A concurrent writer took the legacy tmp and published this
		// digest: succeed only against an honest final copy.
		return storeAdoptPublished(dir, p, digest)
	}
	// Anything else at the legacy name is scratch, never evidence — and
	// it may carry the old 0444 mode, which its own owner cannot open
	// for writing. Remove it (the directory is what grants us that, not
	// the file) so the stale mode can never deny the digest it names.
	if err := os.Remove(legacy); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot clear the scratch file %s "+
			"left by an interrupted store: %w", legacy, err)
	}
	// r27 F4: the scratch name is PER-CALL unique — os.CreateTemp's
	// random suffix, the same shape validation.WriteJson uses
	// (name.tmp-<rand>: recognisable as a crash leftover, one writer per
	// scratch file) — so two processes binding one digest never share
	// scratch. The old fixed name made the loser's os.Rename return
	// ENOENT and exit 2 with a raw "no such file or directory" on the
	// very path the docs call idempotent (reproduced 4/8 and 2/10
	// rounds). CreateTemp's O_EXCL is the other half: whatever a hostile
	// writer planted at a guessed name is never written through — the
	// call simply gets a fresh name. The defer is the whole failure-path
	// story: this call's scratch never accumulates.
	fh, err := os.CreateTemp(dir, filepath.Base(p)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("cannot create the report scratch for %s "+
			"in %s: %w", digest, dir, err)
	}
	tt := fh.Name()
	defer func() { _ = os.Remove(tt) }()
	// Belt and braces on the exact name we are about to write through.
	if err := storeRefuseNonRegular(tt); err != nil {
		fh.Close()
		return "", err
	}
	// The create mode is filtered by umask, so the 0600 is set on the
	// OPEN handle; and the Sync below must be ours to check — a
	// swallowed fsync error is the crash seam this close exists for.
	if _, err := fh.Write(raw); err != nil {
		fh.Close()
		return "", err
	}
	if err := fh.Chmod(0o600); err != nil {
		fh.Close()
		return "", err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return "", fmt.Errorf("cannot fsync the report tmp %s: %w "+
			"(the rename must not publish bytes the disk never got)",
			tt, err)
	}
	if err := fh.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tt, p); err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		// r27 F4(b): the tmp vanished under the rename because another
		// writer published the identical digest. That is a lost race,
		// not a failure — adopt the published copy if (and only if) its
		// bytes hash to the digest this bind names.
		return storeAdoptPublished(dir, p, digest)
	}
	// 0444 lands AFTER the rename: the tmp name must stay owner-writable
	// for the life of the crash window, or a kill -9 between the two
	// steps re-creates the wedge this rail removes. The seal fsyncs the
	// mode and the directory entry (r27 F6).
	if err := storeSeal(dir, p); err != nil {
		return "", err
	}
	return p, nil
}

// storeSyncRefused: a Sync failure that means the FILESYSTEM cannot do
// it, not that the durability step silently did not happen. Everything
// else is surfaced (r27 F6).
func storeSyncRefused(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.ENOSYS)
}

// storePathShape names what was actually found at a store path, so the
// refusal can state the exact shape observed (r27 F5). The regular-file
// case became reachable with r28 F4's directory rail: a plain FILE where a
// store DIRECTORY belongs is named as one ("regular file", not its raw
// mode string) in the refusal that tells the operator the store must live
// inside the campaign.
func storePathShape(fi os.FileInfo) string {
	m := fi.Mode()
	switch {
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "directory"
	case m&os.ModeNamedPipe != 0:
		return "fifo"
	case m&os.ModeSocket != 0:
		return "socket"
	case m&os.ModeCharDevice != 0:
		return "character device"
	case m&os.ModeDevice != 0:
		return "block device"
	case m.IsRegular():
		return "regular file"
	}
	return m.String()
}

// storeEnsureStoreDir is the r28 F4 directory rail: the store may only
// write into a REAL directory the campaign owns. lstat (never Stat) the
// path; a missing one is created 0755 (MkdirAll, then re-lstat so a link
// planted in the race is still seen as a link); an existing symlink — or
// any other non-directory — is a REFUSAL naming the path and the shape
// found, because the store must live inside the campaign. Resolving
// through the link and continuing is exactly the escape this refuses:
// os.MkdirAll follows a link, so the write and its 0444 chmod land
// outside the campaign with no audit-visible trace.
func storeEnsureStoreDir(path, role string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if merr := os.MkdirAll(path, 0o755); merr != nil {
			return fmt.Errorf("cannot create the %s %s: %w", role, path,
				merr)
		}
		if fi, err = os.Lstat(path); err != nil {
			return err
		}
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("the %s %s is a %s, not a directory - the store "+
			"must live inside the campaign, never through a link (a "+
			"symlinked store directory writes the evidence outside it)",
			role, path, storePathShape(fi))
	}
	return nil
}

// storeRefuseNonRegular: the store never operates THROUGH an object.
// lstat (not Stat) both the tmp and the final name; a non-regular object
// is a REFUSAL naming its shape, never scratch to delete (r27 F2/F3/F5).
func storeRefuseNonRegular(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode().IsRegular() {
		// r27b: a HARDLINK is regular to lstat, so a shared inode walks
		// past the shape check — and a chmod through it rewrites the
		// mode of every other name for those bytes. The copy must be a
		// file the store ALONE names.
		if n, ok := storeLinkCount(fi); ok && n > 1 {
			return fmt.Errorf("the store path %s is a regular file with "+
				"%d hard links - the copy must be a file only the store "+
				"names (a shared inode means the read-only chmod "+
				"rewrites a foreign name too)", path, n)
		}
		return nil
	}
	return fmt.Errorf("the store path %s is a %s, not the copy - the "+
		"immutable record must be a regular file inside the campaign",
		path, storePathShape(fi))
}

// storeLinkCount reads the link count where the platform reports one.
func storeLinkCount(fi os.FileInfo) (uint64, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink), true
	}
	return 0, false
}

// storeAdoptPublished: a rename lost the race to a writer that published
// this digest. Success is honest ONLY if the final path is a regular file
// the store owns whose bytes hash to the digest; anything else is the
// refusal it deserves (r27 F3/F4).
func storeAdoptPublished(dir, p, digest string) (string, error) {
	if err := storeRefuseNonRegular(p); err != nil {
		return "", err
	}
	cur, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("the report scratch for %s vanished before "+
			"the rename and the store does not hold it: %w", digest, err)
	}
	if validation.Sha256Hex(cur) != digest {
		return "", fmt.Errorf("%s exists with foreign bytes (impossible "+
			"under a sha-named path: a prior collision or a tamper)", p)
	}
	if err := storeSeal(dir, p); err != nil {
		return "", err
	}
	return p, nil
}

// storeSeal publishes the immutable copy: 0444 ON the regular file, then
// fsync OF the file (so a crash cannot leave the copy 0600 while the docs
// promise 0444) and fsync of the directory entry that names it (so power
// loss cannot leave a registry row citing a file the disk never got).
// Only failures meaning "this filesystem cannot" are tolerated (r27 F6):
// an OPEN failure is surfaced with its path and its error — a reports
// directory the process cannot open (mode 0333 -> EACCES) used to skip
// the whole durability step silently in the name of best-effort.
func storeSeal(dir, p string) error {
	if err := storeRefuseNonRegular(p); err != nil {
		return err
	}
	if err := os.Chmod(p, 0o444); err != nil {
		return fmt.Errorf("cannot set the immutable mode 0444 on the "+
			"published copy %s: %w", p, err)
	}
	fh, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("cannot open the published copy %s to fsync its "+
			"0444 mode: %w", p, err)
	}
	serr := fh.Sync()
	fh.Close()
	if serr != nil && !storeSyncRefused(serr) {
		return fmt.Errorf("cannot fsync the published copy %s after the "+
			"0444 chmod: %w", p, serr)
	}
	d, derr := os.Open(dir)
	if derr != nil {
		return fmt.Errorf("cannot open the report store %s to fsync the "+
			"rename that published %s: %w", dir, p, derr)
	}
	dserr := d.Sync()
	d.Close()
	if dserr != nil && !storeSyncRefused(dserr) {
		return fmt.Errorf("cannot fsync the report store %s: %w",
			dir, dserr)
	}
	return nil
}
