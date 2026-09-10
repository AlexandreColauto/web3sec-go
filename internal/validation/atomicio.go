package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ReadJson is Python's read_json: parse a UTF-8 JSON file into an ordered
// Value (key order and the int/float distinction preserved).
func ReadJson(path string) (Value, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return VNull(), err
	}
	return ParseOrdered(raw)
}

// WriteJson is Python's write_json: validate when schemaName is set,
// create parent dirs, dump with indent=2 / ensure_ascii=False (raw
// UTF-8) plus a trailing newline to a tmp file, then atomically rename.
// The tmp file keeps the Python-era shape (foo.json -> foo.json.tmp-<rand>,
// foo -> foo.tmp-<rand>) so a crash leftover is still recognisable, with a
// per-writer suffix so two writers on the same path cannot interleave into
// one temp file and lose a record. The content is fsynced before the rename:
// without it the rename can land while the bytes are still in the page cache,
// which is exactly the crash window the tmp+rename dance exists to close. An
// existing file keeps its mode (a 0600 state file must not become 0644 on the
// next write).
func WriteJson(path string, data Value, schemaName string) error {
	if schemaName != "" {
		if err := Validate(data, schemaName, 1); err != nil {
			return err
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	fh, err := os.CreateTemp(dir, filepath.Base(tmpName(path))+"-*")
	if err != nil {
		return err
	}
	tmp := fh.Name()
	if _, err := fh.WriteString(DumpIndented(data) + "\n"); err != nil {
		fh.Close()
		os.Remove(tmp)
		return err
	}
	if err := fh.Chmod(mode); err != nil {
		fh.Close()
		os.Remove(tmp)
		return err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		os.Remove(tmp)
		return err
	}
	if err := fh.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// tmpName is the Path.with_suffix(suffix + ".tmp") equivalent.
func tmpName(path string) string {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext == "" || ext == "." {
		return filepath.Join(dir, base+".tmp")
	}
	return filepath.Join(dir, base[:len(base)-len(ext)]+ext+".tmp")
}

// AppendJsonl appends one line + "\n" (raw UTF-8; used by the non-ASCII
// logs: learnings, planner_hints, benchmarks, waivers).
func AppendJsonl(path, line string) error {
	return appendJsonlChecked(path, line, true)
}

// AppendJsonlAscii is the events/costs log writer: the JSONL split policy
// requires those files to be pure ASCII (framing/hash determinism), so a
// non-ASCII line is rejected before anything is written (Go-native
// hardening over the Python port, which trusted its callers).
func AppendJsonlAscii(path, line string) error {
	return appendJsonlChecked(path, line, false)
}

func appendJsonlChecked(path, line string, allowNonASCII bool) error {
	if !allowNonASCII && !isASCII(line) {
		return fmt.Errorf("validation: non-ASCII line rejected for %s (ASCII-only log)", filepath.Base(path))
	}
	if err := checkJsonlTail(path); err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	if _, err := fmt.Fprint(fh, line+"\n"); err != nil {
		return err
	}
	// The append is the record: fsync so a reported success survives a crash
	// (the hash chain is repaired from this file, so a lost tail is a lost
	// event that the caller believes it wrote).
	return fh.Sync()
}

// checkJsonlTail refuses to append behind a record that was never terminated.
// An append-only JSONL log is only readable while every record ends in "\n":
// if the trailing newline is missing (torn write, external edit), the next
// append concatenates two records into one unparseable line — the write
// reports success, the log is corrupt, and every later reader fails on the
// merged line with "data after top-level value". Refusing here turns that
// silent corruption into a loud error at the write that would have caused it.
// The check is one stat + (for non-empty files) one byte, so the hot append
// path stays cheap.
func checkJsonlTail(path string) error {
	fh, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // first append to this log
		}
		return err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return nil
	}
	if _, err := fh.Seek(-1, io.SeekEnd); err != nil {
		return err
	}
	var last [1]byte
	if _, err := io.ReadFull(fh, last[:]); err != nil {
		return err
	}
	if last[0] != '\n' {
		return fmt.Errorf("validation: refusing to append to %s: "+
			"the file does not end in a newline (torn write or external "+
			"edit) — its last record is incomplete and appending would "+
			"merge two records into one unreadable line; restore the file "+
			"from a snapshot or truncate the partial line, then re-run",
			path)
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Sha256Hex is hashlib.sha256(data).hexdigest().
func Sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Sha256File is sha256_path: stream the file in 64KiB chunks.
func Sha256File(path string) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	buf := make([]byte, 1<<16)
	for {
		n, rerr := fh.Read(buf)
		h.Write(buf[:n])
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
