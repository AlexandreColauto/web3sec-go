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
// The tmp name mirrors Path.with_suffix(suffix + ".tmp"): foo.json ->
// foo.json.tmp, foo -> foo.tmp.
func WriteJson(path string, data Value, schemaName string) error {
	if schemaName != "" {
		if err := Validate(data, schemaName, 1); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := tmpName(path)
	body := DumpIndented(data) + "\n"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
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
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	if _, err := fmt.Fprint(fh, line+"\n"); err != nil {
		return err
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
