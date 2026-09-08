package state

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// nowIso is Python's now_iso: UTC with exactly 6-digit microseconds and a
// +00:00 offset (never "Z"). Microsecond precision keeps same-second
// findings in true creation order (the (created_at, finding_id) sort
// contract would otherwise tie-break on random UUIDs).
func nowIso() string {
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}

// newId is Python's new_id: prefix + "-" + the first n hex chars of a
// fresh uuid4 (version and variant bits set, as uuid.uuid4 does).
func newId(prefix string, n int) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("state: uuid4: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	if n > len(h) {
		n = len(h)
	}
	return prefix + "-" + h[:n]
}
