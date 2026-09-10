package state

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

// nowIso is Python's now_iso: UTC with exactly 6-digit microseconds and a
// +00:00 offset (never "Z"). Microsecond precision keeps same-second
// findings in true creation order (the (created_at, finding_id) sort
// contract would otherwise tie-break on random UUIDs).
// Golden-suite hook: when WEBV2_NOW is set (the golden recipe pins the clock
// so a replay emits byte-identical artifacts), it is returned verbatim.
// Unset: real clock, no behavior change.
func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}

// NowIso is now_iso, exported for the modules that stamp their own reports
// (doctor's repaired_at, history mining's generated_at).
func NowIso() string { return nowIso() }

// newId is Python's new_id: prefix + "-" + the first n hex chars of a
// fresh uuid4 (version and variant bits set, as uuid.uuid4 does).
// uuidPinCounter advances once per pinned id; it is the deterministic
// stream position shared with the Python twin's new_id (same seed ->
// same bytes, so campaign/artifact ids match across implementations).
var uuidPinCounter int

// Golden-suite hook: when WEBV2_UUID is set, the "uuid4" is
// sha256("<seed>:<counter>")[:16] with the version/variant bits forced —
// the exact same derivation the Python twin performs, so the ids are
// reproducible and cross-implementation identical. Unset: crypto/rand.
func newId(prefix string, n int) string {
	b := make([]byte, 16)
	if seed := os.Getenv("WEBV2_UUID"); seed != "" {
		h := sha256.Sum256([]byte(seed + ":" + strconv.Itoa(uuidPinCounter)))
		copy(b, h[:16])
		uuidPinCounter++
	} else if _, err := rand.Read(b); err != nil {
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

// ResetIDStream rewinds the pinned uuid stream to its first draw. The golden
// recipe replays each scenario from the same stream position, so it must be
// able to rewind; production code never calls it.
func ResetIDStream() { uuidPinCounter = 0 }

// NewID is the exported alias of new_id for call sites outside this package
// (pricing.set_price mints PRC- ids, risk.mint_impact_evidence mints EV-
// ids). Additive only: same WEBV2_UUID pin stream, same derivation.
func NewID(prefix string, n int) string { return newId(prefix, n) }
