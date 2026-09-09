// concepts.go: the fuzzy concept fold, the guard-strength scale's tables and
// the sink/amplifier vocabularies — every list sorted or ordered exactly as
// structural_index.py declares it, because the artifact must be byte-stable.
package structidx

import "regexp"

// synonymFold is _SYNONYM_FOLD: hash/root/digest are ONE concept, so
// `prevStateRoot` folds onto `getPrevStateHash`.
var synonymFold = map[string]string{
	"root": "root", "hash": "root", "digest": "root",
	"addr": "addr", "address": "addr",
	"msg": "msg", "message": "msg",
	"tkn": "token", "token": "token",
	"id": "id", "identifier": "id",
	"period": "period", "seconds": "period",
	"idx": "index", "index": "index",
	"fn": "fn", "func": "fn",
}

// stopwords is _STOPWORDS, dropped AFTER folding.
var stopwords = map[string]bool{
	"mem": true, "ptr": true, "offset": true, "length": true, "len": true,
	"size": true, "i": true, "j": true, "k": true, "x": true,
	"y": true, "z": true, "tmp": true, "temp": true, "ret": true, "out": true,
	"in": true, "bytes": true, "get": true, "store": true,
	"set": true, "compute": true, "load": true, "check": true, "v0": true,
	"v1": true, "v2": true, "codec": true,
	"wrapper": true, "contract": true, "library": true, "this": true,
	"super": true, "uint256": true,
	"bytes32": true, "bool": true, "calldata": true, "memory": true,
	"internal": true,
}

// authzHints is _AUTHZ_HINTS: the modifiers that gate AUTHORIZATION.
var authzHints = []string{"owner", "onlyrole", "requiresauth", "auth",
	"admin", "governor", "keeper", "guardian", "pauser", "minter", "bridge"}

func isAuthzGuard(mod string) bool {
	lower := toLowerASCII(mod)
	for _, h := range authzHints {
		if containsASCII(lower, h) {
			return true
		}
	}
	return false
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

func containsASCII(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// sinkMethods is SINK_METHODS: labels that move value by construction.
var sinkMethods = map[string]bool{
	"transfer": true, "transferFrom": true, "mint": true, "burn": true,
	"withdraw": true, "deposit": true,
	"execute": true, "swap": true, "rescueToken": true, "donate": true,
	"addLiquidity": true, "removeLiquidity": true,
}

var reFlashLoanSink = regexp.MustCompile(`^flashLoan`)

// isSinkCall is _is_sink_call.
func isSinkCall(call string) bool {
	if len(call) >= 10 && call[:10] == "low-level." {
		return true
	}
	meth := call
	if i := lastIndexByte(call, '.'); i >= 0 {
		meth = call[i+1:]
	}
	if sinkMethods[meth] {
		return true
	}
	return reFlashLoanSink.MatchString(meth)
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// amplifierPatterns is AMPLIFIER_PATTERNS (case-insensitive).
var amplifierPatterns = []struct {
	sig string
	re  *regexp.Regexp
}{
	{"flash-loan", regexp.MustCompile(`(?i)(flashloan|ivault\.borrow|flash_borrow)`)},
	{"oracle", regexp.MustCompile(`(?i)(latestrounddata|getprice|consult|peek|pricefeed)`)},
	{"bridge", regexp.MustCompile(`(?i)bridge`)},
	{"cross-chain", regexp.MustCompile(`(?i)(relay|sendmessage|crosschain|domainseparator)`)},
}
