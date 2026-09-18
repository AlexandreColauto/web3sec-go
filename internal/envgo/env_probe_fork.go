// Fork RPC probe (fork_rpc_probe): a minimal JSON-RPC eth_chainId over the
// urlopen seam, with Python-shaped transport error text.
package envgo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"websec/internal/validation"
)

// httpReply is the minimal response shape fork_rpc_probe reads.
type httpReply struct {
	Body []byte
}

// realHTTPDo is urllib.request.urlopen(req, timeout=t) for the one JSON-RPC
// POST this module makes.
func realHTTPDo(url string, payload []byte, timeout time.Duration) (httpReply, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(string(payload)))
	if err != nil {
		return httpReply{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return httpReply{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return httpReply{}, err
	}
	return httpReply{Body: body}, nil
}

// ForkRPCProbe is fork_rpc_probe: a minimal JSON-RPC eth_chainId —
// reachability AND the chain id, so a campaign can compare it against its
// chain pin.
func ForkRPCProbe(url *string, timeout float64) validation.Value {
	var u *string
	if url != nil {
		u = url
	} else if v := os.Getenv("FORK_RPC_URL"); v != "" {
		u = &v
	}
	var urlV validation.Value = validation.VNull()
	if u != nil {
		urlV = validation.VStr(*u)
	}
	reachable, chainID, errText := false, (*int64)(nil), ""
	if u == nil {
		errText = "FORK_RPC_URL is not set"
		return rpcValue(urlV, reachable, chainID, errText)
	}
	payload := []byte(`{"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", ` +
		`"params": []}`)
	reply, err := httpDo(*u, payload, time.Duration(timeout*float64(time.Second)))
	if err != nil {
		errText = pyURLOpenError(err)
		return rpcValue(urlV, reachable, chainID, errText)
	}
	var body map[string]any
	if err := json.Unmarshal(reply.Body, &body); err != nil {
		errText = pyErrText("JSONDecodeError", err.Error())
		return rpcValue(urlV, reachable, chainID, errText)
	}
	result, ok := body["result"].(string)
	if ok && strings.HasPrefix(result, "0x") {
		var n int64
		if _, err := fmt.Sscanf(result, "0x%x", &n); err == nil {
			reachable = true
			chainID = &n
			return rpcValue(urlV, reachable, chainID, "")
		}
	}
	raw, _ := json.Marshal(body["result"])
	errText = pyErrText("", "unexpected result: "+pyHead(string(raw), 120))
	return rpcValue(urlV, reachable, chainID, errText)
}

func rpcValue(url validation.Value, reachable bool, chainID *int64,
	errText string) validation.Value {
	var chainV validation.Value = validation.VNull()
	if chainID != nil {
		chainV = validation.VInt(*chainID)
	}
	var errV validation.Value = validation.VNull()
	if errText != "" {
		errV = validation.VStr(errText)
	}
	return validation.VObj(
		validation.KV{K: "url", V: url},
		validation.KV{K: "reachable", V: validation.VBool(reachable)},
		validation.KV{K: "chain_id", V: chainV},
		validation.KV{K: "error", V: errV},
	)
}

// pyErrText renders `{type(exc).__name__}: {str(exc)[:120]}`.
func pyErrText(name, msg string) string {
	msg = pyHead(msg, 120)
	if name == "" {
		return msg
	}
	return name + ": " + msg
}

// pyURLOpenError maps a Go transport error onto Python's urllib text for
// the failures an operator actually hits (connection refused, DNS, timeout).
// Deviation (reported): Go's transport strings differ from Python's, so the
// Errno phrasing is reproduced for the common cases and the raw Go text is
// used otherwise.
func pyURLOpenError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "URLError: <urlopen error [Errno 111] Connection refused>"
	case strings.Contains(msg, "no such host"):
		return "URLError: <urlopen error [Errno -2] Name or service not known>"
	case strings.Contains(msg, "Client.Timeout") ||
		strings.Contains(msg, "context deadline exceeded"):
		return "URLError: <urlopen error [Errno 110] Connection timed out>"
	}
	return pyErrText("URLError", msg)
}

func pyHead(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}
