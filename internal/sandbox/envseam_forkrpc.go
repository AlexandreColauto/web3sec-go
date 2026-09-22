// envseam_forkrpc.go: the fork-runner preflight's fork_rpc row — the ONE
// place exec-time readiness probes FORK_RPC_URL.
//
// BuildContainerArgv injects FORK_RPC_URL into every fork-runner container
// (operator value, else the http://host.docker.internal:8545 default), and
// every framework diagnostic — the env doctor, evidence-floor-unreachable,
// campaign_requirements — keys on that variable. Until this seam existed,
// nothing on the exec path ever looked at it: a run could start with a dead
// auto-injected endpoint and preflight stayed silent, while a payload that
// read a DIFFERENT variable (the observed vm.envString("OPTIMISM_NODE"))
// ran fine. The row makes the truth audible without blocking either shape.
package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// forkRunnerProfile is the ONE profile whose containers receive
// FORK_RPC_URL (BuildContainerArgv's injection predicate) — named so the
// preflight row and the argv builder can never key on different profiles,
// and so new code stops repeating the literal (goconst).
const forkRunnerProfile = "fork-runner"

// forkRPCPayload is the minimal eth_chainId request every probe sends.
const forkRPCPayload = `{"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", ` +
	`"params": []}`

// forkRPCProbeTimeout bounds the preflight probe: long enough for a
// blackholed endpoint to fail, short enough not to stall every exec. It
// matches the env doctor's 5s ForkRPCProbe budget.
const forkRPCProbeTimeout = 5 * timeSecond

// ForkRPCRow is one preflight "fork_rpc" check row (status/detail/fix),
// shared by BOTH sandbox_preflight transcriptions — envseam_preflight.go's
// seam default and envgo/preflight.go's wired copy — so the two can never
// disagree about the fork RPC (the r45b lesson).
type ForkRPCRow struct {
	Status string
	Detail string
	Fix    *string
}

// forkRPCProbeFn is the fork RPC probe behind ForkRPCPreflight — a package
// var so tests can stub it (the dockerDaemonOK shape).
var forkRPCProbeFn = probeForkRPC

// SetForkRPCProbe installs the fork RPC probe (tests, the env seam); nil
// restores the real JSON-RPC probe.
func SetForkRPCProbe(f func(string) error) {
	if f == nil {
		f = probeForkRPC
	}
	forkRPCProbeFn = f
}

// ForkRPCPreflight computes the fork_rpc preflight row: nil unless the
// profile is the one profile that injects FORK_RPC_URL (fork-runner), else
// a WARN when the variable is unset or its endpoint does not answer, or an
// "ok" row when it does.
//
// WARN, never FAIL, on purpose: the probe runs from the HOST, while the
// container reaches the endpoint through the host-gateway alias — either
// hop can fail while the other works, so an unreachable fork RPC is loud
// advice, not a refusal. A payload that never reads FORK_RPC_URL (the
// OPTIMISM_NODE shape) must keep running; the evidence-floor gate, not
// preflight, owns refusing unreachable evidence.
func ForkRPCPreflight(profile *string) *ForkRPCRow {
	if profile == nil || *profile != forkRunnerProfile {
		return nil
	}
	raw := os.Getenv("FORK_RPC_URL")
	if raw == "" {
		return forkRPCUnsetRow()
	}
	if err := forkRPCProbeFn(raw); err != nil {
		return forkRPCDeadRow(raw, err)
	}
	return forkRPCOKRow(raw)
}

// forkRPCUnsetRow warns about the value BuildContainerArgv WILL inject when
// the operator exported nothing — naming the exact default so the warning
// and the record's container.env_keys cannot drift apart.
func forkRPCUnsetRow() *ForkRPCRow {
	fix := "export FORK_RPC_URL=<your fork RPC URL> (start a fork, e.g. " +
		"`anvil --fork-url <upstream>`) — `webv2 env doctor` probes it"
	return &ForkRPCRow{Status: "warn",
		Detail: "FORK_RPC_URL is not set — fork-runner injects the default " +
			"FORK_RPC_URL=http://host.docker.internal:8545 into the " +
			"container and nothing has verified that an endpoint answers " +
			"there; a payload that does not read FORK_RPC_URL is unaffected",
		Fix: &fix}
}

// forkRPCDeadRow reports a set-but-unreachable endpoint, naming both the
// host value and — via ContainerForkURL, the same rewrite the launcher
// applies — what the container will actually see.
func forkRPCDeadRow(raw string, probeErr error) *ForkRPCRow {
	fix := "start the fork endpoint FORK_RPC_URL names, or point " +
		"FORK_RPC_URL at a running one — `webv2 env doctor` probes it"
	return &ForkRPCRow{Status: "warn",
		Detail: "fork RPC unreachable: " + forkRPCSeenBy(raw) + " — " +
			forkRPCHead(probeErr.Error(), 160) +
			" (probed from the host; the container's hop through " +
			"host.docker.internal is checked by nothing)",
		Fix: &fix}
}

// forkRPCOKRow is the healthy case: the endpoint answered eth_chainId.
func forkRPCOKRow(raw string) *ForkRPCRow {
	return &ForkRPCRow{Status: "ok",
		Detail: forkRPCSeenBy(raw) + " answers eth_chainId"}
}

// forkRPCSeenBy names the endpoint, plus the container-facing rewrite when
// ContainerForkURL would rewrite it (loopback -> host.docker.internal).
func forkRPCSeenBy(raw string) string {
	line := "FORK_RPC_URL=" + raw
	if cu := ContainerForkURL(raw); cu != raw {
		line += " (the container sees " + cu + ")"
	}
	return line
}

// probeForkRPC is the real probe: one eth_chainId POST. Reachable means a
// 2xx reply carrying a JSON-RPC hex chain id — exactly what a fork payload
// needs; anything else returns an error naming what actually came back.
func probeForkRPC(rawURL string) error {
	client := &http.Client{Timeout: forkRPCProbeTimeout}
	resp, err := client.Post(rawURL, "application/json",
		strings.NewReader(forkRPCPayload))
	if err != nil {
		return errors.New(forkRPCHead(err.Error(), 160))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("reading the JSON-RPC reply: %s",
			forkRPCHead(err.Error(), 160))
	}
	return checkForkRPCReply(resp.StatusCode, body)
}

// checkForkRPCReply judges one reply: status first (an HTML error page is
// not JSON-RPC), then the JSON-RPC envelope, then the chain-id shape.
func checkForkRPCReply(status int, body []byte) error {
	if status < 200 || status > 299 {
		return fmt.Errorf("HTTP %d", status)
	}
	var reply struct {
		Result *string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		return fmt.Errorf("not a JSON-RPC 2.0 reply: %s",
			forkRPCHead(string(body), 80))
	}
	if reply.Error != nil {
		return fmt.Errorf("JSON-RPC error: %s",
			forkRPCHead(reply.Error.Message, 80))
	}
	var got string
	if reply.Result != nil {
		got = *reply.Result
	}
	if !forkRPCHexID(got) {
		return fmt.Errorf("unexpected eth_chainId result: %s",
			forkRPCHead(got, 80))
	}
	return nil
}

// forkRPCHexID is the eth_chainId shape: 0x followed by at least one hex
// digit (a bare "0x" or a non-hex tail is not a chain id).
func forkRPCHexID(s string) bool {
	if !strings.HasPrefix(s, "0x") || len(s) < 3 {
		return false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' ||
			c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// forkRPCHead bounds one detail fragment to n runes (the pyHead shape), so
// a hostile or absurd reply cannot flood the preflight output.
func forkRPCHead(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
