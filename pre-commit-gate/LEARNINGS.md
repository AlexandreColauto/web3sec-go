# Lessons (self-refinement ledger)

One lesson per line. Format: `- [id] (kind) lesson`. These are durable, evidence-backed
corrections and tactics; more specific lessons take precedence over broader ones.

- [20260919-alao] (tactic) Isolate pre-commit gate testing with PATH-prepended configurable fake binaries plus fresh fixture repos per language scenario.
- [20260919-fc20] (correction) Reset git state and match fake diagnostic file paths to actually-staged files to avoid cross-test contamination false results.
- [20260919-71zb] (correction) Verify raw tool exit semantics directly (gofmt -l exits 0, eslint warn exits 0, tsc strictness) before attributing pass/fail to wrapper logic.
- [20260919-gafo] (tactic) Re-verify claimed fixes with independent adversarial fixtures instead of trusting the author's passing suite.
- [20260919-6ngk] (tactic) Probe tool/LLM JSON outputs for absent, null, and wrong-type fields to expose fail-open and traceback crashes.
- [20260919-fqdp] (tactic) Run hook tests in isolated scratch git repos with absolute paths and remove the scratch dir afterward.
- [20260919-nlxe] (correction) Avoid patching generated fixtures with nested inline string-replace; write files directly to prevent escaping and duplicate-key bugs.
- [20260919-1vtw] (tactic) Run the author's regression suite plus an independent adversarial fixture suite with real tools in throwaway git repos.
- [20260919-20i8] (tactic) Create isolated scratch dirs for verification artifacts and delete them afterward to restore a clean workspace.
- [20260919-7did] (tactic) Never trust piped exit codes when verifying hooks; capture status separately or pipes mask block-vs-allow.
- [20260919-sztb] (tactic) Use isolated temp repos driven by a Python subprocess driver instead of stateful shell fixtures to avoid pollution and HEAD-less false results.
- [20260919-v8pv] (environment) Shim external tools via PATH/PYTHONPATH wrappers and verify binary identity (e.g. radon needs PYTHONPATH, tsc/eslint may be imposters).
- [20260920-vgsf] (correction) When fixing load-time config validation, sweep all sibling keys not just the reported one to prevent repeated drift regressions
- [20260920-eutq] (tactic) Prefer a Python driver over bash for building fixture repos to avoid fragile shell edits, duplicate TOML sections, and staging bugs
- [20260920-jnzn] (tactic) Execute and parse documentation copy-paste examples as real configs to catch invalid syntax like multi-line inline TOML tables
- [20260920-towo] (correction) When fixing config-key validation, sweep all sibling keys and types instead of patching only the reported case.
- [20260920-3zq8] (correction) Validate numeric/threshold config at load time so downstream tool rejection cannot silently downgrade to pass.
- [20260920-ssaz] (tactic) Test doc config samples by extracting all fenced blocks, not only ```toml-tagged ones, or invalid examples escape the suite.
- [20260920-sr43] (correction) Crash-path tests that disable all sibling checks miss interaction bugs; always test crashed check alongside a healthy sibling.
- [20260920-5ppc] (tactic) Verify exit-code/stderr classification empirically with clean git fixtures and PATH-isolated stub binaries emitting controlled stdout/stderr/exit/signal.
- [20260920-kjg7] (environment) Real linters emit stderr noise on success-with-findings (tsc exit 2, eslint exit 1) and eslint flat config ignores TS without explicit files glob, so neither signals a crash.
- [20260920-hvsd] (correction) Bash tool calls are stateless: re-export PATH and variables on every invocation.
- [20260920-t2p0] (tactic) Avoid interactive git hangs in automation with GIT_EDITOR=true and git commit -m.
- [20260920-d0c2] (correction) When stubbing executables, keep PATH stubs current because PATH resolution outranks repo-local copies.
- [20260920-af1r] (correction) A crash/error classification is only as good as its consumer: fixing the detector (e.g. a crash_suspect() helper) without auditing every call site and branch that consumes its verdict leaves the same silent pass (round 12→13→14: detector fixed, but the result was routed to a "notes/skipped" list and later a sibling-check branch, so the gate still exited 0). After any new classification, grep for every reader of that field and test each path with a healthy sibling present.
