# Stage 36 — Sandbox Isolation & Execution Discipline

You are executing LLM-generated artifacts. Treat every one of them as
hostile, including your own.

## The rule

```
LLM -> untrusted artifact -> policy check -> sandbox -> execution
     -> captured artifact (hashed, logged) -> LLM interpretation
```

The LLM never receives raw unrestricted host access. Every execution goes
through `sandbox.Sandbox(campaign, profile)` and produces an `EXEC-*`
record: command, environment, input hashes, exit status, output paths,
artifact hashes.

## Profiles

- `host-readonly` — no network, sandbox-tmp writes. Evidence ceiling: **E3**.
- `docker-networkless` — container, no network. Ceiling: **E5**.
- `docker-gvisor` — container on gVisor, networkless. Ceiling: **E5**.
- `vm-snapshot` — full VM, rolled back after run. Ceiling: **E5**.
- `fork-runner` — container + allow-listed fork RPC egress only. Ceiling: **E5+**.

Evidence at E4+ MUST reference an exec record from a container/VM profile.
The `findings.add_evidence` gate enforces this; there is no override.

## Policy tripwires (deny-by-default)

Network egress tools (`curl`, `wget`, `nc`), privilege escalation (`sudo`,
`eval`), destructive paths (`rm -rf /`), secret access (`~/.ssh`, `~/.aws`,
`.env`, `id_rsa`), external publishing (`git push`, `docker push`),
system writes (`/etc`).

A refusal is FINAL for that command. Rewriting the command to slip past the
policy is a violation, not a workaround — fix the intent, not the string.

## PoC environment requirements

- Foundry/forge runs execute under `docker-networkless` (or `fork-runner`
  when forking mainnet at the pinned block).
- The pinned snapshot root is mounted READ-ONLY; build outputs go to tmp.
- Environment tool versions are recorded per exec — a PoC that cannot state
  its forge/solc versions is not reproducible evidence.
- Failed runs are recorded too; failure records feed fresh-context retries
  (Stage 23 / reproduction.py), which is the point.

## Operator duties (human, not agent)

- keep docker/gVisor updated; never give the sandbox credentials
- review EXEC records with `policy_verdict.allowed = false`
- remember: the sandbox is a safety net, not a security boundary against a
  determined adversary — do not run bounties on a machine that holds keys
