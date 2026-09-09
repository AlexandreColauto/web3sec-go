# Prompts — v2 stage pack

The legacy pack (`prompts_legacy/01–30`) stays intact and mapped. This pack
adds the v2 subsystems the deterministic control plane expects. Stages are
executed through `adapter.build_context(campaign, stage)`, which bundles the
bounded context each stage needs — the orchestrator decides when.

## v2 stage map

| Stage | File | Subsystem | Feeds |
|---|---|---|---|
| 31 | history_and_audit_mining | Learning / E-trajectory | planner, bounty policy exclusions |
| 32 | findings_state_discipline | all | the state machine contract every stage obeys |
| 33 | tiered_dedup | Candidate Intelligence | tier-2/3 signatures |
| 34 | risk_calibration | Verification / gates | honest inputs to the 3-pass risk |
| 35 | exploit_chaining | Exploit Synthesis | capability graph, chains |
| 36 | sandbox_isolation | Verification | execution discipline, E4+ admissibility |
| 37 | protocol_knowledge_graph | Protocol Intelligence | protocol_model.json, INV registry |
| 38 | campaign_planning | Campaign Planning | campaign_plan.json, work queue |
| 39 | trajectory_dispatch | Discovery | hypotheses from 7 orthogonal trajectories |
| 40 | deployment_vs_source | Recon / G-trajectory | deployment pins, drift report |
| 41 | tiered_reproduction | Verification | T0–T4 attempts, fresh-context retries |
| 42 | learning_memory_reflection | Learning | memory queue, detectors, benchmarks |
| 43 | report_and_submission | Reporting | report views, submission packages |
| 44 | maximal_exploitation | Exploit Synthesis | variant ladder (base→amplified→maximal) per CONFIRMED finding |
| 45 | independent_verification | Verification | E6 + unanchored maximal-variant search (run-1-corrected IV brief) |
| 46 | mainnet_fork_poc | Verification | the LATEST required step: every CONFIRMED finding's PoC proven on the pinned mainnet fork (fork-runner E5), then immunization basis |
| 50 | adversarial_simulation | Discovery (simulation mode) | simulation_directive + the playbook's simulation block (accompanies the proposer system prompt for adversarial-simulation classes) |

## How stages map from the legacy pack

Legacy 01–30 are NOT replaced. The canonical mapping into the 8 subsystems:

- **Recon & Snapshot**: legacy 01 + Stage 40 → `snapshot.py` pins,
  `structural_index.py`
- **Protocol Intelligence**: legacy 02, 04 + Stage 37 →
  `protocol_model.json`, `invariants.py`, `economics.py`
- **Campaign Planning**: legacy 30 (planning part) + Stage 38 →
  `planner.py`, `coverage.py`
- **Discovery**: legacy 05–16 + Stage 39 (trajectories A/B/C/D/E/F/G)
- **Candidate Intelligence**: legacy 17 + Stage 33 → `dedup.py`
- **Verification**: legacy 18–23 + Stages 36, 41 → `reproduction.py`,
  `sandbox.py`
- **Exploit Synthesis**: legacy 24 + Stage 35 → `chain_engine.py`,
  `bounty_policy.py`, `risk.py`
- **Learning**: legacy 26–30 + Stages 31, 42 → `learning.py`,
  `history_mining.py`

## Operating rules (inherited from the legacy pack)

- Run stages sequentially; artifacts are the persistent state.
- A memory-recall result is evidence, not a verdict.
- Do not overwrite artifacts; append revisions.
- Do not let any model stage decide its own hypothesis is true — the
  deterministic gates decide.
