# Plan: AGENTATK Competitive Evolution (Synthesizing Agent-Opfor Strengths)

## Summary
A comprehensive architectural upgrade to **AGENTATK** synthesizing the best design patterns from `KeyValueSoftwareSystems/agent-opfor` while retaining and enhancing our unique strengths (autonomous AST codebase recon, DAG threat modeling, deterministic multi-layer verification, standalone PoC generation, and unified git patch remediation).

## User Story
As an AI security researcher or DevSecOps engineer,
I want an autonomous security scanner that discovers all agent attack surfaces across domains (IoT, Finance, DevOps, Healthcare, MCP), simulates multi-turn adaptive attacks using realistic adversarial personas and strategies, and delivers verifiable PoCs, SARIF reports, and auto-remediation patches,
So that I can comprehensively audit and secure AI agent systems against OWASP LLM and MITRE ATLAS vulnerabilities before production deployment.

## Metadata
- **Complexity**: Large (Cross-cutting architecture enhancement across 5 core modules)
- **Source**: `https://github.com/KeyValueSoftwareSystems/agent-opfor` vs `agentatk`
- **Estimated Files Affected**: 7 files

---

## 1. Key Enhancements Planned

1. **Multi-Domain Action & Sink Lexicon** ([`agentatk/recon_tools.py`](file:///c:/Users/agrpr/OneDrive/Desktop/CODES/securitycheckeragent/agentatk/recon_tools.py)):
   - **Financial/Trading**: `order`, `trade`, `buy`, `sell`, `allocate`, `rebalance`, `transfer`, `liquidate`, `invest`, `place_`
   - **Cloud/DevOps**: `deploy`, `provision`, `exec`, `terminate`, `scale`, `restart`, `destroy`, `push`, `publish`
   - **Database/Storage**: `drop`, `truncate`, `delete`, `query`, `execute_sql`, `update`, `insert`, `dump`
   - **Medical/Healthcare**: `dose`, `dispense`, `prescribe`, `infuse`, `override`, `administer`
   - **OpenAPI / MCP Schemas**: Parse OpenAPI JSON/YAML specs and MCP tool definitions.

2. **Multi-Domain Risk Budgeting** ([`agentatk/attacks/risk_budget.py`](file:///c:/Users/agrpr/OneDrive/Desktop/CODES/securitycheckeragent/agentatk/attacks/risk_budget.py)):
   - Classify financial trading, medical dosage, and cloud deletion operations as Tier 0 Critical.

3. **6 Adversarial Personas & Strategy Mutators** ([`agentatk/attacks/mutators.py`](file:///c:/Users/agrpr/OneDrive/Desktop/CODES/securitycheckeragent/agentatk/attacks/mutators.py)):
   - **Personas**: `Security Auditor`, `Frustrated Developer`, `Naive User`, `Fellow AI System`, `Entitled Customer`, `Compliance Inspector`.
   - **Strategies**: `Authority Escalation`, `Context Overload`, `Encoding/Base64 Obfuscation`, `Fictional Simulation`, `Workflow Smuggling`, `Instruction Override`.

4. **Adaptive Multi-Turn Probing** ([`agentatk/attacker.py`](file:///c:/Users/agrpr/OneDrive/Desktop/CODES/securitycheckeragent/agentatk/attacker.py)):
   - Stateful multi-attempt escalation applying targeted personas and strategies on successive probe attempts.

5. **Enterprise SARIF 2.1.0 & HTML Reporting** ([`agentatk/reporting/sarif.py`](file:///c:/Users/agrpr/OneDrive/Desktop/CODES/securitycheckeragent/agentatk/reporting/sarif.py)):
   - Standard SARIF output for GitHub Security tab / CI integration.

---

## 2. Step-by-Step Tasks

### Task 1: Multi-Domain AST & Schema Recon (`agentatk/recon_tools.py`)
- Expand regex and AST keyword tokenizers with Financial, Cloud, Database, Medical, and OpenAPI schema parsers.

### Task 2: Multi-Domain Risk Budgeting (`agentatk/attacks/risk_budget.py`)
- Tier all critical multi-domain action sinks into Tier 0 (Critical), Tier 1 (Moderate), Tier 2 (Low).

### Task 3: 6-Persona & Strategy Mutator Engine (`agentatk/attacks/mutators.py`)
- Build the adversarial prompt mutator library with 6 archetypal personas and 6 attack strategies.

### Task 4: Adaptive Multi-Turn Driver (`agentatk/attacker.py`)
- Wire the mutator engine into `_run_probing_loop` to dynamically escalate attack strategies across attempts.

### Task 5: SARIF 2.1.0 Exporter (`agentatk/reporting/sarif.py`)
- Implement full SARIF 2.1.0 export with OWASP Top 10 and MITRE ATLAS taxonomy.

---

## 3. Validation Plan
- `pytest tests` (Verify zero regressions).
- `python -m agentatk.cli scan ./targets/ai-hedge-fund` (Verify broker & trade sinks are discovered).
- `python -m agentatk.cli scan ./targets/home-llm` (Verify IoT security unchanged).
