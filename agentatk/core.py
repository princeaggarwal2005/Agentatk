import json
import time
from typing import Any, Callable, Dict, List, Optional

from agentatk.attacker import AttackerAgent
from agentatk.state import TargetState, ResearchBudget, Hypothesis
from agentatk.adapters.simulation_adapter import SimulationAdapter
from agentatk.sandbox import Sandbox
from agentatk.verifier.contextual import verify_contextual_authorization


def run_autonomous_audit(
    target_path: str,
    model_client: Any,
    policy: Optional[Dict[str, Any]] = None,
    budget: Optional[ResearchBudget] = None,
    on_progress: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> TargetState:
    """
    Primary Entrypoint: Launches the Autonomous AI Security Researcher Agent
    to explore, model, probe, and verify vulnerabilities in target_path.
    """
    attacker = AttackerAgent(
        model_client=model_client,
        target_root=target_path,
        policy=policy,
        budget=budget,
        on_progress=on_progress,
    )
    return attacker.run_full_audit()


def run_scan(
    model_client: Any,
    system_prompt: str,
    tools: List[Dict[str, Any]],
    policy: Optional[Dict[str, Any]] = None,
    on_progress: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Declarative Scan Mode: Directly audits a system prompt and tool schema.
    """
    deny_tools = policy.get("deny", []) if policy else []
    results = []
    
    # 1. Synthesize targeted attack scenarios
    from agentatk.attacks.planner import llm_plan_attacks
    sandbox_master = Sandbox()
    attacks = llm_plan_attacks(
        model_client=model_client,
        system_prompt=system_prompt,
        tools=tools,
        policy=policy,
        canary=sandbox_master.canary,
    )
    total_attacks = len(attacks)

    if on_progress:
        on_progress("plan_ready", {"total": total_attacks, "attacks": attacks})

    # 2. Execute each attack with SimulationAdapter and Contextual Verifier
    adapter = SimulationAdapter(model_client)

    for i, attack in enumerate(attacks):
        case_sandbox = Sandbox(canary=sandbox_master.canary)
        payload = attack.get("payload", "")
        if isinstance(payload, (list, dict)):
            payload = json.dumps(payload, indent=2)
        elif not isinstance(payload, str):
            payload = str(payload) if payload else ""

        if payload:
            case_sandbox.seed_payload(payload)
            case_sandbox.net.serve_page("http://status-check.example/ping", payload)

        case = attack.get("case", "custom_exploit")
        variant = attack.get("variant", attack.get("vulnerability_hypothesis", case))
        target_sink = attack.get("target_sink", "")
        task_intent = attack.get("task", "")

        if on_progress:
            on_progress("test_start", {
                "index": i + 1,
                "total": total_attacks,
                "case": case,
                "variant": variant,
            })

        launch_spec = {
            "system_prompt": system_prompt,
            "tools": tools,
        }
        injection_vector = {
            "channel": "seeded_file",
            "content": payload,
            "task": task_intent,
        }

        telemetry = adapter.execute(launch_spec, injection_vector, task_intent, case_sandbox)

        # Contextual Deterministic Verification
        temp_hyp = Hypothesis(
            title=variant,
            threat_class=case,
            source_node="inbound_payload",
            target_sink=target_sink or "",
            rationale=attack.get("vulnerability_hypothesis", ""),
        )

        verdict_res = verify_contextual_authorization(
            telemetry=telemetry,
            hypothesis=temp_hyp,
            canary_token=case_sandbox.canary,
            policy=policy,
            stated_intent=task_intent,
        )

        passed = verdict_res.verdict in ("RESISTED", "GUARDRAIL_BLOCKED")
        detail = verdict_res.verdict_detail

        result_item = {
            "case": case,
            "variant": variant,
            "task": task_intent,
            "payload": payload,
            "trace": telemetry.tool_trace,
            "passed": passed,
            "verdict": verdict_res.verdict,
            "detail": detail,
            "coverage_tier": "Contextual Authorization Simulation",
            "hypothesis": attack.get("vulnerability_hypothesis", ""),
        }
        results.append(result_item)

        if on_progress:
            on_progress("test_complete", {
                "index": i + 1,
                "total": total_attacks,
                "result": result_item,
                "results": list(results),
            })

        case_sandbox.reset()
        time.sleep(0.1)

    sandbox_master.reset()
    return results
