import argparse
import sys
import webbrowser
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from agentatk.attacker import AttackerAgent
from agentatk.model_client import ModelClient
from agentatk.attacks.risk_budget import categorize_sink_tier


def print_banner():
    banner = """
==========================================================================
              AGENTATK: AUTONOMOUS AI SECURITY RESEARCHER
     Dynamic Attack Surface Discovery, Hypothesis Engine & Verifiers
==========================================================================
"""
    print(banner)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Autonomous AI Agent Security Researcher & Vulnerability Verifier"
    )
    parser.add_argument("command", choices=["scan", "serve"], help="Command to run")
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to target agent repository or artifact",
    )
    parser.add_argument(
        "--ui",
        action="store_true",
        help="Launch the live web research visualizer dashboard",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to run the dashboard server on (default: 8080)",
    )

    args = parser.parse_args()

    if args.command == "serve":
        import socket
        import uvicorn
        from agentatk.server import app

        port = args.port
        # Check if port is available, otherwise find next open port
        def is_port_in_use(p):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                return s.connect_ex(('127.0.0.1', p)) == 0

        while is_port_in_use(port) and port < args.port + 20:
            print(f"[NOTE] Port {port} is already in use. Trying {port + 1}...")
            port += 1

        print(f"Starting AGENTATK Live Dashboard on http://localhost:{port} ...")
        import webbrowser
        webbrowser.open(f"http://localhost:{port}")
        uvicorn.run(app, host="0.0.0.0", port=port)
        return

    if args.command == "scan":
        target_path = Path(args.target).resolve()
        if not target_path.exists():
            print(f"[ERROR] Target path does not exist: {target_path}")
            sys.exit(1)

        print(f"[AUTONOMOUS RECON] Inspecting target codebase at: {target_path}\n")

        client = ModelClient()

        def cli_progress_logger(event_type: str, data: dict):
            if event_type == "phase_change":
                print(f"[{data.get('phase')}] {data.get('message')}\n")
            elif event_type == "recon_complete":
                frameworks = data.get("frameworks", []) or ["Generic / Custom Agent"]
                sources = data.get("sources", [])
                sinks = data.get("sinks", [])
                t0 = [s["name"] for s in sinks if categorize_sink_tier(s["name"])[2] == 0]
                t1 = [s["name"] for s in sinks if categorize_sink_tier(s["name"])[2] == 1]
                t2 = [s["name"] for s in sinks if categorize_sink_tier(s["name"])[2] == 2]

                print("[STATIC ANALYSIS] Attack Surface Reconnaissance:")
                print(f"   • Frameworks Detected    : {', '.join(frameworks)}")
                print(f"   • Files Analyzed         : {data.get('total_files', 0)}")
                print(f"   • Input Sources ({len(sources)})      : {', '.join(sources[:6])}")
                print(f"   • Action Sinks Discovered: {len(sinks)}")
                if t0:
                    print(f"     |-- 🔴 Tier 0 (Critical) : {', '.join(t0[:6])}")
                if t1:
                    print(f"     |-- 🟡 Tier 1 (Moderate) : {', '.join(t1[:6])}")
                if t2:
                    print(f"     +-- 🟢 Tier 2 (Low)      : {', '.join(t2[:6])}")
                print()
            elif event_type == "hypothesis_start":
                hyp = data.get("hypothesis", {})
                pri = hyp.get("priority", "P1")
                tier = hyp.get("sink_tier", "Tier 1")
                owasp = hyp.get("owasp_category", "")
                print(f"   [HYPOTHESIS {pri} | {tier}] {hyp.get('title')}")
                print(f"      | Standards    : {owasp} ({hyp.get('mitre_atlas_id', '')})")
                print(f"      | Flow Path    : {hyp.get('source_node')} --> {hyp.get('target_sink')}")
            elif event_type == "experiment_result":
                attempt = data.get("attempt")
                verdict = data.get("verdict")
                detail = data.get("detail")
                if verdict == "CONFIRMED_VULNERABLE":
                    print(f"      | Attempt {attempt}    : 🔴 VULNERABLE — {detail}")
                elif verdict == "RESISTED":
                    print(f"      | Attempt {attempt}    : 🟢 SECURE — {detail}")
                elif verdict == "GUARDRAIL_BLOCKED":
                    print(f"      | Attempt {attempt}    : 🟡 BLOCKED — {detail}")
                elif verdict == "HALLUCINATED_TARGET":
                    print(f"      | Attempt {attempt}    : ⚪ INVALID PARAMETER — {detail}")
                else:
                    print(f"      | Attempt {attempt}    : {verdict} — {detail}")
                print()

        attacker = AttackerAgent(
            model_client=client,
            target_root=str(target_path),
            on_progress=cli_progress_logger,
        )

        target_state = attacker.run_full_audit()

        total_exp = len(target_state.experiments)
        findings = target_state.findings
        vulnerable_count = len(findings)

        # Graph node classification
        source_nodes = [n for n in target_state.nodes if n.type == "source"]
        sink_nodes = [n for n in target_state.nodes if n.type == "sink"]

        # Coverage breakdown by tier
        tier_0_count = sum(1 for h in target_state.hypotheses if "Tier 0" in (h.sink_tier or ""))
        tier_1_count = sum(1 for h in target_state.hypotheses if "Tier 1" in (h.sink_tier or ""))
        tier_2_count = sum(1 for h in target_state.hypotheses if "Tier 2" in (h.sink_tier or ""))

        unique_tested_sinks = len(set(h.target_sink.lower() for h in target_state.hypotheses if h.status != "UNTESTED"))
        total_sinks_discovered = max(len(sink_nodes), len(target_state.sinks), len(attacker.extracted_tools), unique_tested_sinks)

        print("\n" + "=" * 74)
        print("AUDIT SCORECARD & SECURITY FINDINGS")
        print("=" * 74)
        print(f"  • Target Name           : {target_state.target_name}")
        print(f"  • Audit Methodology     : Static AST & Schema Recon + Dynamic Sandboxed Probing")
        print(f"  • Total Experiments Run : {total_exp} (Budget Allocated: {target_state.budget.max_total_experiments})")
        print(f"  • Discovered Nodes      : {len(target_state.nodes)} (Sources: {len(source_nodes)}, Sinks: {len(sink_nodes)})")
        print(f"  • Hypotheses Tested     : {len(target_state.hypotheses)} across {unique_tested_sinks}/{total_sinks_discovered} Sinks")
        print(f"  • Verified Findings     : {vulnerable_count}")

        print("\nSTATIC ATTACK SURFACE BREAKDOWN:")
        print(f"  • 🔴 Tier 0 (Critical Sinks) : {tier_0_count} (Physical safety / Financial assets / SQL execution)")
        print(f"  • 🟡 Tier 1 (Moderate Sinks) : {tier_1_count} (State modification / Queue operations / PII lookups)")
        print(f"  • 🟢 Tier 2 (Low Sinks)      : {tier_2_count} (Read-only data access / Status queries)")

        print("\nDYNAMIC EXPLOIT PROBING SUMMARY:")
        print(f"  • 🔴 Verified Exploits       : {vulnerable_count}")
        print(f"  • 🟢 Resisted Probes         : {len(target_state.hypotheses) - vulnerable_count}")

        if findings:
            print("\nCONFIRMED VULNERABILITIES:")
            for idx, f in enumerate(findings, 1):
                print(f"\n   [{idx}] [{f.severity}] {f.title}")
                print(f"       • Target Component : {f.target_component} ({f.sink_tier})")
                print(f"       • Standards        : {f.owasp_category} | {f.mitre_atlas_id}")
                print(f"       • Attack Path      : {f.attack_path}")
                print(f"       • Channel & Rubric : {f.injection_channel} (Rubric: {f.rubric_used})")
                print(f"       • Judge Reasoning  : {f.judge_reasoning}")
                if f.poc_script_path:
                    print(f"       • Standalone PoC   : {f.poc_script_path}")
                if f.patch_diff:
                    print(f"       • Remediation Patch: {f.remediation_patch}")
                    print(f"       • Impact           : {f.impact_summary}")
        else:
            print("\n🟢 All tested attack surfaces resisted adversarial probing. Zero vulnerabilities detected.")

        print("=" * 74 + "\n")

        if args.ui:
            import uvicorn
            from agentatk.server import app, SCAN_STATE

            hyp_map = {h.hypothesis_id: h for h in target_state.hypotheses}
            results_list = []
            for exp in target_state.experiments:
                h = hyp_map.get(exp.hypothesis_id)
                results_list.append({
                    "case": exp.hypothesis_id,
                    "variant": h.title if h else exp.verdict_detail,
                    "passed": exp.verdict != "CONFIRMED_VULNERABLE",
                    "verdict": exp.verdict,
                    "detail": exp.verdict_detail,
                    "owasp": exp.owasp_category,
                    "mitre": exp.mitre_atlas_id,
                    "channel": exp.injection_channel,
                    "rubric": exp.rubric_used,
                    "tier": exp.sink_tier,
                    "hypothesis": f"{h.threat_class}: {h.rationale}" if h else exp.verdict_detail,
                    "payload": exp.injection_vector.get("content", ""),
                    "trace": exp.tool_trace or [],
                    "justifications": exp.judge_justifications,
                })

            SCAN_STATE["target"] = target_state.target_name
            SCAN_STATE["graph"] = {
                "nodes": [n.model_dump() for n in target_state.nodes],
                "edges": [e.model_dump() for e in target_state.edges],
            }
            SCAN_STATE["results"] = results_list
            SCAN_STATE["completed_cases"] = len(results_list)
            SCAN_STATE["failed_cases"] = vulnerable_count
            SCAN_STATE["asr"] = round((vulnerable_count / len(results_list) * 100), 1) if results_list else 0.0
            SCAN_STATE["findings"] = [f.model_dump() for f in target_state.findings]
            SCAN_STATE["status"] = "completed"
            SCAN_STATE["current_activity"] = f"Audit Complete: {len(results_list)} paths tested, {vulnerable_count} vulnerabilities verified."

            print("Launching live dashboard at http://localhost:8080 ...")
            webbrowser.open("http://localhost:8080")
            uvicorn.run(app, host="0.0.0.0", port=8080)

        sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
