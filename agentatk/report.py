import json
import os
from datetime import datetime


def generate_report(target_name, results, output_dir="runs"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, timestamp)
    os.makedirs(run_dir, exist_ok=True)

    report_file = os.path.join(run_dir, "report.json")

    total = len(results)
    failures = [r for r in results if not r.get("passed", True) and not r.get("skipped", False)]
    passed = total - len(failures)

    tier = "In-Process (Live Agent Object)" if any(r.get("coverage_tier", "").startswith("In-Process") for r in results) else "Loop-Replay (Model & Prompt Simulation)"

    summary = {
        "target": target_name,
        "timestamp": timestamp,
        "total_cases": total,
        "passed": passed,
        "failed": len(failures),
        "asr_percentage": (len(failures) / total * 100) if total > 0 else 0.0,
        "coverage_tier": tier,
        "results": results,
    }


    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Console Output
    print("\n" + "=" * 65)
    print(f" SECURITY SCAN REPORT — {target_name}")
    print("=" * 65)
    print(f"Coverage Tier : {summary['coverage_tier']}")
    print(f"Audit Saved   : {report_file}")
    print("-" * 65)

    for r in results:
        case_name = r.get("case", "unknown").upper()
        variant_name = r.get("variant", "default")

        if r.get("skipped"):
            print(f"[ SKIPPED ] {case_name} ({variant_name}): No policy provided.")
            continue

        if not r.get("passed", True):
            status = "FAIL 🔴"
        else:
            status = "PASS 🟢"

        print(f"[{status}] {case_name} -> [{variant_name}]")

        for v in r.get("violations", []):
            print(f"   ↳ Scope Violation: Forbidden tool '{v.get('tool')}' called.")
        for h in r.get("hits", []):
            print(f"   ↳ Exfiltration Leak: Canary matched ({h.get('matched_as')}) in network request!")

    print("-" * 65)
    print(f"SUMMARY: {passed}/{total} Passed | ASR (Attack Success Rate): {summary['asr_percentage']:.1f}%")
    print("=" * 65 + "\n")

    return len(failures) > 0
