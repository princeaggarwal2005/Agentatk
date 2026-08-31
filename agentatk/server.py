import json
import os
import traceback
from dotenv import load_dotenv
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import time
from agentatk.core import run_autonomous_audit
from agentatk.model_client import ModelClient

load_dotenv()

app = FastAPI(title="AGENTATK: Autonomous AI Security Researcher API")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCAN_STATE = {
    "status": "idle",
    "target": "Awaiting scan...",
    "current_activity": "Ready to scan target agent.",
    "graph": {"nodes": [], "edges": []},
    "results": [],
    "total_cases": 0,
    "completed_cases": 0,
    "failed_cases": 0,
    "asr": 0.0,
    "findings": [],
    "error": None,
}


class ScanRequest(BaseModel):
    target_path: str = "./targets/home-llm"


def execute_background_scan(target_path: str):
    SCAN_STATE["status"] = "running"
    SCAN_STATE["results"] = []
    SCAN_STATE["findings"] = []
    SCAN_STATE["total_cases"] = 0
    SCAN_STATE["completed_cases"] = 0
    SCAN_STATE["failed_cases"] = 0
    SCAN_STATE["asr"] = 0.0
    SCAN_STATE["error"] = None
    SCAN_STATE["current_activity"] = f"Reconnaissance: discovering tools and prompts at {target_path}..."

    try:
        client = ModelClient()

        def handle_progress(event_type: str, data: dict):
            if event_type == "phase_change":
                SCAN_STATE["current_activity"] = f"[{data['phase']}] {data.get('message', '')}"
            elif event_type == "plan_ready":
                SCAN_STATE["total_cases"] = data.get("total", 0)
                if data.get("graph"):
                    SCAN_STATE["graph"] = data.get("graph")
                
                # Pre-populate full queue of discovered tests so user sees the complete plan upfront
                hyps = data.get("hypotheses", [])
                initial_results = []
                for h in hyps:
                    initial_results.append({
                        "case": h.get("hypothesis_id", ""),
                        "variant": h.get("title", ""),
                        "status": "queued",
                        "passed": None,
                        "verdict": "QUEUED",
                        "detail": h.get("rationale", ""),
                        "owasp": h.get("owasp_category", "OWASP-LLM01"),
                        "mitre": h.get("mitre_atlas_id", "AML.T0051"),
                        "channel": h.get("source_node", "direct_user_turn"),
                        "tier": h.get("sink_tier", "Tier 1"),
                        "hypothesis": f"{h.get('threat_class', '')}: {h.get('rationale', '')}",
                        "payload": "",
                        "trace": [],
                        "justifications": [],
                    })
                SCAN_STATE["results"] = initial_results
                SCAN_STATE["current_activity"] = f"📋 Discovered {len(initial_results)} attack paths. Starting sequential verification..."
            elif event_type == "hypothesis_start":
                hyp = data.get("hypothesis", {})
                hyp_id = hyp.get("hypothesis_id", "")
                SCAN_STATE["current_activity"] = f"🎯 Testing [{hyp_id}]: {hyp.get('title', '')} ({hyp.get('sink_tier', 'Tier 1')})"
                for r in SCAN_STATE["results"]:
                    if r.get("case") == hyp_id:
                        r["status"] = "testing"
                        r["verdict"] = "TESTING..."
            elif event_type == "experiment_result":
                exp = data
                hyp_id = exp.get("hypothesis_id", "")
                verdict = exp.get("verdict", "")
                is_vulnerable = verdict == "CONFIRMED_VULNERABLE"
                
                found = False
                for r in SCAN_STATE["results"]:
                    if r.get("case") == hyp_id:
                        r["status"] = "tested"
                        r["passed"] = not is_vulnerable
                        r["verdict"] = verdict
                        r["detail"] = exp.get("verdict_detail") or exp.get("detail", "")
                        r["payload"] = exp.get("injection_vector", {}).get("content", "") if isinstance(exp.get("injection_vector"), dict) else ""
                        r["trace"] = exp.get("tool_trace") or exp.get("telemetry", {}).get("tool_trace", [])
                        r["justifications"] = exp.get("judge_justifications", [])
                        found = True
                        break
                if not found:
                    SCAN_STATE["results"].append({
                        "case": hyp_id,
                        "variant": exp.get("detail", ""),
                        "status": "tested",
                        "passed": not is_vulnerable,
                        "verdict": verdict,
                        "detail": exp.get("verdict_detail") or exp.get("detail", ""),
                        "owasp": exp.get("owasp_category", "OWASP-LLM01"),
                        "mitre": exp.get("mitre_atlas_id", "AML.T0051"),
                        "channel": exp.get("injection_channel", "direct_user_turn"),
                        "tier": exp.get("sink_tier", "Tier 1"),
                        "hypothesis": exp.get("detail", ""),
                        "payload": exp.get("injection_vector", {}).get("content", "") if isinstance(exp.get("injection_vector"), dict) else "",
                        "trace": exp.get("tool_trace") or exp.get("telemetry", {}).get("tool_trace", []),
                        "justifications": exp.get("judge_justifications", []),
                    })
                
                tested_cases = [r for r in SCAN_STATE["results"] if r.get("status") == "tested"]
                SCAN_STATE["completed_cases"] = len(tested_cases)
                failed_count = sum(1 for r in tested_cases if r.get("passed") is False)
                SCAN_STATE["failed_cases"] = failed_count
                total = len(tested_cases)
                SCAN_STATE["asr"] = round((failed_count / total * 100), 1) if total > 0 else 0.0

        target_state = run_autonomous_audit(
            target_path=target_path,
            model_client=client,
            on_progress=handle_progress,
        )

        hyp_map = {h.hypothesis_id: h for h in target_state.hypotheses}
        results_list = []
        for exp in target_state.experiments:
            h = hyp_map.get(exp.hypothesis_id)
            results_list.append({
                "case": exp.hypothesis_id,
                "variant": h.title if h else exp.verdict_detail,
                "status": "tested",
                "passed": exp.verdict != "CONFIRMED_VULNERABLE",
                "verdict": exp.verdict,
                "detail": exp.verdict_detail,
                "owasp": exp.owasp_category,
                "mitre": exp.mitre_atlas_id,
                "channel": exp.injection_channel,
                "rubric": exp.rubric_used,
                "tier": exp.sink_tier,
                "hypothesis": f"{h.threat_class}: {h.rationale}" if h else exp.verdict_detail,
                "payload": exp.injection_vector.get("content", "") if isinstance(exp.injection_vector, dict) else "",
                "trace": exp.tool_trace or [],
                "justifications": exp.judge_justifications,
            })

        SCAN_STATE["target"] = target_state.target_name
        SCAN_STATE["graph"] = {
            "nodes": [n.model_dump() for n in target_state.nodes],
            "edges": [e.model_dump() for e in target_state.edges],
        }
        SCAN_STATE["results"] = results_list
        SCAN_STATE["total_cases"] = len(results_list)
        SCAN_STATE["completed_cases"] = len(results_list)
        failed_count = len(target_state.findings)
        SCAN_STATE["failed_cases"] = failed_count
        SCAN_STATE["asr"] = round((failed_count / len(results_list) * 100), 1) if results_list else 0.0
        SCAN_STATE["findings"] = [f.model_dump() for f in target_state.findings]
        SCAN_STATE["status"] = "completed"
        SCAN_STATE["current_activity"] = f"✅ Audit Complete: {len(results_list)} paths tested, {failed_count} vulnerabilities verified."

        # Persist audit scorecard and attack surface graph to Google Cloud Firestore (if configured)
        try:
            from agentatk.gcp_storage import gcp_store
            audit_id = f"audit_{target_state.target_name}_{int(time.time())}"
            gcp_store.save_audit_report(
                audit_id=audit_id,
                target_name=target_state.target_name,
                results=results_list,
                stats={
                    "total_cases": len(results_list),
                    "failed_cases": failed_count,
                    "asr": SCAN_STATE["asr"],
                },
                graph_data=SCAN_STATE["graph"],
            )
        except Exception:
            pass

    except Exception as e:
        SCAN_STATE["status"] = "error"
        SCAN_STATE["error"] = str(e)
        SCAN_STATE["current_activity"] = f"❌ Audit failed: {e}"
        traceback.print_exc()


@app.post("/api/scan")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(execute_background_scan, req.target_path)
    return {"status": "started", "target": req.target_path}


@app.get("/api/state")
def get_state():
    return SCAN_STATE


@app.get("/", response_class=FileResponse)
def serve_dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse("<h1>AGENTATK Console</h1><p>Dashboard static files not found.</p>")

