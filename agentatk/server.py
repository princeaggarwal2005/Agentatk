import json
import os
import traceback
from dotenv import load_dotenv
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from agentatk.core import run_autonomous_audit
from agentatk.model_client import ModelClient

load_dotenv()

app = FastAPI(title="AGENTATK: Autonomous AI Security Researcher API")

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


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AGENTATK — Autonomous AI Security Researcher</title>
  
  <!-- Typography: Inter for UI, JetBrains Mono exclusively for code/traces -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  
  <!-- Tailwind CSS & Vis-Network for Attack Surface Topology -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>

  <style>
    :root {
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    body {
      background-color: #07090e;
      color: #cbd5e1;
      font-family: var(--font-sans);
      letter-spacing: -0.011em;
    }
    .font-code {
      font-family: var(--font-mono) !important;
    }
    .glass-card {
      background: #0d121f;
      border: 1px solid #1e293b;
      box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5);
    }
    .pulse-dot {
      animation: pulse-ring 1.8s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }
    @keyframes pulse-ring {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.35; transform: scale(1.15); }
    }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #07090e; }
    ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #334155; }
    
    /* Result card status styles */
    .card-queued {
      background: #0b101d !important;
      border: 1px solid #1a2333 !important;
      border-left: 4px solid #475569 !important;
      opacity: 0.85;
    }
    .card-queued:hover {
      border-color: #334155 !important;
      opacity: 1;
    }
    .card-testing {
      background: rgba(8, 51, 68, 0.35) !important;
      border: 1px solid rgba(6, 182, 212, 0.5) !important;
      border-left: 5px solid #06b6d4 !important;
      box-shadow: 0 0 16px -2px rgba(6, 182, 212, 0.25);
    }
    .card-vulnerable {
      background: rgba(69, 10, 10, 0.35) !important;
      border: 1px solid rgba(153, 27, 27, 0.45) !important;
      border-left: 5px solid #ef4444 !important;
    }
    .card-vulnerable:hover {
      border-color: rgba(239, 68, 68, 0.8) !important;
      box-shadow: 0 0 16px -2px rgba(239, 68, 68, 0.25);
    }
    .card-secure {
      background: rgba(6, 44, 33, 0.3) !important;
      border: 1px solid rgba(6, 95, 70, 0.4) !important;
      border-left: 5px solid #10b981 !important;
    }
    .card-secure:hover {
      border-color: rgba(16, 185, 129, 0.7) !important;
      box-shadow: 0 0 14px -2px rgba(16, 185, 129, 0.15);
    }
    .card-selected {
      outline: 2px solid #38bdf8 !important;
      outline-offset: 1px;
    }
  </style>
</head>
<body class="p-4 md:p-6 max-w-[1720px] mx-auto min-h-screen flex flex-col space-y-5">

  <!-- TOP HEADER & AUDIT TRIGGER -->
  <header class="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 pb-4 border-b border-slate-800/80">
    <div class="flex items-center space-x-3.5">
      <div class="w-11 h-11 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-2xl shadow-lg shadow-cyan-600/25 border border-cyan-400/30">🛡️</div>
      <div>
        <div class="flex items-center space-x-2.5">
          <h1 class="text-xl font-black text-white tracking-tight">AGENTATK</h1>
          <span class="text-[10px] px-2 py-0.5 rounded font-code font-bold bg-cyan-950/90 text-cyan-300 border border-cyan-700/80 tracking-wider">AUTONOMOUS SECURITY RESEARCHER</span>
        </div>
        <p class="text-xs text-slate-400 mt-0.5 leading-relaxed">Dynamic Attack Surface Graphing, Multi-Judge Invariant Verification & Exploit Synthesis</p>
      </div>
    </div>

    <!-- Scan Path Input Controls -->
    <div class="flex items-center space-x-2.5 w-full lg:w-auto">
      <div class="relative w-full lg:w-96">
        <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500 text-xs font-code">📁</span>
        <input id="target-input" type="text" value="./targets/home-llm" 
               placeholder="Path to target agent directory..."
               class="pl-8 pr-3 py-2 bg-slate-950 border border-slate-700/90 rounded-lg text-xs font-code text-cyan-300 w-full focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-500 transition placeholder-slate-600" />
      </div>
      <button onclick="triggerScan()" id="scan-btn"
              class="px-5 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs rounded-lg shadow-lg shadow-cyan-600/30 transition flex items-center space-x-2 whitespace-nowrap active:scale-95">
        <span id="scan-btn-icon">▶</span>
        <span id="scan-btn-text">Run Security Audit</span>
      </button>
    </div>
  </header>

  <!-- LIVE ACTIVITY TELEMETRY BAR -->
  <div id="live-activity-bar" class="p-3.5 px-5 rounded-xl glass-card flex items-center justify-between border-l-[5px] border-cyan-500 text-xs shadow-md">
    <div class="flex items-center space-x-3 min-w-0">
      <span id="status-indicator" class="w-2.5 h-2.5 rounded-full bg-cyan-400 pulse-dot flex-shrink-0"></span>
      <span id="activity-text" class="font-medium text-slate-200 truncate">Ready to audit target agent.</span>
    </div>
    <span id="status-pill" class="px-3 py-1 text-[11px] font-code font-bold rounded-md bg-slate-800/90 text-slate-400 uppercase tracking-wider flex-shrink-0 ml-3">IDLE</span>
  </div>

  <!-- TOP STAT METRICS (LARGE NUMBERS) -->
  <section class="grid grid-cols-2 lg:grid-cols-4 gap-4">
    <div class="p-5 rounded-xl glass-card flex flex-col justify-between">
      <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-widest">Target Agent</div>
      <div id="stat-target" class="text-2xl lg:text-3xl font-extrabold text-white mt-2 truncate tracking-tight">—</div>
      <div id="stat-target-meta" class="text-[11px] font-code text-slate-500 mt-1">Autonomous Recon</div>
    </div>

    <div class="p-5 rounded-xl glass-card flex flex-col justify-between">
      <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-widest">Attack Success Rate (ASR)</div>
      <div id="stat-asr" class="text-3xl lg:text-4xl font-black text-slate-200 mt-2 tracking-tight">0.0%</div>
      <div class="text-[11px] font-code text-slate-500 mt-1">Confirmed Compromises / Evaluated</div>
    </div>

    <div class="p-5 rounded-xl glass-card flex flex-col justify-between">
      <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-widest">Verified Vulnerabilities</div>
      <div id="stat-failed" class="text-3xl lg:text-4xl font-black text-red-400 mt-2 tracking-tight">0</div>
      <div id="stat-failed-meta" class="text-[11px] font-code text-red-400/80 mt-1">0 Critical / 0 High</div>
    </div>

    <div class="p-5 rounded-xl glass-card flex flex-col justify-between">
      <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-widest">Attack Paths Progress</div>
      <div id="stat-total" class="text-3xl lg:text-4xl font-black text-cyan-300 mt-2 tracking-tight">0 / 0</div>
      <div id="stat-total-meta" class="text-[11px] font-code text-slate-500 mt-1">0 Planned Invariant Probes</div>
    </div>
  </section>

  <!-- MAIN 3-PANEL HIGH-DENSITY WORKSPACE -->
  <main class="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 items-stretch">
    
    <!-- PANEL 1 (CENTERPIECE, 5 COLS): INTERACTIVE ATTACK SURFACE GRAPH -->
    <div class="lg:col-span-5 rounded-xl glass-card p-5 flex flex-col space-y-3.5 relative">
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <div class="flex items-center space-x-2">
          <span class="text-sm font-bold text-white tracking-tight">⚡ Attack Surface Graph</span>
          <span id="node-count-badge" class="px-2 py-0.5 rounded text-[11px] font-code bg-slate-800/90 text-cyan-300 border border-slate-700">0 nodes</span>
        </div>
        <div class="flex items-center space-x-2">
          <button onclick="resetGraphView()" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-code text-slate-300 border border-slate-700 transition" title="Center & Fit Graph">Fit</button>
          <button id="physics-btn" onclick="toggleGraphPhysics()" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-code text-slate-300 border border-slate-700 transition" title="Toggle Live Physics">Physics: Off</button>
        </div>
      </div>

      <!-- Graph Legend Bar -->
      <div class="flex flex-wrap gap-2 text-[10px] font-medium text-slate-400 py-1 border-b border-slate-800/50">
        <span class="flex items-center space-x-1"><span class="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block"></span><span>Source</span></span>
        <span class="flex items-center space-x-1"><span class="w-2.5 h-2.5 rotate-45 bg-red-500 inline-block"></span><span>Tier 0 (Crit)</span></span>
        <span class="flex items-center space-x-1"><span class="w-2.5 h-2.5 rounded-sm bg-amber-500 inline-block"></span><span>Tier 1 (Mod)</span></span>
        <span class="flex items-center space-x-1"><span class="w-2.5 h-2.5 rounded-sm bg-slate-500 inline-block"></span><span>Tier 2 (Low)</span></span>
        <span class="flex items-center space-x-1"><span class="w-3 h-0.5 bg-red-500 inline-block"></span><span>Vulnerable</span></span>
        <span class="flex items-center space-x-1"><span class="w-3 h-0.5 bg-emerald-500 inline-block"></span><span>Secured</span></span>
      </div>

      <!-- Vis Network Graph Canvas Container -->
      <div class="relative flex-1 min-h-[580px] w-full rounded-lg bg-[#06080e] border border-slate-900 overflow-hidden">
        <div id="vis-graph-canvas" class="w-full h-full absolute inset-0"></div>
        <div id="graph-fallback-container" class="hidden p-4 overflow-y-auto max-h-[580px] space-y-3 text-xs"></div>
      </div>
      <div class="text-[11px] text-slate-500 flex justify-between items-center pt-1">
        <span>💡 Click any node to filter and inspect related attack paths.</span>
        <span id="graph-status-text" class="font-code text-[10px]">Stabilized</span>
      </div>
    </div>

    <!-- PANEL 2 (3.5 COLS): TESTED ATTACK PATHS FEED -->
    <div class="lg:col-span-3 rounded-xl glass-card p-5 flex flex-col space-y-3.5">
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <div class="flex items-center space-x-2">
          <span class="text-sm font-bold text-white tracking-tight">📋 Planned & Tested Paths</span>
          <span id="results-count-badge" class="px-2 py-0.5 rounded text-[11px] font-code bg-slate-800/90 text-slate-300 border border-slate-700">0</span>
        </div>
        <div class="flex space-x-1 text-[11px] font-code">
          <button onclick="setFeedFilter('all')" id="filter-all-btn" class="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700">All</button>
          <button onclick="setFeedFilter('vulnerable')" id="filter-vuln-btn" class="px-2 py-0.5 rounded bg-slate-800 text-slate-400 hover:text-red-300">Vuln</button>
          <button onclick="setFeedFilter('secure')" id="filter-sec-btn" class="px-2 py-0.5 rounded bg-slate-800 text-slate-400 hover:text-emerald-300">Safe</button>
        </div>
      </div>

      <div id="feed-container" class="space-y-3 flex-1 overflow-y-auto max-h-[620px] pr-1.5">
        <div class="text-slate-500 italic p-6 text-center text-xs">Awaiting scan execution...</div>
      </div>
    </div>

    <!-- PANEL 3 (3.5 COLS): FORENSIC ATTACK & REMEDIATION INSPECTOR -->
    <div class="lg:col-span-4 rounded-xl glass-card p-5 flex flex-col space-y-3.5">
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <span class="text-sm font-bold text-white tracking-tight">🔬 Forensic Inspector</span>
        <span id="inspector-badge" class="text-[11px] text-cyan-400 font-code px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/80">Select any test case</span>
      </div>

      <div id="inspector-container" class="flex-1 overflow-y-auto max-h-[620px] space-y-4 pr-1.5 text-xs">
        <div class="text-slate-500 italic p-8 text-center leading-relaxed">
          Select any test case from the feed or click a graph node to inspect the injected adversarial vector, invariant checks, execution trace, and automated remediation patch.
        </div>
      </div>
    </div>

  </main>

  <script>
    let currentResults = [];
    let currentFindings = [];
    let activeFilter = 'all';
    let selectedCaseIndex = null;
    let network = null;
    let networkNodes = null;
    let networkEdges = null;
    let physicsEnabled = false;

    async function triggerScan() {
      const inputEl = document.getElementById('target-input');
      const path = inputEl ? inputEl.value.trim() : "./targets/home-llm";
      if (!path) return;
      
      const btn = document.getElementById('scan-btn');
      if (btn) btn.disabled = true;
      const iconEl = document.getElementById('scan-btn-icon');
      if (iconEl) iconEl.innerText = "⏳";
      const textEl = document.getElementById('scan-btn-text');
      if (textEl) textEl.innerText = "Auditing Target...";

      try {
        const response = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target_path: path })
        });
        const resData = await response.json();
        console.log("Scan initiated:", resData);
        setTimeout(poll, 500);
      } catch (err) {
        console.error("Scan trigger error:", err);
        if (btn) btn.disabled = false;
        if (iconEl) iconEl.innerText = "▶";
        if (textEl) textEl.innerText = "Run Security Audit";
      }
    }

    async function poll() {
      try {
        const res = await fetch('/api/state');
        const data = await res.json();
        renderState(data);
        if (data.status === 'running') {
          setTimeout(poll, 750);
        } else {
          const btn = document.getElementById('scan-btn');
          if (btn) btn.disabled = false;
          const iconEl = document.getElementById('scan-btn-icon');
          if (iconEl) iconEl.innerText = "▶";
          const textEl = document.getElementById('scan-btn-text');
          if (textEl) textEl.innerText = "Run Security Audit";
        }
      } catch (err) {
        console.error("Polling error:", err);
      }
    }

    function renderState(data) {
      const statTarget = document.getElementById('stat-target');
      if (statTarget) statTarget.innerText = data.target || "—";

      const totalDiscovered = data.total_cases || (data.results ? data.results.length : 0);
      const completed = data.completed_cases !== undefined ? data.completed_cases : (data.results ? data.results.filter(r => r.status === 'tested').length : 0);
      const failed = data.failed_cases !== undefined ? data.failed_cases : (data.results ? data.results.filter(r => r.passed === false).length : 0);

      const statTotal = document.getElementById('stat-total');
      if (statTotal) statTotal.innerText = `${completed} / ${totalDiscovered}`;
      const statTotalMeta = document.getElementById('stat-total-meta');
      if (statTotalMeta) statTotalMeta.innerText = `${totalDiscovered} Discovered Attack Paths`;
      
      const statFailed = document.getElementById('stat-failed');
      if (statFailed) statFailed.innerText = failed;
      const statFailedMeta = document.getElementById('stat-failed-meta');
      if (statFailedMeta) statFailedMeta.innerText = failed > 0 ? `${failed} Confirmed Vulnerabilities` : '0 Vulnerabilities Found';

      const asr = completed > 0 ? ((failed / completed) * 100).toFixed(1) : "0.0";
      const asrEl = document.getElementById('stat-asr');
      if (asrEl) {
        asrEl.innerText = `${asr}%`;
        asrEl.className = failed > 0 ? "text-3xl lg:text-4xl font-black text-red-400 mt-2 tracking-tight" : "text-3xl lg:text-4xl font-black text-emerald-400 mt-2 tracking-tight";
      }

      const actText = document.getElementById('activity-text');
      if (actText) actText.innerText = data.current_activity || "Idle";

      const statusPill = document.getElementById('status-pill');
      const indicator = document.getElementById('status-indicator');

      if (data.status === 'running') {
        if (statusPill) {
          statusPill.className = "px-3 py-1 text-[11px] font-code font-bold rounded-md bg-cyan-950 text-cyan-300 border border-cyan-600";
          statusPill.innerText = "AUDITING";
        }
        if (indicator) indicator.className = "w-2.5 h-2.5 rounded-full bg-cyan-400 pulse-dot flex-shrink-0";
      } else if (data.status === 'completed') {
        if (statusPill) {
          statusPill.className = "px-3 py-1 text-[11px] font-code font-bold rounded-md bg-emerald-950 text-emerald-300 border border-emerald-600";
          statusPill.innerText = "COMPLETED";
        }
        if (indicator) indicator.className = "w-2.5 h-2.5 rounded-full bg-emerald-400 flex-shrink-0";
      } else if (data.status === 'error') {
        if (statusPill) {
          statusPill.className = "px-3 py-1 text-[11px] font-code font-bold rounded-md bg-red-950 text-red-300 border border-red-600";
          statusPill.innerText = "ERROR";
        }
        if (indicator) indicator.className = "w-2.5 h-2.5 rounded-full bg-red-400 flex-shrink-0";
      }

      currentResults = data.results || [];
      currentFindings = data.findings || [];

      renderAttackSurfaceGraph(data.graph, currentResults);
      renderFeed();
    }

    function renderAttackSurfaceGraph(graphData, results) {
      const rawNodes = graphData?.nodes || [];
      const rawEdges = graphData?.edges || [];
      const badge = document.getElementById('node-count-badge');
      if (badge) badge.innerText = `${rawNodes.length} nodes`;

      if (typeof vis === 'undefined') {
        renderGraphFallback(rawNodes);
        return;
      }

      const container = document.getElementById('vis-graph-canvas');
      if (!container) return;

      if (rawNodes.length === 0) {
        container.innerHTML = '<div class="flex items-center justify-center h-full text-slate-500 text-xs italic">Awaiting attack surface discovery...</div>';
        return;
      }

      const nodesArray = rawNodes.map(n => {
        const isSource = n.type === 'source';
        const tier = (n.metadata && n.metadata.tier) || 'Tier 1';
        const isTier0 = tier.includes('Tier 0') || tier.includes('Critical');
        const isTier1 = tier.includes('Tier 1') || tier.includes('Moderate');
        
        let shape = 'dot';
        let size = 16;
        let color = {
          background: '#083344',
          border: '#06b6d4',
          highlight: { background: '#0e7490', border: '#22d3ee' }
        };

        if (isSource) {
          shape = 'dot';
          size = 14;
        } else {
          if (isTier0) {
            shape = 'diamond';
            size = 20;
            color = {
              background: '#450a0a',
              border: '#ef4444',
              highlight: { background: '#7f1d1d', border: '#f87171' }
            };
          } else if (isTier1) {
            shape = 'square';
            size = 16;
            color = {
              background: '#451a03',
              border: '#f59e0b',
              highlight: { background: '#78350f', border: '#fbbf24' }
            };
          } else {
            shape = 'box';
            size = 14;
            color = {
              background: '#1e293b',
              border: '#64748b',
              highlight: { background: '#334155', border: '#94a3b8' }
            };
          }
        }

        return {
          id: n.id,
          label: n.label,
          shape: shape,
          size: size,
          color: color,
          font: { color: '#f1f5f9', size: 11, face: 'Inter, sans-serif' },
          borderWidth: 2,
          shadow: { enabled: true, color: 'rgba(0,0,0,0.6)', size: 6, x: 2, y: 2 },
          title: `${n.type.toUpperCase()}: ${n.label} (${isSource ? 'Ingress Source' : tier})`
        };
      });

      const edgesArray = rawEdges.map(e => {
        let edgeColor = '#334155';
        let width = 1.2;
        let dashes = true;

        if (e.status === 'confirmed' || e.status === 'tested_vulnerable') {
          edgeColor = '#ef4444';
          width = 2.5;
          dashes = false;
        } else if (e.status === 'tested' || e.status === 'blocked' || e.status === 'resisted') {
          edgeColor = '#10b981';
          width = 1.5;
          dashes = false;
        }

        return {
          id: `${e.source}->${e.target}`,
          from: e.source,
          to: e.target,
          color: { color: edgeColor, highlight: '#38bdf8', opacity: 0.9 },
          width: width,
          dashes: dashes,
          arrows: { to: { enabled: true, scaleFactor: 0.5 } }
        };
      });

      try {
        if (!network) {
          container.innerHTML = '';
          networkNodes = new vis.DataSet(nodesArray);
          networkEdges = new vis.DataSet(edgesArray);

          const options = {
            nodes: { scaling: { min: 12, max: 28 } },
            edges: { smooth: { type: 'continuous', roundness: 0.25 } },
            physics: {
              solver: 'forceAtlas2Based',
              forceAtlas2Based: {
                gravitationalConstant: -45,
                centralGravity: 0.015,
                springLength: 95,
                springConstant: 0.14,
                damping: 0.92
              },
              stabilization: { enabled: true, iterations: 140, updateInterval: 25 }
            },
            interaction: { hover: true, tooltipDelay: 80, zoomView: true, dragView: true }
          };

          network = new vis.Network(container, { nodes: networkNodes, edges: networkEdges }, options);

          network.once('stabilizationIterationsDone', function () {
            network.setOptions({ physics: { enabled: false } });
            physicsEnabled = false;
            const pBtn = document.getElementById('physics-btn');
            if (pBtn) pBtn.innerText = "Physics: Off";
            const gStat = document.getElementById('graph-status-text');
            if (gStat) gStat.innerText = "Stabilized & Pinned";
          });

          network.on('click', function (params) {
            if (params.nodes.length > 0) {
              const clickedId = params.nodes[0];
              onNodeClicked(clickedId);
            }
          });
        } else {
          networkNodes.clear();
          networkNodes.add(nodesArray);
          networkEdges.clear();
          networkEdges.add(edgesArray);
        }
      } catch (err) {
        console.error("Vis Network init error, falling back to list:", err);
        renderGraphFallback(rawNodes);
      }
    }

    function renderGraphFallback(nodes) {
      const fallback = document.getElementById('graph-fallback-container');
      const canvas = document.getElementById('vis-graph-canvas');
      if (canvas) canvas.classList.add('hidden');
      if (fallback) {
        fallback.classList.remove('hidden');
        const sources = nodes.filter(n => n.type === 'source');
        const sinks = nodes.filter(n => n.type === 'sink');
        fallback.innerHTML = `
          <div>
            <div class="text-cyan-400 font-bold uppercase text-[10px] tracking-wider mb-1">📥 Sources (${sources.length})</div>
            <div class="space-y-1">${sources.map(s => `<div class="p-2 rounded bg-cyan-950/40 text-cyan-300 font-code text-xs">${s.label}</div>`).join('')}</div>
          </div>
          <div class="mt-4">
            <div class="text-amber-400 font-bold uppercase text-[10px] tracking-wider mb-1">⚡ Action Sinks (${sinks.length})</div>
            <div class="space-y-1">${sinks.map(s => `<div class="p-2 rounded bg-slate-900 text-amber-300 font-code text-xs flex justify-between"><span>${s.label}</span><span class="text-slate-500">${s.metadata?.tier || 'Tier 1'}</span></div>`).join('')}</div>
          </div>
        `;
      }
    }

    function resetGraphView() {
      if (network) {
        network.fit({ animation: { duration: 600, easingFunction: 'easeInOutQuad' } });
      }
    }

    function toggleGraphPhysics() {
      if (!network) return;
      physicsEnabled = !physicsEnabled;
      network.setOptions({ physics: { enabled: physicsEnabled } });
      const pBtn = document.getElementById('physics-btn');
      if (pBtn) pBtn.innerText = physicsEnabled ? "Physics: On" : "Physics: Off";
      const gStat = document.getElementById('graph-status-text');
      if (gStat) gStat.innerText = physicsEnabled ? "Live Dynamic Physics" : "Pinned";
    }

    function onNodeClicked(nodeId) {
      const targetMatchIndex = currentResults.findIndex(r => {
        const text = (r.variant || '') + ' ' + (r.case || '');
        return text.toLowerCase().includes(nodeId.toLowerCase());
      });

      if (targetMatchIndex !== -1) {
        inspectCase(targetMatchIndex);
        const cardEl = document.getElementById(`feed-card-${targetMatchIndex}`);
        if (cardEl) {
          cardEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      }
    }

    function setFeedFilter(filter) {
      activeFilter = filter;
      const allBtn = document.getElementById('filter-all-btn');
      const vulnBtn = document.getElementById('filter-vuln-btn');
      const secBtn = document.getElementById('filter-sec-btn');

      if (allBtn) allBtn.className = filter === 'all' ? 'px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700' : 'px-2 py-0.5 rounded bg-slate-800 text-slate-400';
      if (vulnBtn) vulnBtn.className = filter === 'vulnerable' ? 'px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-700' : 'px-2 py-0.5 rounded bg-slate-800 text-slate-400 hover:text-red-300';
      if (secBtn) secBtn.className = filter === 'secure' ? 'px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700' : 'px-2 py-0.5 rounded bg-slate-800 text-slate-400 hover:text-emerald-300';
      renderFeed();
    }

    function renderFeed() {
      const container = document.getElementById('feed-container');
      if (!container) return;

      let filtered = currentResults.map((r, idx) => ({ ...r, originalIndex: idx }));
      if (activeFilter === 'vulnerable') filtered = filtered.filter(r => r.passed === false);
      if (activeFilter === 'secure') filtered = filtered.filter(r => r.passed === true);

      const badge = document.getElementById('results-count-badge');
      if (badge) badge.innerText = `${filtered.length} / ${currentResults.length}`;

      if (filtered.length === 0) {
        container.innerHTML = '<div class="text-slate-500 italic p-6 text-center text-xs">No matching attack paths found.</div>';
        return;
      }

      container.innerHTML = filtered.map(r => {
        const isSelected = selectedCaseIndex === r.originalIndex;
        
        let cardClass = 'card-queued';
        let badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-code font-semibold bg-slate-800 text-slate-400 border border-slate-700">⏳ QUEUED</span>`;

        if (r.status === 'testing' || r.verdict === 'TESTING...') {
          cardClass = 'card-testing';
          badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-code font-bold bg-cyan-950 text-cyan-300 border border-cyan-500 animate-pulse">⚡ AUDITING...</span>`;
        } else if (r.status === 'tested' || r.passed !== null) {
          if (r.passed === false) {
            cardClass = 'card-vulnerable';
            badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-code font-extrabold bg-red-950 text-red-300 border border-red-700">🔴 VULNERABLE</span>`;
          } else if (r.passed === true) {
            cardClass = 'card-secure';
            badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-code font-extrabold bg-emerald-950 text-emerald-300 border border-emerald-700">🟢 SECURE</span>`;
          }
        }

        return `
          <div id="feed-card-${r.originalIndex}" onclick="inspectCase(${r.originalIndex})" 
               class="p-4 rounded-xl cursor-pointer transition-all duration-150 ${cardClass} ${isSelected ? 'card-selected' : ''}">
            <div class="flex justify-between items-center">
              ${badgeHtml}
              <span class="text-[10px] text-slate-400 font-code tracking-wider">${r.case}</span>
            </div>
            <div class="text-xs font-semibold text-white mt-2.5 line-clamp-2 leading-snug">${escapeHtml(r.variant)}</div>
            <div class="flex items-center space-x-2 mt-3 text-[10px] font-code">
              <span class="px-2 py-0.5 rounded bg-slate-950 text-cyan-300 border border-slate-800">${r.channel || 'direct'}</span>
              <span class="px-2 py-0.5 rounded bg-slate-950 text-amber-300 border border-slate-800">${r.tier || 'Tier 1'}</span>
            </div>
          </div>
        `;
      }).join('');

      if (selectedCaseIndex === null && filtered.length > 0) {
        inspectCase(filtered[0].originalIndex);
      }
    }

    function inspectCase(index) {
      selectedCaseIndex = index;
      const item = currentResults[index];
      if (!item) return;

      document.querySelectorAll('[id^="feed-card-"]').forEach(el => el.classList.remove('card-selected'));
      const activeCard = document.getElementById(`feed-card-${index}`);
      if (activeCard) activeCard.classList.add('card-selected');

      const inspBadge = document.getElementById('inspector-badge');
      if (inspBadge) inspBadge.innerText = `Case #${index + 1} — ${item.case}`;

      let html = `<div class="space-y-4">`;
      
      // Top Verdict / Status Banner
      if (item.status === 'queued' || item.passed === null) {
        html += `
          <div class="p-4 rounded-xl border bg-slate-900/60 border-slate-800 text-slate-300">
            <div class="text-[11px] font-code font-bold uppercase tracking-wider text-slate-400">⏳ DISCOVERED ATTACK PATH (AWAITING PROBE)</div>
            <div class="text-sm font-bold text-white mt-1.5 leading-snug">${escapeHtml(item.variant)}</div>
          </div>
        `;
      } else if (item.status === 'testing') {
        html += `
          <div class="p-4 rounded-xl border bg-cyan-950/40 border-cyan-600 text-cyan-300 animate-pulse">
            <div class="text-[11px] font-code font-bold uppercase tracking-wider">⚡ ACTIVELY AUDITING & PROBING TARGET...</div>
            <div class="text-sm font-bold text-white mt-1.5 leading-snug">${escapeHtml(item.variant)}</div>
          </div>
        `;
      } else {
        html += `
          <div class="p-4 rounded-xl border ${item.passed ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300' : 'bg-red-950/50 border-red-800 text-red-300'}">
            <div class="text-[11px] font-code font-bold uppercase tracking-wider">${item.passed ? '🟢 TRUST BOUNDARY UPHELD (DEFENDED)' : '🔴 EXPLOIT VERIFIED (VULNERABILITY CONFIRMED)'}</div>
            <div class="text-sm font-bold text-white mt-1.5 leading-snug">${escapeHtml(item.variant)}</div>
          </div>
        `;
      }

      if (item.owasp || item.mitre) {
        html += `
          <div class="flex flex-wrap gap-2">
            <span class="px-2.5 py-1 rounded bg-blue-950/90 border border-blue-700/70 text-blue-300 font-code text-[11px]">🛡️ ${escapeHtml(item.owasp || 'OWASP-LLM01')}</span>
            <span class="px-2.5 py-1 rounded bg-purple-950/90 border border-purple-700/70 text-purple-300 font-code text-[11px]">🎯 ${escapeHtml(item.mitre || 'MITRE-ATLAS')}</span>
          </div>
        `;
      }

      if (item.hypothesis) {
        html += `
          <div>
            <div class="text-cyan-400 font-semibold uppercase text-[10px] tracking-wider mb-1">🎯 Threat Hypothesis & Path:</div>
            <div class="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 text-xs leading-relaxed font-code">${escapeHtml(item.hypothesis)}</div>
          </div>
        `;
      }

      if (item.payload) {
        html += `
          <div>
            <div class="flex justify-between items-center mb-1">
              <span class="text-purple-400 font-semibold uppercase text-[10px] tracking-wider">💉 Injected Adversarial Vector:</span>
              <button onclick="copyToClipboard('${escapeJsString(item.payload)}', this)" class="text-[10px] font-code text-slate-400 hover:text-purple-300">Copy Payload</button>
            </div>
            <pre class="p-3 bg-[#050811] border border-purple-950/80 rounded-lg text-purple-300 text-xs whitespace-pre-wrap font-code leading-relaxed overflow-x-auto">${escapeHtml(item.payload)}</pre>
          </div>
        `;
      }

      if (item.trace && item.trace.length > 0) {
        html += `
          <div>
            <div class="text-slate-400 font-semibold uppercase text-[10px] tracking-wider mb-1">🔍 Step-by-Step Tool Execution Trace:</div>
            <div class="space-y-2">
        `;
        item.trace.forEach((step, idx) => {
          html += `
            <div class="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col space-y-1.5">
              <div class="flex items-center space-x-2 text-cyan-300 font-code font-bold text-xs">
                <span>[Step ${idx + 1}]</span>
                <span>⚡ ${escapeHtml(step.tool || 'Tool Invocation')}</span>
              </div>
              <pre class="text-slate-300 text-xs p-2 bg-[#060a14] rounded border border-slate-900/90 font-code overflow-x-auto">${escapeHtml(JSON.stringify(step.args || step.arguments || step, null, 2))}</pre>
            </div>
          `;
        });
        html += `</div></div>`;
      } else if (item.status === 'tested') {
        html += `
          <div>
            <div class="text-slate-400 font-semibold uppercase text-[10px] tracking-wider mb-1">🔍 Step-by-Step Tool Execution Trace:</div>
            <div class="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800/80 text-slate-500 italic text-xs">No external action sinks invoked. Attack was neutralized by safety boundaries.</div>
          </div>
        `;
      }

      if (item.detail && item.status === 'tested') {
        html += `
          <div>
            <div class="text-slate-400 font-semibold uppercase text-[10px] tracking-wider mb-1">⚖️ Consensus Multi-Judge Invariant Evaluation:</div>
            <div class="p-3 ${item.passed ? 'bg-emerald-950/30 border border-emerald-900/40 text-emerald-300' : 'bg-red-950/30 border border-red-900/40 text-red-300'} rounded-lg text-xs leading-relaxed font-code">${escapeHtml(item.detail)}</div>
          </div>
        `;
      }

      const matchingFinding = currentFindings.find(f => f.hypothesis_id === item.case);
      if (matchingFinding) {
        if (matchingFinding.patch_diff) {
          html += `
            <div>
              <div class="flex justify-between items-center mb-1">
                <span class="text-emerald-400 font-semibold uppercase text-[10px] tracking-wider">🛠️ Automated Remediation Patch (.diff):</span>
                <button onclick="copyToClipboard('${escapeJsString(matchingFinding.patch_diff)}', this)" class="text-[10px] font-code text-slate-400 hover:text-emerald-300">Copy Diff</button>
              </div>
              <pre class="p-3 bg-[#050811] border border-emerald-950/80 rounded-lg text-emerald-300 text-xs whitespace-pre-wrap font-code leading-relaxed overflow-x-auto">${escapeHtml(matchingFinding.patch_diff)}</pre>
            </div>
          `;
        }
        if (matchingFinding.poc_script_path) {
          html += `
            <div>
              <div class="text-cyan-400 font-semibold uppercase text-[10px] tracking-wider mb-1">⚡ Standalone PoC Script:</div>
              <div class="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-cyan-300 font-code text-xs truncate">${escapeHtml(matchingFinding.poc_script_path)}</div>
            </div>
          `;
        }
      }

      html += `</div>`;
      const inspCont = document.getElementById('inspector-container');
      if (inspCont) inspCont.innerHTML = html;
    }

    function escapeHtml(text) {
      if (!text) return "";
      return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    function escapeJsString(text) {
      if (!text) return "";
      return String(text)
        .replace(/\\/g, "\\\\")
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, "\\n")
        .replace(/\r/g, "");
    }

    function copyToClipboard(text, btn) {
      navigator.clipboard.writeText(text).then(() => {
        const old = btn.innerText;
        btn.innerText = "✓ Copied";
        setTimeout(() => { btn.innerText = old; }, 1500);
      });
    }

    poll();
  </script>
</body>
</html>
"""
