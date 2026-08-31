/**
 * AGENTATK Console — Metrics & Telemetry Component
 */

export function updateMetrics(state) {
  const {
    target,
    current_activity,
    status,
    total_cases = 0,
    completed_cases = 0,
    failed_cases = 0,
    asr = 0.0,
    results = [],
    findings = []
  } = state;

  // 1. Live Telemetry Ticker
  const tickerText = document.getElementById('ticker-text');
  if (tickerText) {
    tickerText.innerText = current_activity || "Autonomous research engine initialized. Awaiting target specification.";
  }

  const tickerDot = document.getElementById('ticker-dot');
  const statusPill = document.getElementById('status-pill');
  
  if (status === 'running') {
    if (tickerDot) tickerDot.className = "ticker-dot pulse";
    if (statusPill) {
      statusPill.className = "pill-status running";
      statusPill.innerText = "AUDITING";
    }
  } else if (status === 'completed') {
    if (tickerDot) {
      tickerDot.className = "ticker-dot";
      tickerDot.style.backgroundColor = "#10b981";
    }
    if (statusPill) {
      statusPill.className = "pill-status completed";
      statusPill.innerText = "COMPLETED";
    }
  } else if (status === 'error') {
    if (tickerDot) {
      tickerDot.className = "ticker-dot";
      tickerDot.style.backgroundColor = "#ef4444";
    }
    if (statusPill) {
      statusPill.className = "pill-status error";
      statusPill.innerText = "FAILED";
    }
  } else {
    if (tickerDot) {
      tickerDot.className = "ticker-dot";
      tickerDot.style.backgroundColor = "#64748b";
    }
    if (statusPill) {
      statusPill.className = "pill-status idle";
      statusPill.innerText = "IDLE";
    }
  }

  // 2. KPI Cards
  // Target Agent
  const targetEl = document.getElementById('kpi-target');
  if (targetEl) {
    targetEl.innerText = target && target !== "Awaiting scan..." ? target : "—";
  }

  // ASR
  const asrEl = document.getElementById('kpi-asr');
  if (asrEl) {
    asrEl.innerText = `${Number(asr).toFixed(1)}%`;
    if (completed_cases > 0) {
      asrEl.className = failed_cases > 0 ? "kpi-value vuln" : "kpi-value safe";
    } else {
      asrEl.className = "kpi-value";
    }
  }

  // Verified Vulnerabilities
  const vulnEl = document.getElementById('kpi-vuln');
  const vulnMetaEl = document.getElementById('kpi-vuln-meta');
  if (vulnEl) {
    vulnEl.innerText = failed_cases;
    vulnEl.className = failed_cases > 0 ? "kpi-value vuln" : "kpi-value";
  }
  if (vulnMetaEl) {
    vulnMetaEl.innerText = failed_cases > 0 ? `${failed_cases} Invariant Failures` : "0 Compromises";
  }

  // Attack Paths Pipeline Progress
  const pathsEl = document.getElementById('kpi-paths');
  const pathsMetaEl = document.getElementById('kpi-paths-meta');
  const totalCount = total_cases || results.length;
  if (pathsEl) {
    pathsEl.innerText = `${completed_cases} / ${totalCount}`;
  }
  if (pathsMetaEl) {
    const pct = totalCount > 0 ? Math.round((completed_cases / totalCount) * 100) : 0;
    pathsMetaEl.innerText = `${pct}% Execution Coverage`;
  }

  // 3. Sidebar Subsystem Widget
  const sideStatusBadge = document.getElementById('sidebar-status-badge');
  const sideProgressBar = document.getElementById('sidebar-progress-bar');
  const sideProgressMeta = document.getElementById('sidebar-progress-meta');

  if (sideStatusBadge) {
    if (status === 'running') {
      sideStatusBadge.className = "status-badge-mini active";
      sideStatusBadge.innerText = "ACTIVE";
    } else if (status === 'completed') {
      sideStatusBadge.className = "status-badge-mini ready";
      sideStatusBadge.innerText = "COMPLETE";
    } else {
      sideStatusBadge.className = "status-badge-mini ready";
      sideStatusBadge.innerText = "STANDBY";
    }
  }

  if (sideProgressBar) {
    const pct = totalCount > 0 ? Math.min(100, Math.round((completed_cases / totalCount) * 100)) : (status === 'running' ? 25 : 0);
    sideProgressBar.style.width = `${pct}%`;
    if (status === 'running') {
      sideProgressBar.classList.add('animated');
    } else {
      sideProgressBar.classList.remove('animated');
    }
  }

  if (sideProgressMeta) {
    sideProgressMeta.innerText = `${completed_cases} / ${totalCount} Evaluated`;
  }
}
