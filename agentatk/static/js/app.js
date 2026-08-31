/**
 * AGENTATK Console — Main Application Controller
 */

import { updateMetrics } from './components/metrics.js';
import { renderTopology, resetTopologyView, toggleTopologyPhysics } from './components/topology.js';
import { renderLedger, setLedgerFilter, setLedgerSearch, selectCase, getSelectedIndex } from './components/ledger.js';
import { renderInspector } from './components/inspector.js';
import { copyToClipboard } from './utils/clipboard.js';

let appState = null;
let pollTimer = null;

async function fetchState() {
  try {
    const res = await fetch('/api/state');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    appState = data;
    render(data);

    // Continue polling if running
    if (data.status === 'running') {
      pollTimer = setTimeout(fetchState, 750);
    } else {
      updateScanButton(false);
    }
  } catch (err) {
    console.error("State polling error:", err);
    updateScanButton(false);
  }
}

function render(data) {
  // Update Metrics & Ticker
  updateMetrics(data);

  // Update Topology Graph
  renderTopology(data.graph, onNodeSelected);

  // Update Ledger
  renderLedger(data.results, onCaseSelected);

  // Update Inspector
  const selectedIdx = getSelectedIndex();
  if (selectedIdx !== null && data.results && data.results[selectedIdx]) {
    const selectedItem = data.results[selectedIdx];
    const matchingFinding = (data.findings || []).find(f => f.hypothesis_id === selectedItem.case);
    renderInspector(selectedItem, matchingFinding);
  } else if (data.results && data.results.length > 0 && selectedIdx === null) {
    selectCase(0, onCaseSelected);
  }
}

function onCaseSelected(index) {
  if (!appState || !appState.results || !appState.results[index]) return;
  const item = appState.results[index];
  const matchingFinding = (appState.findings || []).find(f => f.hypothesis_id === item.case);
  renderInspector(item, matchingFinding);

  const card = document.getElementById(`ledger-item-${index}`);
  if (card) {
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function onNodeSelected(nodeId) {
  if (!appState || !appState.results) return;
  const matchIdx = appState.results.findIndex(r => {
    const text = `${r.variant || ''} ${r.case || ''}`.toLowerCase();
    return text.includes(nodeId.toLowerCase());
  });

  if (matchIdx !== -1) {
    selectCase(matchIdx, onCaseSelected);
  }
}

async function triggerScan() {
  const inputEl = document.getElementById('target-path-input');
  const path = inputEl ? inputEl.value.trim() : './targets/home-llm';
  if (!path) return;

  updateScanButton(true);

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_path: path })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    console.log("Scan started:", data);

    if (pollTimer) clearTimeout(pollTimer);
    setTimeout(fetchState, 400);
  } catch (err) {
    console.error("Failed to start scan:", err);
    updateScanButton(false);
  }
}

function updateScanButton(isRunning) {
  const btn = document.getElementById('btn-run-audit');
  const btnIcon = document.getElementById('btn-run-icon');
  const btnText = document.getElementById('btn-run-text');

  if (!btn) return;
  btn.disabled = isRunning;

  if (isRunning) {
    if (btnIcon) btnIcon.innerText = "⏳";
    if (btnText) btnText.innerText = "Auditing Target...";
  } else {
    if (btnIcon) btnIcon.innerText = "▶";
    if (btnText) btnText.innerText = "Run Security Audit";
  }
}

// Global window hooks for inline HTML attributes
window.triggerScan = triggerScan;
window.selectLedgerCase = (idx) => selectCase(idx, onCaseSelected);
window.filterLedger = (f) => setLedgerFilter(f, onCaseSelected);
window.resetGraph = resetTopologyView;
window.togglePhysics = toggleTopologyPhysics;
window.copyText = copyToClipboard;

// Global Listeners & Sidebar Routing
document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('ledger-search-input');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      setLedgerSearch(e.target.value, onCaseSelected);
    });
  }

  // Keyboard shortcut: Cmd/Ctrl + K to focus search
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      if (searchInput) searchInput.focus();
    }
  });

  // Sidebar Navigation handlers
  const navOverview = document.getElementById('nav-overview');
  const navTopology = document.getElementById('nav-topology');
  const navLedger = document.getElementById('nav-ledger');
  const navRemediation = document.getElementById('nav-remediation');

  const navItems = [navOverview, navTopology, navLedger, navRemediation].filter(Boolean);

  function setActiveNav(targetNav) {
    navItems.forEach(n => n.classList.remove('active'));
    if (targetNav) targetNav.classList.add('active');
  }

  if (navOverview) {
    navOverview.addEventListener('click', () => {
      setActiveNav(navOverview);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  if (navTopology) {
    navTopology.addEventListener('click', () => {
      setActiveNav(navTopology);
      const graphCanvas = document.getElementById('vis-graph-canvas');
      if (graphCanvas) graphCanvas.scrollIntoView({ behavior: 'smooth', block: 'center' });
      resetTopologyView();
    });
  }

  if (navLedger) {
    navLedger.addEventListener('click', () => {
      setActiveNav(navLedger);
      const ledgerContainer = document.getElementById('ledger-container');
      if (ledgerContainer) ledgerContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  }

  if (navRemediation) {
    navRemediation.addEventListener('click', () => {
      setActiveNav(navRemediation);
      setLedgerFilter('vulnerable', onCaseSelected);
      const inspBody = document.getElementById('inspector-body');
      if (inspBody) inspBody.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  // Initial fetch
  fetchState();
});
