/**
 * AGENTATK Console — Attack Path Ledger Component
 */

import { escapeHtml } from '../utils/formatters.js';

let activeFilter = 'all';
let searchQuery = '';
let selectedIndex = null;
let currentResults = [];

export function renderLedger(results, onSelectCase) {
  currentResults = results || [];
  const container = document.getElementById('ledger-container');
  const countBadge = document.getElementById('ledger-count-badge');
  if (!container) return;

  // Filter & Search
  let filtered = currentResults.map((r, idx) => ({ ...r, originalIndex: idx }));

  if (activeFilter === 'vulnerable') {
    filtered = filtered.filter(r => r.passed === false);
  } else if (activeFilter === 'secure') {
    filtered = filtered.filter(r => r.passed === true);
  }

  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(r => {
      const text = `${r.case} ${r.variant} ${r.channel} ${r.tier} ${r.hypothesis || ''}`.toLowerCase();
      return text.includes(q);
    });
  }

  if (countBadge) {
    countBadge.innerText = `${filtered.length} / ${currentResults.length}`;
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="padding: 36px 16px; text-align: center; color: #64748b; font-size: 12px; font-style: italic;">
        No attack paths match the current filter.
      </div>
    `;
    return;
  }

  container.innerHTML = filtered.map(item => {
    const isSelected = selectedIndex === item.originalIndex;
    
    let statusClass = 'queued';
    let statusBadge = '<span class="badge-status queued">QUEUED</span>';

    if (item.status === 'testing' || item.verdict === 'TESTING...') {
      statusClass = 'testing';
      statusBadge = '<span class="badge-status testing">AUDITING</span>';
    } else if (item.status === 'tested' || item.passed !== null) {
      if (item.passed === false) {
        statusClass = 'vuln';
        statusBadge = '<span class="badge-status vuln">VULNERABLE</span>';
      } else if (item.passed === true) {
        statusClass = 'safe';
        statusBadge = '<span class="badge-status safe">SECURED</span>';
      }
    }

    return `
      <div id="ledger-item-${item.originalIndex}" 
           class="ledger-item ${isSelected ? 'selected' : ''}" 
           onclick="window.selectLedgerCase(${item.originalIndex})">
        <div class="ledger-item-header">
          ${statusBadge}
          <span class="ledger-item-id">${escapeHtml(item.case)}</span>
        </div>
        <div class="ledger-item-title">${escapeHtml(item.variant)}</div>
        <div class="ledger-item-tags">
          <span class="tag-pill channel">${escapeHtml(item.channel || 'direct')}</span>
          <span class="tag-pill tier">${escapeHtml(item.tier || 'Tier 1')}</span>
        </div>
      </div>
    `;
  }).join('');

  // Auto select first if nothing selected
  if (selectedIndex === null && filtered.length > 0 && typeof onSelectCase === 'function') {
    selectCase(filtered[0].originalIndex, onSelectCase);
  }
}

export function setLedgerFilter(filter, onSelectCase) {
  activeFilter = filter;
  const allBtn = document.getElementById('filter-all-btn');
  const vulnBtn = document.getElementById('filter-vuln-btn');
  const safeBtn = document.getElementById('filter-safe-btn');

  if (allBtn) allBtn.className = filter === 'all' ? 'seg-btn active-all' : 'seg-btn';
  if (vulnBtn) vulnBtn.className = filter === 'vulnerable' ? 'seg-btn active-vuln' : 'seg-btn';
  if (safeBtn) safeBtn.className = filter === 'secure' ? 'seg-btn active-safe' : 'seg-btn';

  renderLedger(currentResults, onSelectCase);
}

export function setLedgerSearch(query, onSelectCase) {
  searchQuery = query || '';
  renderLedger(currentResults, onSelectCase);
}

export function selectCase(index, onSelectCase) {
  selectedIndex = index;
  
  // Highlight card
  document.querySelectorAll('.ledger-item').forEach(el => el.classList.remove('selected'));
  const card = document.getElementById(`ledger-item-${index}`);
  if (card) card.classList.add('selected');

  if (typeof onSelectCase === 'function') {
    onSelectCase(index);
  }
}

export function getSelectedIndex() {
  return selectedIndex;
}
