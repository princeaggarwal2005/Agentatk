/**
 * AGENTATK Console — Forensic Inspector & Remediation Component
 */

import { escapeHtml, escapeJsString, formatJson, renderDiff } from '../utils/formatters.js';
import { copyToClipboard } from '../utils/clipboard.js';

export function renderInspector(item, matchingFinding) {
  const container = document.getElementById('inspector-body');
  const badgeEl = document.getElementById('inspector-case-badge');
  if (!container) return;

  if (!item) {
    if (badgeEl) badgeEl.innerText = "Select test case";
    container.innerHTML = `
      <div style="padding: 48px 24px; text-align: center; color: #64748b; font-size: 12px; line-height: 1.6;">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin: 0 auto 12px; opacity: 0.5;"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
        Select any attack hypothesis from the ledger or click an attack graph node to inspect forensic traces, multi-judge invariant verdicts, and verified remediation diffs.
      </div>
    `;
    return;
  }

  if (badgeEl) {
    badgeEl.innerText = `${item.case} (${item.tier || 'Tier 1'})`;
  }

  let html = ``;

  // 1. Top Verdict Banner
  if (item.status === 'queued' || item.passed === null) {
    html += `
      <div class="verdict-banner queued">
        <div class="verdict-banner-title">⏳ Planned Attack Vector (Awaiting Execution)</div>
        <div class="verdict-banner-desc">${escapeHtml(item.variant)}</div>
      </div>
    `;
  } else if (item.status === 'testing') {
    html += `
      <div class="verdict-banner testing">
        <div class="verdict-banner-title">⚡ Autonomous Probing & Execution in Progress...</div>
        <div class="verdict-banner-desc">${escapeHtml(item.variant)}</div>
      </div>
    `;
  } else {
    if (item.passed === false) {
      html += `
        <div class="verdict-banner vuln">
          <div class="verdict-banner-title">🔴 Exploit Verified — Invariant Violated</div>
          <div class="verdict-banner-desc">${escapeHtml(item.variant)}</div>
        </div>
      `;
    } else {
      html += `
        <div class="verdict-banner safe">
          <div class="verdict-banner-title">🟢 Trust Boundary Upheld — Attack Neutralized</div>
          <div class="verdict-banner-desc">${escapeHtml(item.variant)}</div>
        </div>
      `;
    }
  }

  // 2. Standards Taxonomy Badges
  if (item.owasp || item.mitre) {
    html += `
      <div class="taxonomy-row">
        ${item.owasp ? `<div class="taxonomy-badge owasp">🛡️ ${escapeHtml(item.owasp)}</div>` : ''}
        ${item.mitre ? `<div class="taxonomy-badge mitre">🎯 ${escapeHtml(item.mitre)}</div>` : ''}
      </div>
    `;
  }

  // 3. Threat Hypothesis & Path
  if (item.hypothesis) {
    html += `
      <div class="forensic-section">
        <div class="forensic-label">🎯 Threat Hypothesis & Path</div>
        <div class="code-box">${escapeHtml(item.hypothesis)}</div>
      </div>
    `;
  }

  // 4. Injected Adversarial Vector (Payload)
  if (item.payload) {
    html += `
      <div class="forensic-section">
        <div class="forensic-label-row">
          <span class="forensic-label">💉 Injected Adversarial Vector</span>
          <button class="btn-copy-code" onclick="window.copyText('${escapeJsString(item.payload)}', this)">Copy Payload</button>
        </div>
        <pre class="code-box payload">${escapeHtml(item.payload)}</pre>
      </div>
    `;
  }

  // 5. Step-by-Step Tool Trace Execution
  if (item.trace && item.trace.length > 0) {
    html += `
      <div class="forensic-section">
        <div class="forensic-label">🔍 Step-by-Step Tool Telemetry Execution (${item.trace.length} Steps)</div>
        <div class="trace-steps">
    `;
    item.trace.forEach((step, idx) => {
      const toolName = step.tool || step.action || 'Tool Invocation';
      const argsContent = formatJson(step.args || step.arguments || step);
      html += `
        <div class="trace-step-card">
          <div class="trace-step-header">
            <span>Step ${idx + 1} &middot; ${escapeHtml(toolName)}</span>
          </div>
          <pre class="trace-step-body">${escapeHtml(argsContent)}</pre>
        </div>
      `;
    });
    html += `</div></div>`;
  } else if (item.status === 'tested') {
    html += `
      <div class="forensic-section">
        <div class="forensic-label">🔍 Step-by-Step Tool Telemetry Execution</div>
        <div class="code-box" style="color: #64748b; font-style: italic;">
          No external actions or tool sinks were triggered. The safety guardrails prevented tool dispatch.
        </div>
      </div>
    `;
  }

  // 6. Consensus Multi-Judge Invariant Evaluation
  if (item.detail && item.status === 'tested') {
    const isPass = item.passed;
    html += `
      <div class="forensic-section">
        <div class="forensic-label">⚖️ Consensus Multi-Judge Invariant Evaluation</div>
        <div class="judge-box ${isPass ? 'safe' : 'vuln'}">
          ${escapeHtml(item.detail)}
        </div>
      </div>
    `;
  }

  // 7. Automated Remediation & PoC
  if (matchingFinding) {
    if (matchingFinding.patch_diff) {
      html += `
        <div class="forensic-section">
          <div class="forensic-label-row">
            <span class="forensic-label">🛠️ Automated Remediation Patch (.diff)</span>
            <button class="btn-copy-code" onclick="window.copyText('${escapeJsString(matchingFinding.patch_diff)}', this)">Copy Patch</button>
          </div>
          <div class="code-box diff">${renderDiff(matchingFinding.patch_diff)}</div>
        </div>
      `;
    }
    if (matchingFinding.poc_script_path) {
      html += `
        <div class="forensic-section">
          <div class="forensic-label-row">
            <span class="forensic-label">⚡ Standalone PoC Script</span>
            <button class="btn-copy-code" onclick="window.copyText('${escapeJsString(matchingFinding.poc_script_path)}', this)">Copy Path</button>
          </div>
          <div class="code-box" style="color: #38bdf8;">${escapeHtml(matchingFinding.poc_script_path)}</div>
        </div>
      `;
    }
  }

  container.innerHTML = html;
}
