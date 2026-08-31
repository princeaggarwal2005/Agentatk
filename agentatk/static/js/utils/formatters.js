/**
 * AGENTATK Console — String & Syntax Formatters
 */

export function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function escapeJsString(text) {
  if (!text) return '';
  return String(text)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '');
}

export function formatJson(obj) {
  try {
    if (typeof obj === 'string') {
      obj = JSON.parse(obj);
    }
    return JSON.stringify(obj, null, 2);
  } catch (e) {
    return String(obj);
  }
}

export function renderDiff(diffText) {
  if (!diffText) return '';
  const lines = diffText.split('\n');
  return lines.map(line => {
    const escaped = escapeHtml(line);
    if (line.startsWith('+') && !line.startsWith('+++')) {
      return `<div style="background: rgba(16, 185, 129, 0.12); color: #34d399; padding: 1px 6px;">${escaped}</div>`;
    } else if (line.startsWith('-') && !line.startsWith('---')) {
      return `<div style="background: rgba(239, 68, 68, 0.12); color: #f87171; padding: 1px 6px;">${escaped}</div>`;
    } else if (line.startsWith('@@')) {
      return `<div style="color: #38bdf8; font-weight: 600; padding: 2px 6px;">${escaped}</div>`;
    }
    return `<div style="color: #94a3b8; padding: 1px 6px;">${escaped}</div>`;
  }).join('');
}
