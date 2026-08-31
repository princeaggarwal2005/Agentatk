/**
 * AGENTATK Console — Clipboard Utilities
 */

export function copyToClipboard(text, btnElement, successLabel = "✓ Copied") {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    if (btnElement) {
      const originalText = btnElement.innerText;
      btnElement.innerText = successLabel;
      btnElement.style.color = "#38bdf8";
      setTimeout(() => {
        btnElement.innerText = originalText;
        btnElement.style.color = "";
      }, 1600);
    }
  }).catch(err => {
    console.error("Clipboard copy failed:", err);
  });
}
