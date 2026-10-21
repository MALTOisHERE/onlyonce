// ── Theme init (pre-paint) ───────────────────────────────────────────────────
// Loaded synchronously in <head>, before anything renders, so the saved
// theme applies immediately - avoids a flash of the wrong theme that an
// async chrome.storage-style read would cause.
(() => {
  try {
    const t = localStorage.getItem('blink-theme');
    document.documentElement.setAttribute('data-theme', t || 'light');
  } catch (_e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();
