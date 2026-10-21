// ── Footer version ───────────────────────────────────────────────────────────
// Fills in the running app version (from GET /api/config) wherever an
// #app-version element exists in the page footer.
(() => {
  const el = document.getElementById('app-version');
  if (!el) return;
  fetch('/api/config')
    .then(r => r.json())
    .then(cfg => { if (cfg.version) el.textContent = `v${cfg.version}`; })
    .catch(() => {});
})();
