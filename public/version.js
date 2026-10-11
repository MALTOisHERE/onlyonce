(() => {
  const el = document.getElementById('app-version');
  if (!el) return;
  fetch('/api/config')
    .then(r => r.json())
    .then(cfg => { if (cfg.version) el.textContent = `v${cfg.version}`; })
    .catch(() => {});
})();
