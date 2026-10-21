// ── Extension announcement banner ────────────────────────────────────────────
// Shows the "get the browser extension" banner at the top of the homepage
// unless the visitor has already dismissed it (remembered in localStorage).
(() => {
  const KEY = 'blink-ext-banner-dismissed';
  const banner = document.getElementById('ext-banner');
  if (!banner) return;

  try {
    if (localStorage.getItem(KEY)) return;
  } catch (_e) {}

  banner.classList.remove('hidden');

  const closeBtn = document.getElementById('ext-banner-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      banner.classList.add('hidden');
      try { localStorage.setItem(KEY, '1'); } catch (_e) {}
    });
  }
})();
