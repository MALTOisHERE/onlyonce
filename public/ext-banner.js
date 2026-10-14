(function () {
  var KEY = 'blink-ext-banner-dismissed';
  var banner = document.getElementById('ext-banner');
  if (!banner) return;

  try {
    if (localStorage.getItem(KEY)) return;
  } catch (e) {}

  banner.classList.remove('hidden');

  var closeBtn = document.getElementById('ext-banner-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', function () {
      banner.classList.add('hidden');
      try { localStorage.setItem(KEY, '1'); } catch (e) {}
    });
  }
})();
