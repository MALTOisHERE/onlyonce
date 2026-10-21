// Applies the saved theme before paint, same approach as the website's
// theme-init.js: localStorage is synchronous, so there's no flash of the
// wrong theme the way there would be with an async chrome.storage.get.
(function () {
  try {
    const t = localStorage.getItem('blink-ext-theme');
    document.documentElement.setAttribute('data-theme', t || 'light');
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();
