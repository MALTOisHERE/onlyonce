(function () {
  try {
    var t = localStorage.getItem('blink-theme');
    document.documentElement.setAttribute('data-theme', t || 'light');
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();
