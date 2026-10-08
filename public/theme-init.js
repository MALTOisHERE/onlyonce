(function () {
  try {
    var t = localStorage.getItem('blink-theme');
    if (t) document.documentElement.setAttribute('data-theme', t);
  } catch (e) {}
})();
