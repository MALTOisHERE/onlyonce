(() => {
  document.querySelectorAll('.faq-q').forEach(btn => {
    btn.addEventListener('click', () => {
      const isOpen = btn.getAttribute('aria-expanded') === 'true';
      document.querySelectorAll('.faq-q').forEach(b => b.setAttribute('aria-expanded', 'false'));
      btn.setAttribute('aria-expanded', String(!isOpen));
    });
  });

  // Pro pricing card: open the checkout configured on the server.
  // Falls back to the homepage pricing section if no checkout is configured.
  const proBtn = document.getElementById('btn-pro-cta-about');
  if (proBtn) {
    let checkoutUrl = null;
    fetch('/api/config')
      .then(r => r.json())
      .then(cfg => { checkoutUrl = cfg.proCheckoutUrl || null; })
      .catch(() => {});
    proBtn.addEventListener('click', () => {
      if (checkoutUrl) {
        window.open(checkoutUrl, '_blank', 'noopener');
      } else {
        window.location.href = '/#pricing';
      }
    });
  }
})();
