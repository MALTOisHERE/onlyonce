if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');

let _installPrompt = null;

function setInstallVisible(visible) {
  const btn = document.getElementById('btn-install');
  if (!btn) return;
  const sep = btn.previousElementSibling;
  btn.classList.toggle('hidden', !visible);
  if (sep && sep.classList.contains('logo-sep')) sep.classList.toggle('hidden', !visible);
}

window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  _installPrompt = e;
  setInstallVisible(true);
});

window.addEventListener('appinstalled', () => {
  _installPrompt = null;
  setInstallVisible(false);
});

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btn-install');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    if (!_installPrompt) return;
    await _installPrompt.prompt();
    _installPrompt = null;
    setInstallVisible(false);
  });
});
