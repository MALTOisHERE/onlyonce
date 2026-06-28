if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');

let _installPrompt = null;

window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  _installPrompt = e;
  const bar = document.getElementById('install-bar');
  if (bar) bar.classList.remove('hidden');
});

window.addEventListener('appinstalled', () => {
  _installPrompt = null;
  const bar = document.getElementById('install-bar');
  if (bar) bar.classList.add('hidden');
});

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btn-install');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    if (!_installPrompt) return;
    await _installPrompt.prompt();
    _installPrompt = null;
    const bar = document.getElementById('install-bar');
    if (bar) bar.classList.add('hidden');
  });
});
