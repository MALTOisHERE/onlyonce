(() => {
  document.getElementById('ext-version').textContent = `v${chrome.runtime.getManifest().version}`;

  const bubbleEl      = document.getElementById('opt-bubble-enabled');
  const contextMenuEl = document.getElementById('opt-contextmenu-enabled');
  const btnSave       = document.getElementById('btn-save');

  blinkGetSettings().then((s) => {
    bubbleEl.checked      = s.bubbleEnabled;
    contextMenuEl.checked = s.contextMenuEnabled;
    const match = document.querySelector(`input[name="opt-expiry"][value="${s.defaultExpiryHours}"]`);
    if (match) match.checked = true;
  });

  // Same pattern as popup.js's flashCopied(): the button's own label
  // becomes the confirmation, instead of a separate adjacent hint.
  let saveFlashTimer = null;
  btnSave.addEventListener('click', () => {
    const checkedExpiry = document.querySelector('input[name="opt-expiry"]:checked');
    chrome.storage.sync.set({
      bubbleEnabled:      bubbleEl.checked,
      contextMenuEnabled: contextMenuEl.checked,
      defaultExpiryHours: parseInt(checkedExpiry?.value || '48', 10),
    }, () => {
      btnSave.textContent = 'Saved!';
      btnSave.classList.add('saved');
      clearTimeout(saveFlashTimer);
      saveFlashTimer = setTimeout(() => {
        btnSave.textContent = 'Save';
        btnSave.classList.remove('saved');
      }, 1500);
    });
  });
})();
