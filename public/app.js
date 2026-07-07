(() => {
  const MAX_SECRET_BYTES = 10 * 1024; // 10 KB

  // ── Link pending guard ─────────────────────────────────────────────────────
  // True after a link is created, false once copied or result hidden voluntarily.
  let linkPending = false;

  function setLinkPending(val) {
    linkPending = val;
    if (val) {
      window.addEventListener('beforeunload', onBeforeUnload);
    } else {
      window.removeEventListener('beforeunload', onBeforeUnload);
    }
  }

  function onBeforeUnload(e) {
    e.preventDefault();
    e.returnValue = '';
  }

  // ── Tab switching ──────────────────────────────────────────────────────────
  const tabs = [...document.querySelectorAll('.tab')];
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', async () => {
      const prevIndex = tabs.indexOf(document.querySelector('.tab.active'));
      if (index === prevIndex) return;

      if (linkPending) {
        const leave = await confirmDiscard(
          'You have a secure link ready to share. Switching tabs will discard it and you will need to create a new one.',
          'Discard and switch'
        );
        if (!leave) return;
      }

      const dir = index > prevIndex ? 'slide-in-right' : 'slide-in-left';

      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => {
        c.classList.remove('active', 'slide-in-right', 'slide-in-left');
      });

      tab.classList.add('active');
      const content = document.getElementById(`tab-${tab.dataset.tab}`);
      content.classList.add('active');
      void content.offsetWidth; // force reflow so animation starts clean
      content.classList.add(dir);
      hideResult();
      setLinkPending(false);
    });
  });

  // ── Password generator ─────────────────────────────────────────────────────
  const CHARS = {
    upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower:   'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.?',
  };

  function buildCharset() {
    let cs = '';
    if (document.getElementById('opt-upper').checked)   cs += CHARS.upper;
    if (document.getElementById('opt-lower').checked)   cs += CHARS.lower;
    if (document.getElementById('opt-numbers').checked) cs += CHARS.numbers;
    if (document.getElementById('opt-symbols').checked) cs += CHARS.symbols;
    return cs || CHARS.lower;
  }

  // Rejection-sampling to eliminate modulo bias
  function generatePassword(length, charset) {
    const csLen  = charset.length;
    const maxVal = 256 - (256 % csLen); // largest multiple of csLen that fits in a byte
    const result = [];
    while (result.length < length) {
      const buf = new Uint8Array(length * 3);
      crypto.getRandomValues(buf);
      for (let i = 0; i < buf.length && result.length < length; i++) {
        if (buf[i] < maxVal) result.push(charset[buf[i] % csLen]);
      }
    }
    return result.join('');
  }

  function calcStrength(pwd) {
    let score = 0;
    if (pwd.length >= 10) score++;
    if (pwd.length >= 16) score++;
    if (pwd.length >= 24) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[a-z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    if (score <= 2) return { label: 'Weak',       pct: '20%',  color: '#ef4444' };
    if (score <= 3) return { label: 'Fair',       pct: '45%',  color: '#F5A623' };
    if (score <= 4) return { label: 'Good',       pct: '68%',  color: '#61cf5a' };
    if (score <= 5) return { label: 'Strong',     pct: '85%',  color: '#61cf5a' };
    return               { label: 'Very Strong', pct: '100%', color: '#00D4AA' };
  }

  function regenerate() {
    const length  = parseInt(document.getElementById('length-slider').value, 10);
    const charset = buildCharset();
    const pwd     = generatePassword(length, charset);
    document.getElementById('gen-preview').value = pwd;
    const s    = calcStrength(pwd);
    const fill = document.getElementById('strength-fill');
    fill.style.width      = s.pct;
    fill.style.background = s.color;
    document.getElementById('strength-text').textContent = s.label;
    document.getElementById('strength-text').style.color = s.color;
  }

  const slider = document.getElementById('length-slider');
  slider.addEventListener('input', () => {
    document.getElementById('length-val').textContent = slider.value;
    regenerate();
  });
  ['opt-upper', 'opt-lower', 'opt-numbers', 'opt-symbols'].forEach(id => {
    document.getElementById(id).addEventListener('change', regenerate);
  });
  document.getElementById('btn-generate').addEventListener('click', regenerate);
  document.getElementById('gen-refresh').addEventListener('click', regenerate);
  document.getElementById('gen-copy').addEventListener('click', () => {
    const val = document.getElementById('gen-preview').value;
    if (val) copyText(val, document.getElementById('gen-copy'));
  });

  // ── File tab ───────────────────────────────────────────────────────────────
  const BLOCKED_EXTENSIONS = new Set([
    'exe', 'bat', 'cmd', 'com', 'msi', 'msp', 'msc', 'scr', 'pif', 'lnk',
    'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'jse', 'wsf', 'wsh', 'hta',
    'sh', 'bash', 'zsh', 'fish', 'csh', 'ksh',
    'reg', 'inf', 'cpl', 'dll', 'so', 'dylib',
    'jar', 'apk', 'ipa', 'dmg', 'pkg', 'deb', 'rpm',
  ]);
  const MAX_FILE_BYTES = 2 * 1024 * 1024;

  let _selectedFile = null;

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  }

  function setSelectedFile(file) {
    _selectedFile = file;
    const inner = document.getElementById('file-drop-inner');
    const info  = document.getElementById('file-selected-info');
    if (file) {
      document.getElementById('file-selected-name').textContent = file.name;
      document.getElementById('file-selected-size').textContent = formatBytes(file.size);
      inner.classList.add('hidden');
      info.classList.remove('hidden');
    } else {
      inner.classList.remove('hidden');
      info.classList.add('hidden');
    }
  }

  const dropZone  = document.getElementById('file-drop-zone');
  const fileInput = document.getElementById('file-input');

  document.getElementById('btn-file-pick').addEventListener('click', () => fileInput.click());
  document.getElementById('btn-file-clear').addEventListener('click', () => {
    setSelectedFile(null);
    fileInput.value = '';
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) setSelectedFile(fileInput.files[0]);
  });

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', e => {
    if (!dropZone.contains(e.relatedTarget)) dropZone.classList.remove('drag-over');
  });
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) setSelectedFile(file);
  });

  // ── Byte counter ───────────────────────────────────────────────────────────
  const secretInput  = document.getElementById('secret-input');
  const byteCounter  = document.getElementById('byte-counter');
  const MAX_BYTES    = 10 * 1024;
  secretInput.addEventListener('input', () => {
    const bytes = new TextEncoder().encode(secretInput.value).length;
    byteCounter.textContent = `${(bytes / 1024).toFixed(1)} / 10 KB`;
    byteCounter.classList.toggle('byte-counter-warn',   bytes > MAX_BYTES * 0.8);
    byteCounter.classList.toggle('byte-counter-danger', bytes >= MAX_BYTES);
  });

  // ── Crypto ─────────────────────────────────────────────────────────────────

  // Loop-based base64 — avoids stack overflow from spread on large arrays (F-07)
  function toB64(arr) {
    let str = '';
    for (let i = 0; i < arr.length; i++) str += String.fromCharCode(arr[i]);
    return btoa(str);
  }

  async function encryptSecret(text) {
    const encoded = new TextEncoder().encode(text);
    if (encoded.length > MAX_SECRET_BYTES) {
      throw new RangeError('Secret is too large. Maximum size is 10 KB.');
    }
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
    const iv           = crypto.getRandomValues(new Uint8Array(12));
    const ciphertextBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    const rawKey        = new Uint8Array(await crypto.subtle.exportKey('raw', key));

    // Split key: K = K1 XOR K2. K1 goes in URL fragment, K2 goes to server.
    // Neither half alone can decrypt — server must participate in every reveal.
    const k1 = crypto.getRandomValues(new Uint8Array(32));
    const k2 = new Uint8Array(32);
    for (let i = 0; i < 32; i++) k2[i] = rawKey[i] ^ k1[i];

    return {
      ciphertext: toB64(new Uint8Array(ciphertextBuf)),
      iv:         toB64(iv),
      k1:         toB64(k1),
      k2:         toB64(k2),
    };
  }

  async function encryptFile(file) {
    const encoded = new Uint8Array(await file.arrayBuffer());
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
    const iv           = crypto.getRandomValues(new Uint8Array(12));
    const ciphertextBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    const rawKey        = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    const k1 = crypto.getRandomValues(new Uint8Array(32));
    const k2 = new Uint8Array(32);
    for (let i = 0; i < 32; i++) k2[i] = rawKey[i] ^ k1[i];
    return {
      ciphertext: toB64(new Uint8Array(ciphertextBuf)),
      iv:         toB64(iv),
      k1:         toB64(k1),
      k2:         toB64(k2),
    };
  }

  // ── Create link ────────────────────────────────────────────────────────────
  const btnCreate = document.getElementById('btn-create');
  const BTN_HTML  = `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Encrypt &amp; Create Link`;

  // ── Email confirmation modal ───────────────────────────────────────────────
  function confirmEmail(email) {
    return new Promise(resolve => {
      document.getElementById('modal-email').textContent = email;
      const overlay = document.getElementById('email-confirm-overlay');
      overlay.classList.remove('hidden');
      const confirmBtn = document.getElementById('modal-confirm');
      const cancelBtn  = document.getElementById('modal-cancel');
      function close(result) {
        overlay.classList.add('hidden');
        confirmBtn.replaceWith(confirmBtn.cloneNode(true));
        cancelBtn.replaceWith(cancelBtn.cloneNode(true));
        resolve(result);
      }
      document.getElementById('modal-confirm').addEventListener('click', () => close(true));
      document.getElementById('modal-cancel').addEventListener('click',  () => close(false));
      overlay.addEventListener('click', e => { if (e.target === overlay) close(false); }, { once: true });
    });
  }

  function confirmDiscard(body, discardLabel) {
    return new Promise(resolve => {
      document.getElementById('tab-warn-body').textContent = body;
      document.getElementById('tab-warn-leave-label').textContent = discardLabel;
      const overlay = document.getElementById('tab-warn-overlay');
      overlay.classList.remove('hidden');
      function close(result) {
        overlay.classList.add('hidden');
        document.getElementById('tab-warn-leave').replaceWith(document.getElementById('tab-warn-leave').cloneNode(true));
        document.getElementById('tab-warn-stay').replaceWith(document.getElementById('tab-warn-stay').cloneNode(true));
        resolve(result);
      }
      document.getElementById('tab-warn-leave').addEventListener('click', () => close(true));
      document.getElementById('tab-warn-stay').addEventListener('click',  () => close(false));
      overlay.addEventListener('click', e => { if (e.target === overlay) close(false); }, { once: true });
    });
  }

  btnCreate.addEventListener('click', async () => {
    if (linkPending) {
      const discard = await confirmDiscard(
        'You already have a link ready to share. Creating a new one will discard it permanently.',
        'Discard and create new'
      );
      if (!discard) return;
      setLinkPending(false);
      hideResult();
    }

    const activeTab = document.querySelector('.tab.active').dataset.tab;
    let secret = '';
    let fileToEncrypt = null;

    if (activeTab === 'file') {
      if (!_selectedFile) {
        showError('Please select or drop a file first.');
        return;
      }
      const ext = _selectedFile.name.includes('.') ? _selectedFile.name.split('.').pop().toLowerCase() : '';
      if (BLOCKED_EXTENSIONS.has(ext)) {
        showError(`.${ext} files are not allowed for security reasons.`);
        return;
      }
      if (_selectedFile.size > MAX_FILE_BYTES) {
        showError('File is too large. Maximum size is 2 MB.');
        return;
      }
      fileToEncrypt = _selectedFile;
    } else {
      secret = activeTab === 'enter'
        ? document.getElementById('secret-input').value
        : document.getElementById('gen-preview').value.trim();
      if (!secret) {
        showError(activeTab === 'enter'
          ? 'Please enter a secret before creating a link.'
          : 'Click Generate first to create a password.');
        return;
      }
    }

    const recipientEmail = document.getElementById('recipient-email').value.trim();
    if (recipientEmail) {
      const confirmed = await confirmEmail(recipientEmail);
      if (!confirmed) return;
    }

    hideError();
    btnCreate.disabled = true;
    btnCreate.textContent = 'Encrypting…';

    try {
      const { ciphertext, iv, k1, k2 } = fileToEncrypt
        ? await encryptFile(fileToEncrypt)
        : await encryptSecret(secret);

      const expiresIn = parseInt(document.querySelector('input[name="expiry"]:checked').value, 10);

      const payload = { ciphertext, iv, k2, expiresIn };
      if (recipientEmail) payload.recipientEmail = recipientEmail;
      if (fileToEncrypt) {
        payload.isFile   = true;
        payload.filename = fileToEncrypt.name;
        payload.mimetype = fileToEncrypt.type || 'application/octet-stream';
      }

      const res = await fetch('/api/secret', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(payload),
      });

      if (res.status === 429) {
        showError('Too many requests. Please wait a moment and try again.');
        return;
      }
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        showError(data.error || 'Something went wrong. Please try again.');
        return;
      }

      const { id } = await res.json();

      const viewUrl = `${window.location.origin}/view/${id}#${encodeURIComponent(k1)}`;
      document.getElementById('link-output').value = viewUrl;
      document.getElementById('result').classList.remove('hidden');
      setLinkPending(true);

      const expiryLabel = expiresIn === 1 ? '1 hour' : `${expiresIn} hours`;
      document.querySelector('.warn-box span').textContent = `View once only · Expires in ${expiryLabel} if unopened · Never stored in plaintext`;

      if (!fileToEncrypt) {
        document.getElementById('secret-input').value = '';
        document.getElementById('gen-preview').value  = '';
      }
      document.getElementById('recipient-email').value = '';

    } catch (err) {
      if (err instanceof RangeError) {
        showError(err.message);
      } else {
        showError('Failed to create link. Please try again.');
      }
    } finally {
      btnCreate.disabled = false;
      btnCreate.innerHTML = BTN_HTML;
    }
  });

  // ── Copy link ──────────────────────────────────────────────────────────────
  document.getElementById('link-copy').addEventListener('click', () => {
    const val = document.getElementById('link-output').value;
    copyText(val, document.getElementById('link-copy'), document.querySelector('#link-copy span'));
    setLinkPending(false);
  });

  // ── Helpers ────────────────────────────────────────────────────────────────
  const WARN_ICON_HTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';

  let _toast = null;
  let _toastTimer = null;

  function showError(msg) {
    if (_toast) { _toast.remove(); clearTimeout(_toastTimer); }
    _toast = document.createElement('div');
    _toast.className = 'toast toast-error';
    _toast.innerHTML = WARN_ICON_HTML + '<span></span><button class="toast-close" aria-label="Dismiss">&times;</button>';
    _toast.querySelector('span').textContent = msg;
    _toast.querySelector('.toast-close').addEventListener('click', hideError);
    document.body.appendChild(_toast);
    void _toast.offsetWidth;
    _toast.classList.add('toast-show');
    _toastTimer = setTimeout(hideError, 5000);
  }

  function hideError() {
    if (!_toast) return;
    clearTimeout(_toastTimer);
    _toast.classList.remove('toast-show');
    const el = _toast;
    _toast = null;
    setTimeout(() => el.remove(), 300);
  }

  function hideResult() {
    document.getElementById('result').classList.add('hidden');
  }

  function copyText(text, btn, labelEl) {
    navigator.clipboard.writeText(text).then(() => {
      btn.classList.add('copied');
      const orig = labelEl ? labelEl.textContent : '';
      if (labelEl) labelEl.textContent = 'Copied!';
      setTimeout(() => {
        btn.classList.remove('copied');
        if (labelEl) labelEl.textContent = orig;
      }, 2000);
    }).catch(() => {
      // Clipboard API unavailable (requires HTTPS or localhost)
      showError('Copy failed. Please select and copy the link manually.');
    });
  }

  // ── Secrets count ──────────────────────────────────────────────────────────
  fetch('/api/stats')
    .then(r => r.json())
    .then(({ secretsCreated }) => {
      if (secretsCreated > 0) {
        document.getElementById('stat-card').classList.remove('hidden');
        const el = document.getElementById('secrets-count');
        const duration = 1200;
        const start = performance.now();
        const from = Math.max(0, secretsCreated - Math.min(secretsCreated, 80));
        const step = ts => {
          const p = Math.min((ts - start) / duration, 1);
          const ease = 1 - Math.pow(1 - p, 3);
          el.textContent = Math.round(from + (secretsCreated - from) * ease).toLocaleString();
          if (p < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
      }
    })
    .catch(() => {});

})();
