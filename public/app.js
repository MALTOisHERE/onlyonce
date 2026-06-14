(() => {
  const MAX_SECRET_BYTES = 10 * 1024; // 10 KB

  // ── Tab switching ──────────────────────────────────────────────────────────
  const tabs = [...document.querySelectorAll('.tab')];
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => {
      const prevIndex = tabs.indexOf(document.querySelector('.tab.active'));
      if (index === prevIndex) return;
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

  // ── Create link ────────────────────────────────────────────────────────────
  const btnCreate = document.getElementById('btn-create');
  const BTN_HTML  = `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Encrypt &amp; Create Link`;

  btnCreate.addEventListener('click', async () => {
    const activeTab = document.querySelector('.tab.active').dataset.tab;
    let secret = '';

    if (activeTab === 'enter') {
      secret = document.getElementById('secret-input').value;
    } else {
      secret = document.getElementById('gen-preview').value.trim();
    }

    if (!secret) {
      showError(activeTab === 'enter'
        ? 'Please enter a secret before creating a link.'
        : 'Click Generate first to create a password.');
      return;
    }

    hideError();
    btnCreate.disabled = true;
    btnCreate.textContent = 'Encrypting…';

    try {
      const { ciphertext, iv, k1, k2 } = await encryptSecret(secret);
      const recipientEmail = document.getElementById('recipient-email').value.trim();
      const expiresIn = parseInt(document.querySelector('input[name="expiry"]:checked').value, 10);

      const payload = { ciphertext, iv, k2, expiresIn };
      if (recipientEmail) payload.recipientEmail = recipientEmail;

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

      const expiryLabel = expiresIn === 1 ? '1 hour' : `${expiresIn} hours`;
      document.querySelector('.warn-box span').textContent = `View once only · Expires in ${expiryLabel} if unopened · Never stored in plaintext`;

      // Clear plaintext and email from inputs
      document.getElementById('secret-input').value  = '';
      document.getElementById('gen-preview').value   = '';
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
