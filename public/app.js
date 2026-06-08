(() => {
  const MAX_SECRET_BYTES = 10 * 1024; // 10 KB

  // ── Tab switching ──────────────────────────────────────────────────────────
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
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
    const rawKey        = await crypto.subtle.exportKey('raw', key);
    return {
      ciphertext: toB64(new Uint8Array(ciphertextBuf)),
      iv:         toB64(iv),
      key:        toB64(new Uint8Array(rawKey)),
    };
  }

  // ── Create link ────────────────────────────────────────────────────────────
  const btnCreate = document.getElementById('btn-create');
  const BTN_HTML  = `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Encrypt &amp; Create Link`;

  btnCreate.addEventListener('click', async () => {
    const activeTab = document.querySelector('.tab.active').dataset.tab;
    let secret = '';

    if (activeTab === 'enter') {
      secret = document.getElementById('secret-input').value.trim();
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
      const { ciphertext, iv, key } = await encryptSecret(secret);
      const expires = document.getElementById('opt-expires').checked;

      const res = await fetch('/api/secret', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ ciphertext, iv, expires }),
      });

      if (res.status === 429) {
        showError('Too many requests. Please wait a moment and try again.');
        return;
      }
      if (res.status === 503) {
        showError('Server is at capacity right now. Please try again shortly.');
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const { id, expiresAt } = await res.json();

      const viewUrl = `${window.location.origin}/view/${id}#${encodeURIComponent(key)}`;
      document.getElementById('link-output').value = viewUrl;
      document.getElementById('result').classList.remove('hidden');

      // Clear plaintext from the input so it's not left in the DOM
      document.getElementById('secret-input').value = '';
      document.getElementById('gen-preview').value  = '';

      const warnExpiry = document.getElementById('warn-expiry');
      if (expiresAt) {
        warnExpiry.style.display = '';
        startCountdown(expiresAt, document.getElementById('countdown'));
      } else {
        warnExpiry.style.display = 'none';
      }

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

  function showError(msg) {
    const el = document.getElementById('error-banner');
    // Use innerHTML only for the hardcoded SVG; set msg via textContent to prevent XSS (F-10)
    el.innerHTML = WARN_ICON_HTML + '<span></span>';
    el.querySelector('span').textContent = msg;
    el.classList.add('show');
  }

  function hideError() {
    document.getElementById('error-banner').classList.remove('show');
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

  // Countdown driven by server-issued expiresAt timestamp (F-14)
  function startCountdown(expiresAt, el) {
    const tick = () => {
      const remaining = Math.ceil((expiresAt - Date.now()) / 1000);
      if (remaining <= 0) {
        el.textContent = 'expired';
        return;
      }
      const m = Math.floor(remaining / 60);
      const s = remaining % 60;
      el.textContent = `${m}:${s.toString().padStart(2, '0')}`;
      setTimeout(tick, 500);
    };
    tick();
  }
})();
