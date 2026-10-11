(() => {
  // ── Footer version ──────────────────────────────────────────────────────
  document.getElementById('ext-version').textContent = `v${chrome.runtime.getManifest().version}`;

  // ── Tabs ─────────────────────────────────────────────────────────────────
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
    });
  });

  // ── Create link ──────────────────────────────────────────────────────────
  const secretInput  = document.getElementById('secret-input');
  const byteCounter  = document.getElementById('byte-counter');
  const btnCreate     = document.getElementById('btn-create');
  const createError   = document.getElementById('create-error');
  const resultBox      = document.getElementById('result');
  const linkOutput    = document.getElementById('link-output');

  secretInput.addEventListener('input', () => {
    const bytes = new TextEncoder().encode(secretInput.value).length;
    byteCounter.textContent = `${(bytes / 1024).toFixed(1)} / 10 KB`;
  });

  function showCreateError(msg) {
    createError.textContent = msg;
    createError.classList.remove('hidden');
  }
  function hideCreateError() {
    createError.classList.add('hidden');
  }

  btnCreate.addEventListener('click', async () => {
    const text = secretInput.value;
    if (!text.trim()) {
      showCreateError('Please enter a secret first.');
      return;
    }
    hideCreateError();
    resultBox.classList.add('hidden');
    btnCreate.disabled = true;
    btnCreate.textContent = 'Encrypting…';

    try {
      const ttlHours = document.querySelector('input[name="expiry"]:checked').value;
      const link = await blinkCreateLinkWithTtl(text, ttlHours);
      linkOutput.value = link;
      resultBox.classList.remove('hidden');
      secretInput.value = '';
      byteCounter.textContent = '0.0 / 10 KB';
    } catch (err) {
      showCreateError(err.message || 'Something went wrong. Please try again.');
    } finally {
      btnCreate.disabled = false;
      btnCreate.textContent = 'Encrypt & create link';
    }
  });

  // blinkCreateLink() (crypto.js) hardcodes the site's 48h default; the
  // popup lets the user pick, so swap the body's expiresIn after encrypting.
  async function blinkCreateLinkWithTtl(text, ttlHours) {
    const { ciphertext, iv, k1, k2 } = await blinkEncryptSecret(text);
    const resp = await fetch(`${BLINK_API_BASE}/api/secret`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ ciphertext, iv, k2, expiresIn: parseInt(ttlHours, 10) }),
    });
    if (!resp.ok) {
      if (resp.status === 429) throw new Error('Too many requests. Please wait a moment and try again.');
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error || `Request failed (${resp.status}).`);
    }
    const { id } = await resp.json();
    return `${BLINK_API_BASE}/view/${id}#${encodeURIComponent(k1)}`;
  }

  document.getElementById('btn-copy-link').addEventListener('click', async () => {
    await navigator.clipboard.writeText(linkOutput.value);
    flashCopied('btn-copy-link');
  });

  function flashCopied(id) {
    const btn = document.getElementById(id);
    const original = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = original; }, 1200);
  }

  // ── Password generator ──────────────────────────────────────────────────
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

  function calcStrength(pwd) {
    let score = 0;
    if (pwd.length >= 10) score++;
    if (pwd.length >= 16) score++;
    if (pwd.length >= 24) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[a-z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    if (score <= 2) return { label: 'Weak',        pct: '20%',  color: '#ef4444' };
    if (score <= 3) return { label: 'Fair',        pct: '45%',  color: '#F5A623' };
    if (score <= 4) return { label: 'Good',        pct: '68%',  color: '#61cf5a' };
    if (score <= 5) return { label: 'Strong',      pct: '85%',  color: '#61cf5a' };
    return                 { label: 'Very Strong', pct: '100%', color: '#00D4AA' };
  }

  const lengthSlider = document.getElementById('length-slider');
  const lengthValue  = document.getElementById('length-value');
  const genPreview   = document.getElementById('gen-preview');
  const strengthFill  = document.getElementById('strength-fill');
  const strengthLabel = document.getElementById('strength-label');

  function regenerate() {
    const length  = parseInt(lengthSlider.value, 10);
    const charset = buildCharset();
    const pwd     = blinkGeneratePassword(length, charset);
    genPreview.value = pwd;
    const { label, pct, color } = calcStrength(pwd);
    strengthFill.style.width = pct;
    strengthFill.style.background = color;
    strengthLabel.textContent = label;
  }

  lengthSlider.addEventListener('input', () => {
    lengthValue.textContent = lengthSlider.value;
    regenerate();
  });
  ['opt-upper', 'opt-lower', 'opt-numbers', 'opt-symbols'].forEach(id => {
    document.getElementById(id).addEventListener('change', regenerate);
  });
  document.getElementById('btn-regen').addEventListener('click', regenerate);

  document.getElementById('btn-copy-pwd').addEventListener('click', async () => {
    if (!genPreview.value) return;
    await navigator.clipboard.writeText(genPreview.value);
    flashCopied('btn-copy-pwd');
  });

  document.getElementById('btn-use-as-secret').addEventListener('click', () => {
    if (!genPreview.value) return;
    secretInput.value = genPreview.value;
    secretInput.dispatchEvent(new Event('input'));
    document.querySelector('.tab[data-tab="create"]').click();
    secretInput.focus();
  });

  regenerate();
})();
