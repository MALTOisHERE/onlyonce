(() => {
  const UUID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const K1_B64_RE = /^[A-Za-z0-9+/]{43}=$/;

  function setState(id) {
    document.querySelectorAll('.view-state').forEach(el => el.classList.remove('active'));
    document.getElementById(id).classList.add('active');
  }

  function showExpired(title, msg) {
    document.getElementById('expired-title').textContent = title;
    document.getElementById('expired-msg').textContent   = msg;
    setState('state-expired');
  }

  function showFile(dataB64, filename, mimetype) {
    document.getElementById('file-reveal-name').textContent = filename;
    setState('state-file');

    document.getElementById('btn-download-file').onclick = () => {
      const bytes = atob(dataB64);
      const arr = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
      const blob = new Blob([arr], { type: mimetype });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    };
  }

  function showSecret(plaintext) {
    document.getElementById('secret-text').value = plaintext;
    setState('state-secret');

    // Defined once, not re-attached on repeated calls (F-19)
    const copyBtn = document.getElementById('btn-copy-secret');
    const COPY_HTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy to Clipboard`;

    copyBtn.onclick = () => {
      navigator.clipboard.writeText(plaintext).then(() => {
        copyBtn.textContent = 'Copied!';
        copyBtn.classList.add('copied');
        setTimeout(() => {
          copyBtn.innerHTML = COPY_HTML;
          copyBtn.classList.remove('copied');
        }, 2000);
      }).catch(() => {
        // Clipboard unavailable — select the textarea as fallback
        document.getElementById('secret-text').select();
      });
    };
  }

  async function revealSecret(id, k1B64, otp = null, onDone = null) {
    try {
      const headers = { 'X-Key': k1B64 };
      if (otp) headers['X-OTP'] = otp;
      const res = await fetch(`/api/secret/${id}`, { headers });

      if (res.status === 403) {
        const data = await res.json();
        if (data.error === 'otp_required') {
          setState('state-otp');
          setupOTP(id, k1B64, onDone);
          return;
        }
        if (data.error === 'invalid_otp') {
          setState('state-otp');
          const errEl = document.getElementById('otp-error');
          errEl.textContent = data.attemptsLeft === 1
            ? 'Invalid code. 1 attempt remaining.'
            : `Invalid code. ${data.attemptsLeft} attempts remaining.`;
          errEl.classList.remove('hidden');
          document.getElementById('otp-input').value = '';
          document.getElementById('otp-input').focus();
          setupOTP(id, k1B64, onDone);
          return;
        }
      }
      if (res.status === 404) {
        onDone?.();
        showExpired('Secret Not Found', 'This secret has already been viewed, has expired, or the link is invalid. Ask the sender to create a new one.');
        return;
      }
      if (res.status === 410) {
        onDone?.();
        const data = await res.json().catch(() => ({}));
        if (data.error === 'too_many_attempts') {
          showExpired('Secret Destroyed', 'Too many incorrect codes. The secret has been permanently deleted for security.');
        } else {
          showExpired('Link Expired', 'This link has expired. Ask the sender to create a fresh link.');
        }
        return;
      }
      if (res.status === 429) {
        showExpired('Too Many Requests', 'You have made too many requests. Please wait a moment and try again.');
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const data = await res.json();
      onDone?.();
      if (data.data !== undefined) {
        showFile(data.data, data.filename, data.mimetype);
      } else {
        showSecret(data.plaintext);
      }
    } catch (err) {
      onDone?.();
      showExpired('Something Went Wrong', 'Could not retrieve or decrypt the secret. The link may be malformed or have been tampered with.');
    }
  }

  function setupOTP(id, k1B64, onDone = null) {
    const btn   = document.getElementById('btn-otp-submit');
    const input = document.getElementById('otp-input');
    input.focus();
    const clone = btn.cloneNode(true);
    btn.parentNode.replaceChild(clone, btn);
    clone.addEventListener('click', () => {
      const otp = input.value.trim();
      if (otp.length !== 6) return;
      document.getElementById('otp-error').classList.add('hidden');
      setState('state-loading');
      revealSecret(id, k1B64, otp, onDone);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') clone.click();
    }, { once: true });
  }

  function init() {
    const pathParts = window.location.pathname.split('/');
    const id        = pathParts[pathParts.length - 1];
    const SESS_KEY  = `blink_k1_${id}`;

    // Read K1 from URL hash. If the page was refreshed (hash already stripped),
    // fall back to sessionStorage so OTP users don't lose access mid-flow.
    let k1B64 = decodeURIComponent(window.location.hash.slice(1));
    if (k1B64 && K1_B64_RE.test(k1B64)) {
      try { sessionStorage.setItem(SESS_KEY, k1B64); } catch {}
      history.replaceState(null, '', window.location.pathname);
    } else {
      try { k1B64 = sessionStorage.getItem(SESS_KEY) || ''; } catch {}
    }

    if (!id || !UUID_RE.test(id)) {
      showExpired('Invalid Link', 'The link format is invalid.');
      return;
    }

    if (!k1B64 || !K1_B64_RE.test(k1B64)) {
      showExpired('Invalid Link', 'This link is missing or has a corrupted key.');
      return;
    }

    const clearK1 = () => { try { sessionStorage.removeItem(SESS_KEY); } catch {} };

    setState('state-reveal');

    document.getElementById('btn-reveal').addEventListener('click', () => {
      setState('state-loading');
      revealSecret(id, k1B64, null, clearK1);
    }, { once: true });
  }

  init();
})();
