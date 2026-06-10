(() => {
  // RFC 4122 UUID v4 pattern
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  // AES-GCM IV must decode to exactly 12 bytes
  const IV_DECODED_LEN = 12;

  function setState(id) {
    document.querySelectorAll('.view-state').forEach(el => el.classList.remove('active'));
    document.getElementById(id).classList.add('active');
  }

  // Safe base64 decode — throws on invalid input (F-08)
  function fromB64(str) {
    try {
      return Uint8Array.from(atob(decodeURIComponent(str)), c => c.charCodeAt(0));
    } catch {
      throw new TypeError('Malformed base-64 data.');
    }
  }

  async function decryptSecret(ciphertextB64, ivB64, keyB64) {
    const ivBytes  = fromB64(ivB64);
    const keyBytes = fromB64(keyB64);
    const ctBytes  = fromB64(ciphertextB64);

    if (ivBytes.length !== IV_DECODED_LEN) {
      throw new TypeError(`Invalid IV length: expected ${IV_DECODED_LEN}, got ${ivBytes.length}.`);
    }

    const key = await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes }, key, ctBytes
    );
    return new TextDecoder().decode(decrypted);
  }

  function showExpired(title, msg) {
    document.getElementById('expired-title').textContent = title;
    document.getElementById('expired-msg').textContent   = msg;
    setState('state-expired');
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

  async function revealSecret(id, keyB64, otp = null) {
    try {
      const headers = {};
      if (otp) headers['X-OTP'] = otp;
      const res = await fetch(`/api/secret/${id}`, { headers });

      if (res.status === 403) {
        const data = await res.json();
        if (data.error === 'otp_required') {
          setState('state-otp');
          setupOTP(id, keyB64);
          return;
        }
        if (data.error === 'invalid_otp') {
          setState('state-otp');
          document.getElementById('otp-error').classList.remove('hidden');
          document.getElementById('otp-input').value = '';
          document.getElementById('otp-input').focus();
          setupOTP(id, keyB64);
          return;
        }
      }
      if (res.status === 404) {
        showExpired('Secret Not Found', 'This secret has already been viewed, has expired, or the link is invalid. Ask the sender to create a new one.');
        return;
      }
      if (res.status === 410) {
        showExpired('Link Expired', 'This link has expired. Ask the sender to create a fresh link.');
        return;
      }
      if (res.status === 429) {
        showExpired('Too Many Requests', 'You have made too many requests. Please wait a moment and try again.');
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const { ciphertext, iv } = await res.json();
      const plaintext = await decryptSecret(ciphertext, iv, keyB64);

      history.replaceState(null, '', window.location.pathname);
      showSecret(plaintext);
    } catch (err) {
      showExpired('Something Went Wrong', 'Could not retrieve or decrypt the secret. The link may be malformed or have been tampered with.');
    }
  }

  function setupOTP(id, keyB64) {
    const btn   = document.getElementById('btn-otp-submit');
    const input = document.getElementById('otp-input');
    input.focus();
    const clone = btn.cloneNode(true); // remove any prior listeners
    btn.parentNode.replaceChild(clone, btn);
    clone.addEventListener('click', () => {
      const otp = input.value.trim();
      if (otp.length !== 6) return;
      document.getElementById('otp-error').classList.add('hidden');
      setState('state-loading');
      revealSecret(id, keyB64, otp);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') clone.click();
    }, { once: true });
  }

  function init() {
    const pathParts = window.location.pathname.split('/');
    const id        = pathParts[pathParts.length - 1];
    const keyB64    = window.location.hash.slice(1);

    // Validate UUID format before hitting the server (F-05)
    if (!id || !UUID_RE.test(id)) {
      showExpired('Invalid Link', 'The link format is invalid.');
      return;
    }

    if (!keyB64) {
      showExpired('Invalid Link', 'This link is missing the decryption key.');
      return;
    }

    setState('state-reveal');

    document.getElementById('btn-reveal').addEventListener('click', () => {
      setState('state-loading');
      revealSecret(id, keyB64);
    }, { once: true });
  }

  init();
})();
