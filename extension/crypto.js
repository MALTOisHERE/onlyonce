// Byte-for-byte mirror of public/app.js's encryptSecret(): any link created
// here must decrypt correctly on blink.malto.icu/view/:id, so this logic is
// intentionally kept in lockstep with the website's implementation.

// Loop-based base64, avoids stack overflow from spread on large arrays.
function blinkToB64(arr) {
  let str = '';
  for (let i = 0; i < arr.length; i++) str += String.fromCharCode(arr[i]);
  return btoa(str);
}

async function blinkEncryptSecret(text) {
  const encoded = new TextEncoder().encode(text);
  if (encoded.length > BLINK_MAX_SECRET_BYTES) {
    throw new RangeError('Secret is too large. Maximum size is 10 KB.');
  }
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
  );
  const iv            = crypto.getRandomValues(new Uint8Array(12));
  const ciphertextBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const rawKey        = new Uint8Array(await crypto.subtle.exportKey('raw', key));

  // Split key: K = K1 XOR K2. K1 goes in the URL fragment, K2 goes to the
  // server. Neither half alone can decrypt; the server must participate
  // in every reveal.
  const k1 = crypto.getRandomValues(new Uint8Array(32));
  const k2 = new Uint8Array(32);
  for (let i = 0; i < 32; i++) k2[i] = rawKey[i] ^ k1[i];

  return {
    ciphertext: blinkToB64(new Uint8Array(ciphertextBuf)),
    iv:         blinkToB64(iv),
    k1:         blinkToB64(k1),
    k2:         blinkToB64(k2),
  };
}

async function blinkCreateLink(text, ttlHours = BLINK_DEFAULT_TTL_HOURS) {
  const { ciphertext, iv, k1, k2 } = await blinkEncryptSecret(text);
  const resp = await fetch(`${BLINK_API_BASE}/api/secret`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ ciphertext, iv, k2, expiresIn: ttlHours }),
  });
  if (!resp.ok) {
    if (resp.status === 429) throw new Error('Too many requests. Please wait a moment and try again.');
    const data = await resp.json().catch(() => ({}));
    throw new Error(data.error || `Request failed (${resp.status}).`);
  }
  const { id } = await resp.json();
  return `${BLINK_API_BASE}/view/${id}#${encodeURIComponent(k1)}`;
}

// Rejection-sampling to eliminate modulo bias, mirrors app.js's generator.
function blinkGeneratePassword(length, charset) {
  const csLen  = charset.length;
  const maxVal = 256 - (256 % csLen);
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
