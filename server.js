'use strict';

const express      = require('express');
const crypto       = require('crypto');
const fs           = require('fs');
const path         = require('path');
const { Resend }   = require('resend');
const morgan       = require('morgan');

const { RateLimiter } = require('./lib/ratelimiter');

const app = express();

// ── Trust reverse proxy (nginx, Cloudflare, etc.) ──────────────────────────
app.set('trust proxy', 1);

// ── Request logging ──────────────────────────────────────────────────────────
app.use(morgan('combined'));

// ── Security headers ────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options',     'nosniff');
  res.setHeader('X-Frame-Options',            'DENY');
  res.setHeader('X-XSS-Protection',           '0');
  res.setHeader('Referrer-Policy',            'no-referrer');
  res.setHeader('Permissions-Policy',         'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy',   'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "font-src 'self'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "manifest-src 'self'",
      "worker-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ')
  );
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
  next();
});

// ── HTTPS redirect (production only) ───────────────────────────────────────
// Uses a configured HOST env var to avoid open-redirect via attacker-controlled Host header.
if (process.env.NODE_ENV === 'production' && process.env.HOST) {
  const CANONICAL_HOST = process.env.HOST; // e.g. "yourdomain.com"
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, `https://${CANONICAL_HOST}${req.url}`);
    }
    next();
  });
}

// ── Rate limiters (configurable via env for testing) ───────────────────────
const createLimiter = new RateLimiter(60_000,    parseInt(process.env.CREATE_RATE_LIMIT || '10',  10));
const readLimiter   = new RateLimiter(60_000,    parseInt(process.env.READ_RATE_LIMIT   || '30',  10));
const emailLimiter  = new RateLimiter(3_600_000, parseInt(process.env.EMAIL_RATE_LIMIT  || '3',   10));

// ── Blink Pro licensing (Lemon Squeezy) ─────────────────────────────────────
// Validated against the Lemon Squeezy license API. Results cached in memory.
// BLINK_PRO_DEV_KEY grants Pro locally for development/testing.
const LS_STORE_ID    = process.env.LS_STORE_ID   ? Number(process.env.LS_STORE_ID)   : null;
const LS_PRODUCT_ID  = process.env.LS_PRODUCT_ID ? Number(process.env.LS_PRODUCT_ID) : null;
const PRO_DEV_KEY    = process.env.BLINK_PRO_DEV_KEY || null;
const LICENSE_KEY_RE = /^[A-Za-z0-9-]{8,64}$/;
const LICENSE_CACHE_TTL = 3_600_000; // 1 hour
const licenseCache = new Map(); // key -> { valid, exp }

async function checkLicense(key) {
  if (typeof key !== 'string' || !LICENSE_KEY_RE.test(key)) return false;
  if (PRO_DEV_KEY && key === PRO_DEV_KEY) return true;

  const cached = licenseCache.get(key);
  if (cached && Date.now() < cached.exp) return cached.valid;

  let valid = false;
  try {
    const resp = await fetch('https://api.lemonsqueezy.com/v1/licenses/validate', {
      method:  'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body:    JSON.stringify({ license_key: key }),
    });
    const data   = await resp.json();
    const status = data?.license_key?.status;
    valid = data?.valid === true
      && status !== 'expired' && status !== 'disabled'
      && (!LS_STORE_ID   || data?.meta?.store_id   === LS_STORE_ID)
      && (!LS_PRODUCT_ID || data?.meta?.product_id === LS_PRODUCT_ID);
  } catch (err) {
    console.error('[license]', err.message);
    // Lemon Squeezy unreachable: honour a stale cache entry rather than lock out a paying user
    if (cached) return cached.valid;
    return false;
  }

  licenseCache.set(key, { valid, exp: Date.now() + LICENSE_CACHE_TTL });
  if (licenseCache.size > 5_000) {
    licenseCache.delete(licenseCache.keys().next().value);
  }
  return valid;
}

// ── Body parser ─────────────────────────────────────────────────────────────
// Pro uploads (25 MB files) need a larger body limit. The license is validated
// from the header BEFORE the large parser is chosen, so anonymous requests can
// never send more than the free-tier limit.
const jsonSmall = express.json({ limit: '4mb',  strict: true });
const jsonLarge = express.json({ limit: '40mb', strict: true });
app.use((req, res, next) => {
  const headerKey = req.headers['x-license-key'];
  if (!headerKey) {
    req.isPro = false;
    return jsonSmall(req, res, next);
  }
  checkLicense(String(headerKey).trim())
    .then(ok => {
      req.isPro = ok;
      return (ok ? jsonLarge : jsonSmall)(req, res, next);
    })
    .catch(next);
});

// ── Static files (HTML pages served no-store) ──────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  lastModified: true,
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
    }
  },
}));

// ── In-memory store ─────────────────────────────────────────────────────────
const secrets     = new Map();
const MAX_SECRETS      = 10_000;
const ALLOWED_TTL_HOURS     = new Set([1, 6, 24, 48]);
const ALLOWED_TTL_HOURS_PRO = new Set([1, 6, 24, 48, 168]);
const DEFAULT_TTL_HOURS = 48;
const MAX_VIEWS_PRO       = 5;
const PASSPHRASE_MIN_LEN  = 4;
const PASSPHRASE_MAX_LEN  = 128;
const MAX_AUTH_ATTEMPTS   = 5;

// ── Statistics ───────────────────────────────────────────────────────────────
const STATS_FILE = process.env.STATS_FILE || path.join(__dirname, 'data', 'stats.json');

const STATS_DEFAULTS = {
  secretsCreated:      0,
  secretsWithEmail:    0,
  emailsSent:          0,
  secretsRevealed:     0,
  secretsExpired:      0,
  secretsBruteForced:  0,
  otpFailures:         0,
};

let stats = { ...STATS_DEFAULTS };

try {
  fs.mkdirSync(path.dirname(STATS_FILE), { recursive: true });
  const raw = fs.readFileSync(STATS_FILE, 'utf8');
  stats = { ...STATS_DEFAULTS, ...JSON.parse(raw) };
} catch {}

function saveStats() {
  try {
    const tmp = STATS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(stats, null, 2));
    fs.renameSync(tmp, STATS_FILE);
  } catch (err) {
    console.error('[stats]', err.message);
  }
}

// Purge interval declared after stats so stats.secretsExpired is always initialised
const purge = setInterval(() => {
  const now = Date.now();
  for (const [id, s] of secrets) {
    if (now > s.expiresAt) {
      secrets.delete(id);
      stats.secretsExpired++;
    }
  }
}, 60_000);

const statsPersist = setInterval(saveStats, 60_000);
if (purge.unref) purge.unref();
if (statsPersist.unref) statsPersist.unref();

// ── Validators ──────────────────────────────────────────────────────────────
const UUID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const B64_RE   = /^[A-Za-z0-9+/]+=*$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
// AES-GCM IV must be 12 raw bytes → exactly 16 base-64 chars
const IV_B64_LEN  = 16;
// AES-256 key half (32 bytes) → exactly 44 base-64 chars
const K2_B64_LEN  = 44;
// AES-GCM output is always at least 16-byte auth tag → min 24 base-64 chars
const MIN_CT_LEN      = 24;
// Max plaintext 10 KB + 16-byte GCM tag → ≤ 13 720 base-64 chars
const MAX_CT_LEN      = 13_720;
// Max file 2 MB + 16-byte GCM tag → ≤ 2 796 224 base-64 chars
const MAX_FILE_CT_LEN = 2_796_224;
// Pro: max file 25 MB + 16-byte GCM tag → ≤ 34 952 556 base-64 chars
const MAX_FILE_CT_LEN_PRO = 34_952_556;
const MAX_FILENAME_LEN = 255;

// ── Startup checks ────────────────────────────────────────────────────────────
if (process.env.CIPHER_KEY && !/^[0-9a-f]{64}$/i.test(process.env.CIPHER_KEY)) {
  console.error('[error] CIPHER_KEY must be exactly 64 hex characters (32 bytes). Exiting.');
  process.exit(1);
}

// ── Server secrets (K3 + K4) ─────────────────────────────────────────────────
// K3: masks K2 in memory via HMAC — unique per secret, tied to its ID.
// K4: re-encrypts the ciphertext at rest — mandatory for any decryption.
// Neither key ever leaves the server or travels over any network.
const K3 = process.env.SECRET_KEY;
const K4 = process.env.CIPHER_KEY ? Buffer.from(process.env.CIPHER_KEY, 'hex') : null;

function deriveK3Mask(id) {
  return crypto.createHmac('sha256', K3).update(id).digest();
}

function encryptWithK4(ciphertextB64) {
  const ct  = Buffer.from(ciphertextB64, 'base64');
  const iv  = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', K4, iv);
  const enc = Buffer.concat([cipher.update(ct), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encCt: Buffer.concat([enc, tag]).toString('base64'),
    ctIv:  iv.toString('base64'),
  };
}

function decryptWithK4(encCtB64, ctIvB64) {
  const enc = Buffer.from(encCtB64, 'base64');
  const iv  = Buffer.from(ctIvB64,  'base64');
  const tag = enc.subarray(enc.length - 16);
  const ct  = enc.subarray(0, enc.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', K4, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('base64');
}

// ── Email client ─────────────────────────────────────────────────────────────
const resendClient = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// ── Server-side decrypt ──────────────────────────────────────────────────────
// K = K1 XOR K2. K1 comes from client (URL fragment), K2 stored masked with K3.
// K2_stored = K2 XOR HMAC(K3, id) at creation time.
// At reveal: key = K1 XOR K2_stored XOR HMAC(K3, id) = K1 XOR K2.
// Web Crypto AES-GCM output = ciphertext || 16-byte auth tag.
function serverDecrypt(ciphertextB64, ivB64, k1B64, k2StoredB64, id, raw = false) {
  const ct       = Buffer.from(ciphertextB64, 'base64');
  const iv       = Buffer.from(ivB64,         'base64');
  const k1       = Buffer.from(k1B64,         'base64');
  const k2Stored = Buffer.from(k2StoredB64,   'base64');
  const mask     = K3 ? deriveK3Mask(id) : Buffer.alloc(32);

  const key = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) key[i] = k1[i] ^ k2Stored[i] ^ mask[i];

  const authTag    = ct.subarray(ct.length - 16);
  const ciphertext = ct.subarray(0, ct.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const result = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return raw ? result : result.toString('utf8');
}

// ── Email (Resend) ───────────────────────────────────────────────────────────
async function sendOTPEmail(to, otp) {
  const { error } = await resendClient.emails.send({
    from:    process.env.EMAIL_FROM || 'Blink <noreply@malto.icu>',
    to,
    subject: 'Your Blink verification code',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#0B0E14;color:#E8EDF5;border-radius:12px;text-align:center">
        <table role="presentation" style="margin:0 auto 28px;border-collapse:collapse">
          <tr>
            <td style="vertical-align:middle;padding-right:10px">
              <img src="https://blink.malto.icu/logo.png" alt="Blink" style="width:44px;height:44px;display:block">
            </td>
            <td style="vertical-align:middle;text-align:left">
              <div style="color:#61cf5a;font-size:22px;font-weight:700;line-height:1.1">Blink</div>
              <div style="color:#7A8599;font-size:11px">by MALTO</div>
            </td>
          </tr>
        </table>
        <p style="margin:0 0 20px;font-size:15px">Someone shared a secret with you. Enter this code on the Blink page to reveal it:</p>
        <div style="font-size:40px;font-weight:700;letter-spacing:10px;text-align:center;padding:28px 24px;background:#131820;border-radius:10px;color:#61cf5a;font-family:monospace">${otp}</div>
        <p style="margin:24px 0 0;font-size:12px;color:#4A5468">This code can only be used once. If you were not expecting this, ignore this email.</p>
      </div>
    `,
  });
  if (error) throw new Error(error.message);
}

async function sendViewNotification(to, viewsLeft) {
  const remaining = viewsLeft > 0
    ? `It can be viewed ${viewsLeft} more time${viewsLeft === 1 ? '' : 's'} before it is destroyed.`
    : 'It has now been permanently deleted from the server.';
  const { error } = await resendClient.emails.send({
    from:    process.env.EMAIL_FROM || 'Blink <noreply@malto.icu>',
    to,
    subject: 'Your Blink secret was viewed',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#0B0E14;color:#E8EDF5;border-radius:12px;text-align:center">
        <table role="presentation" style="margin:0 auto 28px;border-collapse:collapse">
          <tr>
            <td style="vertical-align:middle;padding-right:10px">
              <img src="https://blink.malto.icu/logo.png" alt="Blink" style="width:44px;height:44px;display:block">
            </td>
            <td style="vertical-align:middle;text-align:left">
              <div style="color:#61cf5a;font-size:22px;font-weight:700;line-height:1.1">Blink</div>
              <div style="color:#7A8599;font-size:11px">by MALTO</div>
            </td>
          </tr>
        </table>
        <p style="margin:0 0 12px;font-size:15px">A secret you shared on Blink was just viewed.</p>
        <p style="margin:0;font-size:13px;color:#7A8599">${remaining}</p>
      </div>
    `,
  });
  if (error) throw new Error(error.message);
}

// ── POST /api/license/validate ──────────────────────────────────────────────
app.post('/api/license/validate', createLimiter.middleware(), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const key = typeof req.body?.licenseKey === 'string' ? req.body.licenseKey.trim() : '';
  const valid = await checkLicense(key);
  res.json({ valid });
});

// ── POST /api/secret ────────────────────────────────────────────────────────
app.post('/api/secret', createLimiter.middleware(), async (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid payload.' });
  }

  const {
    ciphertext, iv, k2, recipientEmail, expiresIn: expiresInRaw,
    isFile, filename: rawFilename, mimetype: rawMimetype,
    views: viewsRaw, passphrase: passphraseRaw, notifyEmail: notifyEmailRaw,
  } = body;

  const isPro = req.isPro === true;
  const isFileSecret = isFile === true;
  const maxCtLen = isFileSecret
    ? (isPro ? MAX_FILE_CT_LEN_PRO : MAX_FILE_CT_LEN)
    : MAX_CT_LEN;

  if (
    typeof ciphertext !== 'string' || typeof iv !== 'string' || typeof k2 !== 'string' ||
    !ciphertext || !iv || !k2 ||
    !B64_RE.test(iv) || !B64_RE.test(ciphertext) || !B64_RE.test(k2) ||
    iv.length !== IV_B64_LEN ||
    k2.length !== K2_B64_LEN ||
    ciphertext.length < MIN_CT_LEN ||
    ciphertext.length > maxCtLen
  ) {
    return res.status(400).json({ error: 'Invalid payload.' });
  }

  if (isFileSecret) {
    if (typeof rawFilename !== 'string' || !rawFilename.trim() || rawFilename.length > MAX_FILENAME_LEN) {
      return res.status(400).json({ error: 'Invalid filename.' });
    }
    if (typeof rawMimetype !== 'string' || !rawMimetype.trim() || rawMimetype.length > 127) {
      return res.status(400).json({ error: 'Invalid mimetype.' });
    }
  }

  if (secrets.size >= MAX_SECRETS) {
    return res.status(503).json({ error: 'Server is at capacity. Try again shortly.' });
  }

  // ── Pro-gated options ──
  let viewsAllowed = 1;
  if (viewsRaw !== undefined) {
    const v = Number(viewsRaw);
    if (!Number.isInteger(v) || v < 1 || v > MAX_VIEWS_PRO) {
      return res.status(400).json({ error: 'Invalid views value.' });
    }
    if (v > 1 && !isPro) {
      return res.status(403).json({ error: 'pro_required', feature: 'multi-view links' });
    }
    viewsAllowed = v;
  }

  let passHash = null;
  let passSalt = null;
  if (passphraseRaw !== undefined) {
    if (!isPro) {
      return res.status(403).json({ error: 'pro_required', feature: 'passphrase protection' });
    }
    if (typeof passphraseRaw !== 'string' ||
        passphraseRaw.length < PASSPHRASE_MIN_LEN || passphraseRaw.length > PASSPHRASE_MAX_LEN) {
      return res.status(400).json({ error: `Passphrase must be ${PASSPHRASE_MIN_LEN}-${PASSPHRASE_MAX_LEN} characters.` });
    }
    passSalt = crypto.randomBytes(16);
    passHash = crypto.scryptSync(passphraseRaw, passSalt, 32);
  }

  let notifyEmail = null;
  if (notifyEmailRaw !== undefined) {
    if (!isPro) {
      return res.status(403).json({ error: 'pro_required', feature: 'view notifications' });
    }
    if (!resendClient) {
      return res.status(503).json({ error: 'Email is not configured on this server.' });
    }
    if (typeof notifyEmailRaw !== 'string' || !EMAIL_RE.test(notifyEmailRaw)) {
      return res.status(400).json({ error: 'Invalid notification email address.' });
    }
    notifyEmail = notifyEmailRaw;
  }

  if (Number(expiresInRaw) === 168 && !isPro) {
    return res.status(403).json({ error: 'pro_required', feature: '7-day expiry' });
  }

  let otpHash = null;
  if (recipientEmail !== undefined) {
    if (!resendClient) {
      return res.status(503).json({ error: 'Email verification is not configured on this server.' });
    }
    if (typeof recipientEmail !== 'string' || !EMAIL_RE.test(recipientEmail)) {
      return res.status(400).json({ error: 'Invalid email address.' });
    }
    const emailRetryAfter = emailLimiter.check(req.ip);
    if (emailRetryAfter > 0) {
      res.setHeader('Retry-After', String(emailRetryAfter));
      return res.status(429).json({ error: 'Too many verification emails. Try again in an hour.' });
    }

    const otp = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    otpHash   = crypto.createHash('sha256').update(otp).digest('hex');
    try {
      await sendOTPEmail(recipientEmail, otp);
      stats.emailsSent++;
    } catch (err) {
      console.error('[email]', err.message);
      return res.status(500).json({ error: 'Failed to send verification email. Please try again.' });
    }
  }

  const allowedTtl = isPro ? ALLOWED_TTL_HOURS_PRO : ALLOWED_TTL_HOURS;
  const expiresInHours = allowedTtl.has(Number(expiresInRaw)) ? Number(expiresInRaw) : DEFAULT_TTL_HOURS;
  const id        = crypto.randomUUID();
  const expiresAt = Date.now() + expiresInHours * 3_600_000;

  // Apply K3 mask to K2 before storage: k2Stored = K2 XOR HMAC(K3, id)
  let k2Stored = k2;
  if (K3) {
    const mask     = deriveK3Mask(id);
    const k2Buf    = Buffer.from(k2, 'base64');
    const maskedBuf = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) maskedBuf[i] = k2Buf[i] ^ mask[i];
    k2Stored = maskedBuf.toString('base64');
  }

  // Wrap ciphertext with K4 before storage — K4 is mandatory for any decryption
  let storedCt = ciphertext;
  let ctIv     = null;
  if (K4) {
    ({ encCt: storedCt, ctIv } = encryptWithK4(ciphertext));
  }

  const filename = isFileSecret ? rawFilename.trim() : null;
  const mimetype = isFileSecret ? rawMimetype.trim() : null;
  secrets.set(id, {
    ciphertext: storedCt, ctIv, iv, k2: k2Stored, expiresAt,
    otpHash, otpAttempts: 0,
    isFile: isFileSecret, filename, mimetype,
    viewsLeft: viewsAllowed,
    passHash: passHash ? passHash.toString('hex') : null,
    passSalt: passSalt ? passSalt.toString('hex') : null,
    passAttempts: 0,
    notifyEmail,
  });

  stats.secretsCreated++;
  if (otpHash) stats.secretsWithEmail++;

  res.status(201).json({ id });
});

// ── GET /api/secret/:id ─────────────────────────────────────────────────────
app.get('/api/secret/:id', readLimiter.middleware(), (req, res) => {
  const { id } = req.params;

  if (!UUID_RE.test(id)) {
    return res.status(400).json({ error: 'Invalid identifier.' });
  }

  const k1B64 = (req.headers['x-key'] || '').trim();
  if (!k1B64 || k1B64.length !== K2_B64_LEN || !B64_RE.test(k1B64)) {
    return res.status(400).json({ error: 'Missing or invalid key.' });
  }

  res.setHeader('Cache-Control', 'no-store');

  const secret = secrets.get(id);
  if (!secret) {
    return res.status(404).json({ error: 'not_found' });
  }

  if (Date.now() > secret.expiresAt) {
    secrets.delete(id);
    return res.status(410).json({ error: 'expired' });
  }

  // Passphrase verification (Pro)
  if (secret.passHash) {
    const rawHeader = (req.headers['x-passphrase'] || '').trim();
    if (!rawHeader) {
      return res.status(403).json({ error: 'passphrase_required' });
    }
    let pass = '';
    try { pass = decodeURIComponent(rawHeader); } catch { pass = rawHeader; }
    const inputHash = crypto.scryptSync(
      pass.slice(0, PASSPHRASE_MAX_LEN),
      Buffer.from(secret.passSalt, 'hex'),
      32
    );
    const passValid = crypto.timingSafeEqual(Buffer.from(secret.passHash, 'hex'), inputHash);
    if (!passValid) {
      secret.passAttempts++;
      if (secret.passAttempts >= MAX_AUTH_ATTEMPTS) {
        secrets.delete(id);
        stats.secretsBruteForced++;
        return res.status(410).json({ error: 'too_many_attempts' });
      }
      return res.status(403).json({ error: 'invalid_passphrase', attemptsLeft: MAX_AUTH_ATTEMPTS - secret.passAttempts });
    }
  }

  // OTP verification
  if (secret.otpHash) {
    const otp = (req.headers['x-otp'] || '').trim();
    if (!otp) {
      return res.status(403).json({ error: 'otp_required' });
    }
    if (!/^\d{6}$/.test(otp)) {
      return res.status(403).json({ error: 'invalid_otp' });
    }
    const inputHash = crypto.createHash('sha256').update(otp).digest('hex');
    const valid     = crypto.timingSafeEqual(
      Buffer.from(secret.otpHash, 'hex'),
      Buffer.from(inputHash,      'hex')
    );
    if (!valid) {
      secret.otpAttempts++;
      stats.otpFailures++;
      if (secret.otpAttempts >= 5) {
        secrets.delete(id);
        stats.secretsBruteForced++;
        return res.status(410).json({ error: 'too_many_attempts' });
      }
      return res.status(403).json({ error: 'invalid_otp', attemptsLeft: 5 - secret.otpAttempts });
    }
  }

  // Reconstruct key, decrypt, consume one view
  try {
    const rawCt = (K4 && secret.ctIv) ? decryptWithK4(secret.ciphertext, secret.ctIv) : secret.ciphertext;

    let payload;
    if (secret.isFile) {
      const fileBuf = serverDecrypt(rawCt, secret.iv, k1B64, secret.k2, id, true);
      payload = { data: fileBuf.toString('base64'), filename: secret.filename, mimetype: secret.mimetype };
    } else {
      payload = { plaintext: serverDecrypt(rawCt, secret.iv, k1B64, secret.k2, id) };
    }

    // Multi-view (Pro): only destroy once all allowed views are consumed
    secret.viewsLeft = (secret.viewsLeft ?? 1) - 1;
    const viewsLeft = secret.viewsLeft;
    if (viewsLeft <= 0) {
      secrets.delete(id);
    }
    stats.secretsRevealed++;

    if (secret.notifyEmail && resendClient) {
      sendViewNotification(secret.notifyEmail, viewsLeft)
        .then(() => { stats.emailsSent++; })
        .catch(err => console.error('[email]', err.message));
    }

    payload.viewsLeft = viewsLeft;
    res.json(payload);
  } catch {
    return res.status(400).json({ error: 'Decryption failed. The link may be corrupted.' });
  }
});

// ── GET /api/config ──────────────────────────────────────────────────────────
// Public frontend configuration. The checkout URL is not a secret (it is a
// public payment page) — env keeps it configurable per deployment.
app.get('/api/config', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ proCheckoutUrl: process.env.PRO_CHECKOUT_URL || null });
});

// ── GET /api/stats ───────────────────────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ secretsCreated: stats.secretsCreated });
});

// ── About page ───────────────────────────────────────────────────────────────
app.get('/about', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'about.html'));
});

// ── View page ────────────────────────────────────────────────────────────────
app.get('/view/:id', (req, res) => {
  if (!UUID_RE.test(req.params.id)) return res.redirect('/');
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

// ── 404 ─────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// ── Global error handler ────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  if (err.type === 'entity.too.large' || err.status === 413) {
    return res.status(413).json({ error: 'Payload too large.' });
  }
  if (err.status && err.status >= 400 && err.status < 500) {
    return res.status(err.status).json({ error: 'Invalid request.' });
  }
  console.error('[error]', err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Startup checks ────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'test') {
  if (!process.env.SECRET_KEY) {
    console.warn('[warn] SECRET_KEY not set — K3 HMAC binding is disabled (K2 stored unmasked)');
  }
  if (!process.env.CIPHER_KEY) {
    console.warn('[warn] CIPHER_KEY not set — K4 ciphertext encryption is disabled');
  }
  if (!process.env.RESEND_API_KEY) {
    console.warn('[warn] RESEND_API_KEY not set — email OTP feature is disabled');
  }
  if (!process.env.LS_STORE_ID || !process.env.LS_PRODUCT_ID) {
    console.warn('[warn] LS_STORE_ID / LS_PRODUCT_ID not set — Lemon Squeezy keys from ANY store would validate; Pro effectively limited to BLINK_PRO_DEV_KEY');
  }
  if (process.env.NODE_ENV === 'production' && !process.env.HOST) {
    console.warn('[warn] HOST not set — HTTPS redirect will not work in production');
  }
}

// ── Start ────────────────────────────────────────────────────────────────────
if (require.main === module) {
  const PORT   = parseInt(process.env.PORT || '3000', 10);
  const server = app.listen(PORT, () => {
    console.log(`Blink listening on port ${PORT}  [${process.env.NODE_ENV || 'development'}]`);
  });

  // ── Graceful shutdown ────────────────────────────────────────────────────────
  const shutdown = (signal) => {
    console.log(`${signal}: shutting down`);
    saveStats();
    server.close(() => {
      secrets.clear();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 5_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
}

module.exports = { app };
