'use strict';

const express      = require('express');
const crypto       = require('crypto');
const path         = require('path');
const { Resend }   = require('resend');

const app = express();

// ── Trust reverse proxy (nginx, Cloudflare, etc.) ──────────────────────────
app.set('trust proxy', 1);

// ── Security headers ────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options',     'nosniff');
  res.setHeader('X-Frame-Options',            'DENY');
  res.setHeader('X-XSS-Protection',           '0');
  res.setHeader('Referrer-Policy',            'no-referrer');
  res.setHeader('Permissions-Policy',         'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src https://fonts.gstatic.com",
      "img-src 'self' data:",
      "connect-src 'self'",
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

// ── Rate limiter (fixed-window, no external deps) ──────────────────────────
class RateLimiter {
  constructor(windowMs, max) {
    this.windowMs = windowMs;
    this.max      = max;
    this.store    = new Map();
    const t = setInterval(() => {
      const now = Date.now();
      for (const [k, v] of this.store) {
        if (v.resetAt < now) this.store.delete(k);
      }
    }, windowMs);
    if (t.unref) t.unref();
  }

  // Returns retry-after seconds if limited, 0 if allowed
  check(ip) {
    const key = ip || '0.0.0.0';
    const now = Date.now();
    let e = this.store.get(key);
    if (!e || now >= e.resetAt) {
      e = { count: 0, resetAt: now + this.windowMs };
      this.store.set(key, e);
    }
    e.count++;
    if (e.count > this.max) {
      return Math.ceil((e.resetAt - now) / 1000);
    }
    return 0;
  }

  middleware() {
    return (req, res, next) => {
      const retryAfter = this.check(req.ip);
      if (retryAfter > 0) {
        res.setHeader('Retry-After', String(retryAfter));
        return res.status(429).json({ error: 'Too many requests. Please slow down.' });
      }
      next();
    };
  }
}

const createLimiter = new RateLimiter(60_000,      10);  // 10 creates  / min  per IP
const readLimiter   = new RateLimiter(60_000,      30);  // 30 reads    / min  per IP
const emailLimiter  = new RateLimiter(3_600_000,    3);  //  3 OTP emails / hour per IP

// ── Body parser ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '16kb', strict: true }));

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
const MAX_SECRETS = 10_000;
const TTL_MS      = 48 * 60 * 60 * 1000; // 48 hours

const purge = setInterval(() => {
  const now = Date.now();
  for (const [id, s] of secrets) {
    if (now > s.expiresAt) secrets.delete(id);
  }
}, 60_000);
if (purge.unref) purge.unref();

// ── Validators ──────────────────────────────────────────────────────────────
const UUID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const B64_RE   = /^[A-Za-z0-9+/]+=*$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
// AES-GCM IV must be 12 raw bytes → exactly 16 base-64 chars
const IV_B64_LEN = 16;
// Max plaintext 10 KB + 16-byte GCM tag → ≤ 13 720 base-64 chars
const MAX_CT_LEN = 13_720;

// ── Email (Resend) ───────────────────────────────────────────────────────────
async function sendOTPEmail(to, otp) {
  const resend = new Resend(process.env.RESEND_API_KEY);
  const { error } = await resend.emails.send({
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

// ── POST /api/secret ────────────────────────────────────────────────────────
app.post('/api/secret', createLimiter.middleware(), async (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid payload.' });
  }

  const { ciphertext, iv, recipientEmail } = body;

  if (
    typeof ciphertext !== 'string' || typeof iv !== 'string' ||
    !ciphertext || !iv ||
    !B64_RE.test(iv) || !B64_RE.test(ciphertext) ||
    iv.length !== IV_B64_LEN ||
    ciphertext.length > MAX_CT_LEN
  ) {
    return res.status(400).json({ error: 'Invalid payload.' });
  }

  if (secrets.size >= MAX_SECRETS) {
    return res.status(503).json({ error: 'Server is at capacity. Try again shortly.' });
  }

  let otpHash = null;
  if (recipientEmail !== undefined) {
    if (!process.env.RESEND_API_KEY) {
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
    } catch (err) {
      console.error('[email]', err.message);
      return res.status(500).json({ error: 'Failed to send verification email. Please try again.' });
    }
  }

  const id        = crypto.randomUUID();
  const expiresAt = Date.now() + TTL_MS;
  secrets.set(id, { ciphertext, iv, expiresAt, otpHash, otpAttempts: 0 });

  res.status(201).json({ id });
});

// ── GET /api/secret/:id ─────────────────────────────────────────────────────
app.get('/api/secret/:id', readLimiter.middleware(), (req, res) => {
  const { id } = req.params;

  if (!UUID_RE.test(id)) {
    return res.status(400).json({ error: 'Invalid identifier.' });
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
      if (secret.otpAttempts >= 5) {
        secrets.delete(id);
        return res.status(410).json({ error: 'too_many_attempts' });
      }
      return res.status(403).json({ error: 'invalid_otp', attemptsLeft: 5 - secret.otpAttempts });
    }
  }

  // Consume the secret atomically before responding
  const payload = { ciphertext: secret.ciphertext, iv: secret.iv };
  secrets.delete(id);
  res.json(payload);
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
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  console.error('[error]', err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Start ────────────────────────────────────────────────────────────────────
const PORT   = parseInt(process.env.PORT || '3000', 10);
const server = app.listen(PORT, () => {
  console.log(`Blink listening on port ${PORT}  [${process.env.NODE_ENV || 'development'}]`);
});

// ── Graceful shutdown ────────────────────────────────────────────────────────
function shutdown(signal) {
  console.log(`${signal} — shutting down`);
  server.close(() => {
    secrets.clear();
    process.exit(0);
  });
  // Force-kill if server hasn't closed within 5 s
  setTimeout(() => process.exit(1), 5_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
