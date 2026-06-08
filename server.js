'use strict';

const express = require('express');
const crypto  = require('crypto');
const path    = require('path');

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

  middleware() {
    return (req, res, next) => {
      const key = req.ip || '0.0.0.0';
      const now = Date.now();
      let e = this.store.get(key);
      if (!e || now >= e.resetAt) {
        e = { count: 0, resetAt: now + this.windowMs };
        this.store.set(key, e);
      }
      e.count++;
      if (e.count > this.max) {
        res.setHeader('Retry-After', String(Math.ceil((e.resetAt - now) / 1000)));
        return res.status(429).json({ error: 'Too many requests. Please slow down.' });
      }
      next();
    };
  }
}

const createLimiter = new RateLimiter(60_000, 10);  // 10 creates / min per IP
const readLimiter   = new RateLimiter(60_000, 30);  // 30 reads   / min per IP

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

// ── Validators ──────────────────────────────────────────────────────────────
const UUID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const B64_RE   = /^[A-Za-z0-9+/]+=*$/;
// AES-GCM IV must be 12 raw bytes → exactly 16 base-64 chars
const IV_B64_LEN = 16;
// Max plaintext 10 KB + 16-byte GCM tag → ≤ 13 720 base-64 chars
const MAX_CT_LEN = 13_720;

// ── POST /api/secret ────────────────────────────────────────────────────────
app.post('/api/secret', createLimiter.middleware(), (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid payload.' });
  }

  const { ciphertext, iv } = body;

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

  const id = crypto.randomUUID();
  secrets.set(id, { ciphertext, iv });

  res.status(201).json({ id });
});

// ── GET /api/secret/:id ─────────────────────────────────────────────────────
app.get('/api/secret/:id', readLimiter.middleware(), (req, res) => {
  const { id } = req.params;

  if (!UUID_RE.test(id)) {
    return res.status(400).json({ error: 'Invalid identifier.' });
  }

  const secret = secrets.get(id);
  if (!secret) {
    return res.status(404).json({ error: 'not_found' });
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
