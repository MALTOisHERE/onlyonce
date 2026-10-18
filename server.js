'use strict';

const express      = require('express');
const crypto       = require('crypto');
const fs           = require('fs');
const path         = require('path');
const { Resend }   = require('resend');
const pinoHttp     = require('pino-http');

const { RateLimiter }  = require('./lib/ratelimiter');
const { logger, LOGS_DIR, flushLogs } = require('./lib/logger');

const { version: APP_VERSION } = require('./package.json');

const app = express();

// ── Trust reverse proxy (nginx, Cloudflare, etc.) ──────────────────────────
// Two real hops sit between the visitor and this app: Cloudflare's edge,
// then nginx - each one is a layer X-Forwarded-For has to be peeled back
// through. Trusting only 1 (as this used to say) makes req.ip resolve to
// Cloudflare's own edge IP, which rotates per-request even for the same
// visitor - silently breaking every IP-keyed thing in this file (all five
// rate limiters, and the `ip` field on every log line) since each request
// lands in a different bucket that never accumulates. Verified empirically
// against the exact X-Forwarded-For shape production actually sends
// (stable visitor IP first, rotating Cloudflare edge IP second): trusting
// 1 hop resolves to the rotating one, trusting 2 resolves to the real one.
app.set('trust proxy', 2);

// ── Request logging ──────────────────────────────────────────────────────────
// Every request still gets req.log attached (route handlers log their own
// business events through it, carrying the same request id, so a single
// request's whole story can be traced by id) — but the automatic "request
// completed" line is only emitted for /api/* traffic, where the actions
// actually are. Static assets and plain page loads (CSS, JS, images, /,
// /about, /view/:id, ...) would otherwise produce one log line per file on
// every page load, which is pure noise next to the business-event logs
// already scattered through the API routes. Errors are never silenced by
// this: the global error handler and the 404 handler below log explicitly,
// regardless of path, independent of this ignore rule.
app.use(pinoHttp({
  logger,
  autoLogging: {
    ignore(req) { return !req.url.startsWith('/api/'); },
  },
  customLogLevel(req, res, err) {
    if (err || res.statusCode >= 500) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
  customSuccessMessage(req, res) {
    return `${req.method} ${req.url} ${res.statusCode}`;
  },
  customErrorMessage(req, res, err) {
    return `${req.method} ${req.url} ${res.statusCode} - ${err.message}`;
  },
  // pino-http's own req.remoteAddress reads the raw TCP socket, which behind
  // nginx/Cloudflare is always the reverse proxy's address, not the visitor's
  // - useless for "who actually did this." req.ip is Express's own address,
  // already trust-proxy-aware (see app.set('trust proxy', 2) above, which
  // the rate limiters already rely on for the same reason) and resolves to
  // the real client IP. customProps runs per-request, so it sees the same
  // req.ip every route handler does. Added here, not as a replacement for
  // remoteAddress, so both are visible: `ip` for attribution, remoteAddress
  // for proxy-layer debugging if that's ever actually what's being debugged.
  customProps(req) {
    return { ip: req.ip };
  },
}));

// ── Security headers ────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options',     'nosniff');
  res.setHeader('X-Frame-Options',            'DENY');
  res.setHeader('X-XSS-Protection',           '0');
  res.setHeader('Referrer-Policy',            'no-referrer');
  res.setHeader('Permissions-Policy',         'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy',   'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'credentialless');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "font-src 'self'",
      "img-src 'self' data: https://assets.malto.icu",
      "connect-src 'self' https://assets.malto.icu",
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
const createLimiter = new RateLimiter(60_000,    parseInt(process.env.CREATE_RATE_LIMIT || '10',  10), 'create');
const readLimiter   = new RateLimiter(60_000,    parseInt(process.env.READ_RATE_LIMIT   || '30',  10), 'read');
const emailLimiter  = new RateLimiter(3_600_000, parseInt(process.env.EMAIL_RATE_LIMIT  || '3',   10), 'email');
// Bucketed by the signed-in account, so every session using the same
// license — however it ended up authenticated — shares one daily quota. This
// is now a secondary safety net: the real protection is that Pro requires a
// live session per account (Activation Limit = 1), not a copy-pasteable
// key. This limiter just guards against runaway/automated abuse of one account.
const licenseUsageLimiter = new RateLimiter(86_400_000, parseInt(process.env.PRO_USAGE_RATE_LIMIT || '50', 10), 'pro-usage');
// Free tier has no account concept, so this is bucketed by IP — the only
// signal available for an anonymous creator.
const freeUsageLimiter = new RateLimiter(86_400_000, parseInt(process.env.FREE_USAGE_RATE_LIMIT || '5', 10), 'free-usage');

// ── Blink Pro licensing (Lemon Squeezy + Google/GitHub Sign-In) ─────────────
// The license key and its Lemon Squeezy instance ID live ONLY on the server,
// keyed by a hash of the signed-in account's verified email — never in the
// browser. The browser only ever holds a signed session cookie proving "this
// email is logged in right now." Keying by email (rather than a
// provider-specific account ID) is deliberate: it's what makes Google and
// GitHub sign-in resolve to the SAME Pro account whenever both are verified
// for the same address. Two different emails are, correctly, two different
// accounts — no linking happens unless the email itself matches.
// A raw license key + instance ID pasted into a chat is just two
// copy-pasteable strings; a live OAuth login is not something people hand
// out the same way, which is what actually stops casual key sharing.
// Set the Lemon Squeezy product's Activation Limit to 1 so a key can only
// ever be bound to one account (one email) at a time.
const LS_STORE_ID    = process.env.LS_STORE_ID   ? Number(process.env.LS_STORE_ID)   : null;
const LS_PRODUCT_ID  = process.env.LS_PRODUCT_ID ? Number(process.env.LS_PRODUCT_ID) : null;
const PRO_DEV_KEY    = process.env.BLINK_PRO_DEV_KEY || null;
// Site owner allowlist — these accounts (by email, either sign-in provider)
// always have Pro, no license or Lemon Squeezy involved. Safer than a shared
// bearer key for this: even if the env var leaked, it only grants Pro to a
// specific real, provider-verified email, not to anyone who happens to read
// the value. Comma-separated in OWNER_EMAILS.
const OWNER_EMAILS = new Set(
  (process.env.OWNER_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean)
);
const LICENSE_KEY_RE      = /^[A-Za-z0-9-]{8,64}$/;
const LICENSE_INSTANCE_RE = /^[A-Za-z0-9-]{1,64}$/;
const LICENSE_CACHE_TTL = 3_600_000; // 1 hour
const licenseCache = new Map(); // "key:instanceId" -> { valid, exp }

function licenseMetaMatches(data) {
  return (!LS_STORE_ID   || data?.meta?.store_id   === LS_STORE_ID)
      && (!LS_PRODUCT_ID || data?.meta?.product_id === LS_PRODUCT_ID);
}

async function activateLicense(key, instanceName) {
  const resp = await fetch('https://api.lemonsqueezy.com/v1/licenses/activate', {
    method:  'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    body:    JSON.stringify({ license_key: key, instance_name: instanceName }),
  });
  const data   = await resp.json();
  const status = data?.license_key?.status;
  const ok = data?.activated === true
    && status !== 'expired' && status !== 'disabled'
    && licenseMetaMatches(data);
  return { ok, instanceId: data?.instance?.id || null, error: data?.error || null };
}

async function deactivateLicense(key, instanceId) {
  await fetch('https://api.lemonsqueezy.com/v1/licenses/deactivate', {
    method:  'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    body:    JSON.stringify({ license_key: key, instance_id: instanceId }),
  });
}

async function checkLicenseInstance(key, instanceId) {
  if (typeof key !== 'string' || !LICENSE_KEY_RE.test(key)) return false;
  if (PRO_DEV_KEY && key === PRO_DEV_KEY) return true;
  if (typeof instanceId !== 'string' || !LICENSE_INSTANCE_RE.test(instanceId)) return false;

  const cacheKey = `${key}:${instanceId}`;
  const cached = licenseCache.get(cacheKey);
  if (cached && Date.now() < cached.exp) return cached.valid;

  let valid = false;
  try {
    const resp = await fetch('https://api.lemonsqueezy.com/v1/licenses/validate', {
      method:  'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body:    JSON.stringify({ license_key: key, instance_id: instanceId }),
    });
    const data   = await resp.json();
    const status = data?.license_key?.status;
    valid = data?.valid === true
      && !!data?.instance
      && status !== 'expired' && status !== 'disabled'
      && licenseMetaMatches(data);
  } catch (err) {
    logger.error({ err, licenseFragment: key.slice(-6) }, 'license validation request failed');
    // Lemon Squeezy unreachable: honour a stale cache entry rather than lock out a paying user
    if (cached) return cached.valid;
    return false;
  }

  licenseCache.set(cacheKey, { valid, exp: Date.now() + LICENSE_CACHE_TTL });
  if (licenseCache.size > 5_000) {
    licenseCache.delete(licenseCache.keys().next().value);
  }
  return valid;
}

// ── Persistent license store, keyed by a hash of the account's verified email ──
// { [sha256(email.toLowerCase())]: { licenseKey, instanceId, email, activatedAt } }
// Never sent to the browser — only the session cookie is. Mirrors the
// STATS_FILE persistence pattern already used elsewhere in this file.
const LICENSES_FILE = process.env.LICENSES_FILE || path.join(__dirname, 'data', 'licenses.json');
let licenses = {};

try {
  fs.mkdirSync(path.dirname(LICENSES_FILE), { recursive: true });
  licenses = JSON.parse(fs.readFileSync(LICENSES_FILE, 'utf8'));
} catch {}

// One-time migration: older records were keyed by a hash of the Google
// account's "sub" ID rather than email. Re-key anything we can (every record
// already stores its email) so Google and GitHub sign-in start resolving to
// the same account immediately, instead of only for newly-activated licenses.
{
  let migrated = false;
  for (const [oldKey, record] of Object.entries(licenses)) {
    if (!record?.email) continue;
    const newKey = emailHash(record.email);
    if (newKey === oldKey) continue; // already keyed correctly
    if (licenses[newKey]) {
      logger.warn({ oldKey, newKey }, 'license migration: email already has a record under the new key, leaving old key in place for manual review');
      continue;
    }
    licenses[newKey] = record;
    delete licenses[oldKey];
    migrated = true;
  }
  if (migrated) saveLicenses(); // hoisted function, defined just below
}

function saveLicenses() {
  try {
    const tmp = LICENSES_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(licenses, null, 2));
    fs.renameSync(tmp, LICENSES_FILE);
  } catch (err) {
    logger.error({ err }, 'failed to persist licenses file');
  }
}

// ── Signed session cookies ──────────────────────────────────────────────────
// Hand-rolled (one HMAC-signed cookie) instead of adding a cookie-parser /
// express-session dependency for something this simple.
const SESSION_SECRET     = process.env.SESSION_SECRET || null;
const SESSION_COOKIE     = 'blink_session';
const SESSION_MAX_AGE    = 7 * 24 * 3_600_000; // 7 days
const OAUTH_STATE_COOKIE = 'blink_oauth_state';

function parseCookies(header) {
  // Keys come straight from the raw Cookie header (attacker-controlled).
  // A null-prototype object means a key like "__proto__" or "constructor"
  // just becomes an own property, never a prototype-pollution vector.
  const out = Object.create(null);
  if (!header) return out;
  for (const pair of header.split(';')) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) { try { out[k] = decodeURIComponent(v); } catch { out[k] = v; } }
  }
  return out;
}

function signValue(value, secret) {
  const sig = crypto.createHmac('sha256', secret).update(value).digest('base64url');
  return `${value}.${sig}`;
}

function unsignValue(signed, secret) {
  const idx = signed.lastIndexOf('.');
  if (idx === -1) return null;
  const value = signed.slice(0, idx);
  const sig   = signed.slice(idx + 1);
  const expected = crypto.createHmac('sha256', secret).update(value).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return value;
}

// The one identity key shared across every sign-in provider: whichever
// provider you authenticate with, this is what actually gets looked up in
// `licenses`. Same verified email -> same hash -> same Pro account.
function emailHash(email) {
  return crypto.createHash('sha256').update(String(email).toLowerCase()).digest('hex');
}

function cookieAttrs(maxAgeSeconds) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `HttpOnly${secure}; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;
}

function setSessionCookie(res, subHash, email) {
  const payload = JSON.stringify({ sub: subHash, email: email || null, exp: Date.now() + SESSION_MAX_AGE });
  const value   = signValue(Buffer.from(payload).toString('base64url'), SESSION_SECRET);
  res.append('Set-Cookie', `${SESSION_COOKIE}=${value}; ${cookieAttrs(Math.floor(SESSION_MAX_AGE / 1000))}`);
}

function clearSessionCookie(res) {
  res.append('Set-Cookie', `${SESSION_COOKIE}=; ${cookieAttrs(0)}`);
}

function readSession(req) {
  if (!SESSION_SECRET) return null;
  const raw = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!raw) return null;
  const encoded = unsignValue(raw, SESSION_SECRET);
  if (!encoded) {
    // Signature didn't match — either a forged/tampered cookie, or an old
    // one signed under a SESSION_SECRET that's since been rotated. Worth
    // knowing about either way; this is otherwise indistinguishable from
    // "not logged in" anywhere else in the request's handling.
    req.log?.warn('session cookie present but signature invalid');
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (typeof payload.sub !== 'string' || typeof payload.exp !== 'number') {
      req.log?.warn('session cookie present but malformed payload');
      return null;
    }
    if (Date.now() > payload.exp) {
      req.log?.debug({ account: payload.sub }, 'session cookie expired');
      return null;
    }
    return payload;
  } catch {
    req.log?.warn('session cookie present but not valid JSON');
    return null;
  }
}

async function isProForSession(session) {
  if (!session) return false;
  if (session.email && OWNER_EMAILS.has(session.email.toLowerCase())) return true;
  const record = licenses[session.sub];
  if (!record) return false;
  return checkLicenseInstance(record.licenseKey, record.instanceId);
}

// ── Google OAuth (server-side redirect flow — no client-side Google JS SDK,
// so the strict script-src 'self' CSP never needs loosening) ───────────────
// See the GitHub OAuth block further down for the second sign-in option;
// both resolve to the same account whenever the verified email matches.
const GOOGLE_CLIENT_ID       = process.env.GOOGLE_CLIENT_ID     || null;
const GOOGLE_CLIENT_SECRET   = process.env.GOOGLE_CLIENT_SECRET || null;
const GOOGLE_REDIRECT_URI    = process.env.GOOGLE_REDIRECT_URI  || null;
const GOOGLE_AUTH_CONFIGURED = !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_REDIRECT_URI && SESSION_SECRET);

app.get('/api/auth/google/start', (req, res) => {
  if (!GOOGLE_AUTH_CONFIGURED) {
    req.log.warn('google sign-in attempted but not configured on this server');
    return res.status(503).send('Google sign-in is not configured on this server.');
  }
  const state = crypto.randomBytes(24).toString('base64url');
  res.append('Set-Cookie', `${OAUTH_STATE_COOKIE}=${state}; ${cookieAttrs(600)}`);
  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope:         'openid email',
    state,
    prompt:        'select_account',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/api/auth/google/callback', async (req, res) => {
  res.append('Set-Cookie', `${OAUTH_STATE_COOKIE}=; ${cookieAttrs(0)}`);
  if (!GOOGLE_AUTH_CONFIGURED) {
    req.log.warn('google oauth callback hit but not configured on this server');
    return res.status(503).send('Google sign-in is not configured on this server.');
  }
  const { code, state } = req.query;
  const expectedState = parseCookies(req.headers.cookie)[OAUTH_STATE_COOKIE];
  if (!code || !state || !expectedState || state !== expectedState) {
    req.log.warn('google oauth callback rejected: missing or mismatched state');
    return res.redirect('/?auth=error');
  }

  try {
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code:          String(code),
        client_id:     GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri:  GOOGLE_REDIRECT_URI,
        grant_type:    'authorization_code',
      }),
    });
    const tokenData = await tokenResp.json();
    if (!tokenData.id_token) {
      req.log.warn('google oauth callback: token exchange returned no id_token');
      return res.redirect('/?auth=error');
    }

    // Verified via Google's tokeninfo endpoint rather than local JWKS/JWT
    // verification — simpler, no extra dependency, fine at this volume.
    const infoResp = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(tokenData.id_token)}`);
    const info = await infoResp.json();
    if (info.aud !== GOOGLE_CLIENT_ID || info.email_verified !== 'true' || !info.sub) {
      req.log.warn('google oauth callback: tokeninfo failed verification');
      return res.redirect('/?auth=error');
    }

    setSessionCookie(res, emailHash(info.email), info.email);
    req.log.info({ provider: 'google', emailHash: emailHash(info.email) }, 'oauth login succeeded');
    res.redirect('/?auth=success');
  } catch (err) {
    req.log.error({ err, provider: 'google' }, 'oauth callback failed');
    res.redirect('/?auth=error');
  }
});

// ── GitHub OAuth (same server-side redirect flow as Google) ────────────────
// Resolves to the exact same account as Google whenever the verified email
// matches — see emailHash() above and the licenses-store comment. GitHub
// accounts can have a private primary email, so this requires the
// "user:email" scope and reads the dedicated /user/emails endpoint rather
// than the basic /user profile.
const GITHUB_CLIENT_ID       = process.env.GITHUB_CLIENT_ID     || null;
const GITHUB_CLIENT_SECRET   = process.env.GITHUB_CLIENT_SECRET || null;
const GITHUB_REDIRECT_URI    = process.env.GITHUB_REDIRECT_URI  || null;
const GITHUB_AUTH_CONFIGURED = !!(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET && GITHUB_REDIRECT_URI && SESSION_SECRET);

app.get('/api/auth/github/start', (req, res) => {
  if (!GITHUB_AUTH_CONFIGURED) {
    req.log.warn('github sign-in attempted but not configured on this server');
    return res.status(503).send('GitHub sign-in is not configured on this server.');
  }
  const state = crypto.randomBytes(24).toString('base64url');
  res.append('Set-Cookie', `${OAUTH_STATE_COOKIE}=${state}; ${cookieAttrs(600)}`);
  const params = new URLSearchParams({
    client_id:    GITHUB_CLIENT_ID,
    redirect_uri: GITHUB_REDIRECT_URI,
    scope:        'read:user user:email',
    state,
    allow_signup: 'true',
  });
  res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

app.get('/api/auth/github/callback', async (req, res) => {
  res.append('Set-Cookie', `${OAUTH_STATE_COOKIE}=; ${cookieAttrs(0)}`);
  if (!GITHUB_AUTH_CONFIGURED) {
    req.log.warn('github oauth callback hit but not configured on this server');
    return res.status(503).send('GitHub sign-in is not configured on this server.');
  }
  const { code, state } = req.query;
  const expectedState = parseCookies(req.headers.cookie)[OAUTH_STATE_COOKIE];
  if (!code || !state || !expectedState || state !== expectedState) {
    req.log.warn('github oauth callback rejected: missing or mismatched state');
    return res.redirect('/?auth=error');
  }

  try {
    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: new URLSearchParams({
        code:          String(code),
        client_id:     GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        redirect_uri:  GITHUB_REDIRECT_URI,
      }),
    });
    const tokenData = await tokenResp.json();
    if (!tokenData.access_token) {
      req.log.warn('github oauth callback: token exchange returned no access_token');
      return res.redirect('/?auth=error');
    }

    // GitHub's /user endpoint only returns a public email if the account has
    // one set; the verified primary address lives in /user/emails instead,
    // and requires its own request with the "user:email" scope.
    const emailsResp = await fetch('https://api.github.com/user/emails', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Accept':        'application/vnd.github+json',
        'User-Agent':    'blink-app',
      },
    });
    const emails = await emailsResp.json();
    const primary = Array.isArray(emails)
      ? emails.find(e => e.primary && e.verified) || emails.find(e => e.verified)
      : null;
    if (!primary?.email) {
      req.log.warn('github oauth callback: no verified email on account');
      return res.redirect('/?auth=error');
    }

    setSessionCookie(res, emailHash(primary.email), primary.email);
    req.log.info({ provider: 'github', emailHash: emailHash(primary.email) }, 'oauth login succeeded');
    res.redirect('/?auth=success');
  } catch (err) {
    req.log.error({ err, provider: 'github' }, 'oauth callback failed');
    res.redirect('/?auth=error');
  }
});

app.get('/api/auth/me', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const session = readSession(req);
  if (!session) return res.json({ loggedIn: false });
  const isPro   = await isProForSession(session);
  const isOwner = !!(session.email && OWNER_EMAILS.has(session.email.toLowerCase()));
  res.json({ loggedIn: true, email: session.email || null, isPro, isOwner });
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const session = readSession(req);
  clearSessionCookie(res);
  if (session) req.log.info({ account: session.sub }, 'logged out');
  res.json({ ok: true });
});

// Dev-only bypass so the full session -> license flow can be tested locally
// without real Google/GitHub OAuth credentials. Never registered in production.
if (process.env.NODE_ENV !== 'production' && PRO_DEV_KEY) {
  app.get('/api/auth/dev-login', (req, res) => {
    const devEmail = 'dev@example.com';
    setSessionCookie(res, emailHash(devEmail), devEmail);
    req.log.warn('dev-login used: auth bypass session created');
    res.redirect('/?auth=success');
  });
}

// ── Body parsers ─────────────────────────────────────────────────────────────
// Pro uploads (25 MB files) need a larger limit than everything else. Applied
// per-route (not globally) so static assets and other endpoints never pay for
// a session/license lookup on every request.
const jsonSmall = express.json({ limit: '4mb',  strict: true });
const jsonLarge = express.json({ limit: '40mb', strict: true });

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
// Deliberately never touches disk during normal operation - that's what
// makes a VPS compromise or disk forensics unable to recover a pending
// secret. The one exception: a GRACEFUL shutdown (a deploy, `docker compose
// restart`) snapshots this Map to the existing /data volume just before
// exiting, and reloads it on the next startup - see saveSecretsSnapshot()
// and loadSecretsSnapshot() below. This loses nothing extra in security
// terms: every value already stored here is the same encrypted ciphertext
// and K3-masked K2 that would be written to the snapshot, never plaintext,
// never usable without K1 (which never reaches the server). A hard crash,
// SIGKILL, or power loss still loses everything unviewed - there's no
// graceful-shutdown moment to snapshot in that case, same as always.
const secrets     = new Map();
const MAX_SECRETS      = 10_000;
const ALLOWED_TTL_HOURS     = new Set([1, 6, 24, 48]);
const ALLOWED_TTL_HOURS_PRO = new Set([1, 6, 24, 48, 168]);
const DEFAULT_TTL_HOURS = 48;
const MAX_VIEWS_PRO       = 5;
const PASSPHRASE_MIN_LEN  = 4;
const PASSPHRASE_MAX_LEN  = 128;
const MAX_AUTH_ATTEMPTS   = 5;

const SECRETS_SNAPSHOT_FILE = process.env.SECRETS_SNAPSHOT_FILE || path.join(__dirname, 'data', 'secrets-snapshot.json');

function loadSecretsSnapshot() {
  let raw;
  try {
    raw = fs.readFileSync(SECRETS_SNAPSHOT_FILE, 'utf8');
  } catch {
    return; // normal case: no snapshot exists (last shutdown wasn't graceful, or this is a fresh start)
  }
  // Delete immediately after reading, graceful or not - a snapshot should
  // never linger on disk longer than the one restart it was written for.
  try { fs.unlinkSync(SECRETS_SNAPSHOT_FILE); } catch {}

  let entries;
  try {
    entries = JSON.parse(raw);
  } catch (err) {
    logger.error({ err }, 'secrets snapshot was corrupt, discarding it');
    return;
  }

  const now = Date.now();
  let restored = 0;
  let expired  = 0;
  for (const [id, secret] of entries) {
    if (secret.expiresAt <= now) { expired++; continue; }
    secrets.set(id, secret);
    restored++;
  }
  logger.info({ restored, expired }, 'secrets restored from graceful-shutdown snapshot');
}

function saveSecretsSnapshot() {
  try {
    const tmp = SECRETS_SNAPSHOT_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify([...secrets.entries()]));
    fs.renameSync(tmp, SECRETS_SNAPSHOT_FILE);
    logger.info({ count: secrets.size }, 'secrets snapshotted for graceful restart');
  } catch (err) {
    logger.error({ err }, 'failed to snapshot secrets before shutdown - any unviewed secret will be lost');
  }
}

try { fs.mkdirSync(path.dirname(SECRETS_SNAPSHOT_FILE), { recursive: true }); } catch {}
loadSecretsSnapshot();

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
    logger.error({ err }, 'failed to persist stats file');
  }
}

// Purge interval declared after stats so stats.secretsExpired is always initialised
const purge = setInterval(() => {
  const now = Date.now();
  let purged = 0;
  for (const [id, s] of secrets) {
    if (now > s.expiresAt) {
      secrets.delete(id);
      stats.secretsExpired++;
      purged++;
    }
  }
  if (purged > 0) {
    logger.info({ purged, remaining: secrets.size }, 'expired secrets purged');
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
  logger.fatal('CIPHER_KEY must be exactly 64 hex characters (32 bytes). Exiting.');
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
// Last 8 hex chars of the secret's UUID — enough to eyeball-match this email
// against the tail of a specific share link, without dumping a full 36-char
// UUID into the email body. Not sensitive: it doesn't help decrypt anything.
function idFragment(id) {
  return id.slice(-8);
}

// Chrome's own behavior, not anything the extension sets deliberately: a
// fetch() from an extension's background service worker always carries
// Origin: chrome-extension://<id>, while the website's own same-origin
// requests carry Origin: https://blink.malto.icu. No CORS handling needed
// either way - this is purely for telling the two apart in logs.
function requestSource(req) {
  const origin = req.headers.origin || '';
  if (origin.startsWith('chrome-extension://') || origin.startsWith('moz-extension://')) return 'extension';
  if (origin) return 'web';
  return 'unknown';
}

function formatExpiry(hours) {
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'}`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? '' : 's'}`;
}

function viewsSetByLine(viewsAllowed) {
  return viewsAllowed > 1
    ? `The sender set this secret to be viewed up to ${viewsAllowed} times.`
    : 'The sender set this secret to be viewed only once.';
}

// Shared chrome for both transactional emails: logo + wordmark, a green
// eyebrow badge naming the email's type, and a fading green divider —
// mirrors the site's own light-theme tokens (style.css) and badge pattern
// (e.g. .about-hero-badge), since CSS mask-recoloring isn't available in
// email clients and the logo PNG itself is baked at the dark-theme green.
function emailHeader(eyebrow) {
  return `
    <tr><td style="padding:24px 28px 18px;">
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>
        <td style="vertical-align:middle;width:47px;"><img src="https://assets.malto.icu/blink/blink-logo.png" alt="Blink" width="47" height="32" style="display:block;height:32px;width:47px;"></td>
        <td style="vertical-align:middle;padding-left:10px;white-space:nowrap;">
          <span style="color:#2f9e2a;font-size:18px;font-weight:700;">Blink</span>
          <span style="display:inline-block;margin-left:8px;border:1px solid rgba(0,0,0,0.10);border-radius:999px;padding:3px 9px;font-size:10px;color:#9aa0aa;vertical-align:middle;">by MALTO</span>
        </td>
        <td style="vertical-align:middle;text-align:right;">
          <span style="display:inline-block;border:1px solid rgba(97,207,90,.2);background:rgba(97,207,90,.10);border-radius:999px;padding:4px 12px;font-size:10px;font-weight:600;letter-spacing:0.08em;color:#2f9e2a;text-transform:uppercase;">${eyebrow}</span>
        </td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:0 28px;"><div style="height:1px;background:linear-gradient(90deg, rgba(255,255,255,0), rgba(97,207,90,.55), rgba(255,255,255,0));"></div></td></tr>
  `;
}

function emailFooter() {
  return `
    <tr><td style="padding:9px 28px;border-top:1px solid rgba(0,0,0,0.10);text-align:center;">
      <p style="margin:0;font-size:10px;line-height:1.3;color:#9aa0aa;">Blink v${APP_VERSION} &middot; <a href="https://blink.malto.icu" style="color:#9aa0aa;text-decoration:none;">blink.malto.icu</a></p>
    </td></tr>
  `;
}

// Hidden preheader text: without it, clients fall back to showing boilerplate
// (e.g. "View in browser") as the inbox preview snippet instead of context.
function preheader(text) {
  const padding = '&#8203;'.repeat(20);
  return `<div style="display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all;">${text} ${padding}</div>`;
}

async function sendOTPEmail(to, otp, id, viewsAllowed = 1, expiresInHours = 48) {
  const { error } = await resendClient.emails.send({
    from:    process.env.EMAIL_FROM || 'Blink <noreply@malto.icu>',
    to,
    subject: '[Blink - Verification] Your Blink verification code',
    html: `
      <div style="margin:0;padding:0;background:#f5f5f5;">
        ${preheader(`Your Blink code: ${otp}. Someone shared a secret with you.`)}
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;"><tr><td align="center" style="padding:36px 16px;">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;background:#ffffff;border:1px solid rgba(0,0,0,0.10);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.05);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
            ${emailHeader('Verification')}
            <tr><td style="padding:26px 28px 20px;text-align:center;">
              <p style="margin:0 0 20px;font-size:15px;color:#111111;line-height:1.5;">Someone shared a secret with you. Enter this code on the Blink page to reveal it:</p>
              <div style="background:#f0f0f0;border:1px solid rgba(0,0,0,0.10);border-top:2px solid rgba(97,207,90,.5);border-radius:10px;padding:24px 20px 18px;">
                <span style="font-family:ui-monospace,'SF Mono',Consolas,'Courier New',monospace;font-size:38px;font-weight:700;letter-spacing:9px;color:#2f9e2a;">${otp}</span>
                <div style="margin-top:10px;font-size:11px;color:#68707c;">${viewsSetByLine(viewsAllowed)} Expires in ${formatExpiry(expiresInHours)}.</div>
              </div>
              <p style="margin:16px 0 0;font-size:11px;color:#b5b9bf;line-height:1.6;">Link ...${idFragment(id)} &nbsp;&middot;&nbsp; works once &nbsp;&middot;&nbsp; didn't request it? ignore this email.</p>
            </td></tr>
            ${emailFooter()}
          </table>
        </td></tr></table>
      </div>
    `,
  });
  if (error) throw new Error(error.message);
}

async function sendViewNotification(to, viewsLeft, id) {
  const remaining = viewsLeft > 0
    ? `It can be viewed ${viewsLeft} more time${viewsLeft === 1 ? '' : 's'} before it is destroyed.`
    : 'It has now been permanently deleted from the server.';
  const pill = viewsLeft > 0
    ? `<span style="display:inline-block;background:rgba(97,207,90,.10);border:1px solid rgba(97,207,90,.2);border-radius:999px;padding:7px 16px;font-size:12px;font-weight:600;color:#2f9e2a;">&#9679;&nbsp; ${viewsLeft} view${viewsLeft === 1 ? '' : 's'} left</span>`
    : `<span style="display:inline-block;background:#f0f0f0;border:1px solid rgba(0,0,0,.10);border-radius:999px;padding:7px 16px;font-size:12px;font-weight:600;color:#68707c;">&#9679;&nbsp; Deleted</span>`;
  const previewText = viewsLeft > 0
    ? 'A secret you shared was just viewed.'
    : 'A secret you shared was viewed and deleted.';
  const { error } = await resendClient.emails.send({
    from:    process.env.EMAIL_FROM || 'Blink <noreply@malto.icu>',
    to,
    subject: '[Blink - Activity] Your Blink secret was viewed',
    html: `
      <div style="margin:0;padding:0;background:#f5f5f5;">
        ${preheader(previewText)}
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;"><tr><td align="center" style="padding:36px 16px;">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;background:#ffffff;border:1px solid rgba(0,0,0,0.10);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.05);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
            ${emailHeader('Activity')}
            <tr><td style="padding:26px 28px 20px;text-align:center;">
              <p style="margin:0 0 16px;font-size:15px;color:#111111;line-height:1.5;">A secret you shared on Blink was just viewed.</p>
              <div style="margin:0 0 12px;">${pill}</div>
              <p style="margin:0 0 16px;font-size:12px;color:#68707c;line-height:1.5;">${remaining}</p>
              <p style="margin:0;font-size:11px;color:#b5b9bf;line-height:1.6;">Link ...${idFragment(id)}</p>
            </td></tr>
            ${emailFooter()}
          </table>
        </td></tr></table>
      </div>
    `,
  });
  if (error) throw new Error(error.message);
}

// ── POST /api/license/activate ───────────────────────────────────────────────
// Requires a verified session (Google or GitHub). Binds the submitted key to
// THIS account's email — the Lemon Squeezy product's Activation Limit (set
// to 1) enforces that no other account can ever activate the same key. The
// key and instance ID are stored server-side only; the browser never
// receives them.
app.post('/api/license/activate', createLimiter.middleware(), jsonSmall, async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const session = readSession(req);
  if (!session) {
    return res.status(401).json({ valid: false, error: 'login_required' });
  }

  const key = typeof req.body?.licenseKey === 'string' ? req.body.licenseKey.trim() : '';
  if (!LICENSE_KEY_RE.test(key)) {
    return res.json({ valid: false, error: 'invalid' });
  }

  const subHash  = session.sub;
  const existing = licenses[subHash];

  if (PRO_DEV_KEY && key === PRO_DEV_KEY) {
    licenses[subHash] = { licenseKey: key, instanceId: 'dev', email: session.email || null, activatedAt: Date.now() };
    saveLicenses();
    req.log.info({ account: subHash, dev: true }, 'license activated');
    return res.json({ valid: true });
  }

  // Already activated with this exact key on this account — nothing to do.
  if (existing && existing.licenseKey === key) {
    req.log.info({ account: subHash }, 'license re-activation: already active, no-op');
    return res.json({ valid: true });
  }

  // Switching to a different key: free the old slot first (best-effort).
  if (existing) {
    try { await deactivateLicense(existing.licenseKey, existing.instanceId); }
    catch (err) { req.log.error({ err, account: subHash }, 'failed to deactivate previous license before switching keys'); }
    delete licenses[subHash];
    req.log.info({ account: subHash }, 'license deactivated (switching keys)');
  }

  try {
    const { ok, instanceId, error } = await activateLicense(key, `account-${subHash}`);
    if (!ok) {
      saveLicenses();
      const limitReached = /activation limit/i.test(error || '');
      req.log.warn({ account: subHash, reason: limitReached ? 'activation_limit' : 'invalid' }, 'license activation rejected');
      return res.json({ valid: false, error: limitReached ? 'activation_limit' : 'invalid' });
    }
    licenses[subHash] = { licenseKey: key, instanceId, email: session.email || null, activatedAt: Date.now() };
    saveLicenses();
    req.log.info({ account: subHash }, 'license activated');
    res.json({ valid: true });
  } catch (err) {
    req.log.error({ err, account: subHash }, 'license activation request failed');
    res.status(503).json({ valid: false, error: 'unavailable' });
  }
});

// ── POST /api/license/deactivate ─────────────────────────────────────────────
// Frees this account's activation slot. No body needed — the server already
// knows which license belongs to this session.
app.post('/api/license/deactivate', createLimiter.middleware(), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const session = readSession(req);
  if (!session) {
    return res.status(401).json({ ok: false });
  }
  const record = licenses[session.sub];
  if (!record) {
    return res.json({ ok: true });
  }
  licenseCache.delete(`${record.licenseKey}:${record.instanceId}`);
  delete licenses[session.sub];
  saveLicenses();
  if (!(PRO_DEV_KEY && record.licenseKey === PRO_DEV_KEY)) {
    try { await deactivateLicense(record.licenseKey, record.instanceId); }
    catch (err) { req.log.error({ err, account: session.sub }, 'failed to deactivate license with Lemon Squeezy'); }
  }
  req.log.info({ account: session.sub }, 'license deactivated');
  res.json({ ok: true });
});

// ── POST /api/secret ────────────────────────────────────────────────────────
app.post('/api/secret', createLimiter.middleware(), async (req, res, next) => {
  const session = readSession(req);
  req.session = session;
  req.isPro   = await isProForSession(session);
  return (req.isPro ? jsonLarge : jsonSmall)(req, res, next);
}, async (req, res) => {
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
  if (isPro) {
    // Bucketed by the account (already a one-way hash of its verified
    // email), not the license key — with Activation Limit = 1 the two
    // are equivalent, and this way the raw key is never touched here.
    const retryAfter = licenseUsageLimiter.check(req.session.sub);
    if (retryAfter > 0) {
      res.setHeader('Retry-After', String(retryAfter));
      req.log.warn({ limiter: 'pro-usage', account: req.session.sub, retryAfter }, 'rate limit exceeded');
      return res.status(429).json({ error: 'This license has reached its daily usage limit. Try again tomorrow, or contact support if this seems wrong.' });
    }
  } else {
    const retryAfter = freeUsageLimiter.check(req.ip);
    if (retryAfter > 0) {
      res.setHeader('Retry-After', String(retryAfter));
      req.log.warn({ limiter: 'free-usage', retryAfter }, 'rate limit exceeded');
      return res.status(429).json({ error: `Free plan is limited to ${freeUsageLimiter.max} secrets per day. Upgrade to Pro for more, or try again tomorrow.` });
    }
  }
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
    req.log.error({ secretsInMemory: secrets.size, cap: MAX_SECRETS }, 'server at secret capacity, rejecting create');
    return res.status(503).json({ error: 'Server is at capacity. Try again shortly.' });
  }

  // Generated early so it can be embedded in the OTP email below, letting a
  // recipient with multiple pending secrets match a code to the right link.
  const id = crypto.randomUUID();

  // ── Pro-gated options ──
  let viewsAllowed = 1;
  if (viewsRaw !== undefined) {
    const v = Number(viewsRaw);
    if (!Number.isInteger(v) || v < 1 || v > MAX_VIEWS_PRO) {
      return res.status(400).json({ error: 'Invalid views value.' });
    }
    if (v > 1 && !isPro) {
      req.log.info({ feature: 'multi-view links' }, 'pro feature blocked: not a pro account');
      return res.status(403).json({ error: 'pro_required', feature: 'multi-view links' });
    }
    viewsAllowed = v;
  }

  let passHash = null;
  let passSalt = null;
  if (passphraseRaw !== undefined) {
    if (!isPro) {
      req.log.info({ feature: 'passphrase protection' }, 'pro feature blocked: not a pro account');
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
      req.log.info({ feature: 'view notifications' }, 'pro feature blocked: not a pro account');
      return res.status(403).json({ error: 'pro_required', feature: 'view notifications' });
    }
    if (!resendClient) {
      req.log.warn('view notification requested but RESEND_API_KEY is not configured');
      return res.status(503).json({ error: 'Email is not configured on this server.' });
    }
    if (typeof notifyEmailRaw !== 'string' || !EMAIL_RE.test(notifyEmailRaw)) {
      return res.status(400).json({ error: 'Invalid notification email address.' });
    }
    notifyEmail = notifyEmailRaw;
  }

  if (Number(expiresInRaw) === 168 && !isPro) {
    req.log.info({ feature: '7-day expiry' }, 'pro feature blocked: not a pro account');
    return res.status(403).json({ error: 'pro_required', feature: '7-day expiry' });
  }

  // Computed before the OTP email below so the email can tell the recipient
  // how long the link lasts and how many times the sender allowed it to be viewed.
  const allowedTtl = isPro ? ALLOWED_TTL_HOURS_PRO : ALLOWED_TTL_HOURS;
  const expiresInHours = allowedTtl.has(Number(expiresInRaw)) ? Number(expiresInRaw) : DEFAULT_TTL_HOURS;
  const expiresAt = Date.now() + expiresInHours * 3_600_000;

  let otpHash = null;
  if (recipientEmail !== undefined) {
    if (!resendClient) {
      req.log.warn('otp email verification requested but RESEND_API_KEY is not configured');
      return res.status(503).json({ error: 'Email verification is not configured on this server.' });
    }
    if (typeof recipientEmail !== 'string' || !EMAIL_RE.test(recipientEmail)) {
      return res.status(400).json({ error: 'Invalid email address.' });
    }
    const emailRetryAfter = emailLimiter.check(req.ip);
    if (emailRetryAfter > 0) {
      res.setHeader('Retry-After', String(emailRetryAfter));
      req.log.warn({ limiter: 'email', retryAfter: emailRetryAfter }, 'rate limit exceeded');
      return res.status(429).json({ error: 'Too many verification emails. Try again in an hour.' });
    }

    const otp = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    otpHash   = crypto.createHash('sha256').update(otp).digest('hex');
    try {
      await sendOTPEmail(recipientEmail, otp, id, viewsAllowed, expiresInHours);
      stats.emailsSent++;
      req.log.info({ secretId: idFragment(id) }, 'otp email sent');
    } catch (err) {
      req.log.error({ err, secretId: idFragment(id) }, 'failed to send otp email');
      return res.status(500).json({ error: 'Failed to send verification email. Please try again.' });
    }
  }

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

  req.log.info({
    secretId:    idFragment(id),
    source:      requestSource(req),
    isPro,
    isFile:      isFileSecret,
    viewsAllowed,
    expiresInHours,
    hasOtp:      !!otpHash,
    hasPassphrase: !!passHash,
    hasNotify:   !!notifyEmail,
  }, 'secret created');

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
    req.log.debug({ secretId: idFragment(id) }, 'secret not found (already viewed, expired, or never existed)');
    return res.status(404).json({ error: 'not_found' });
  }

  if (Date.now() > secret.expiresAt) {
    secrets.delete(id);
    req.log.info({ secretId: idFragment(id) }, 'secret access attempted after expiry');
    return res.status(410).json({ error: 'expired' });
  }

  // Passphrase verification (Pro)
  if (secret.passHash) {
    const rawHeader = (req.headers['x-passphrase'] || '').trim();
    if (!rawHeader) {
      req.log.debug({ secretId: idFragment(id) }, 'passphrase required, not yet supplied');
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
        req.log.warn({ secretId: idFragment(id) }, 'secret destroyed: too many passphrase attempts');
        return res.status(410).json({ error: 'too_many_attempts' });
      }
      req.log.warn({ secretId: idFragment(id), attemptsLeft: MAX_AUTH_ATTEMPTS - secret.passAttempts }, 'invalid passphrase attempt');
      return res.status(403).json({ error: 'invalid_passphrase', attemptsLeft: MAX_AUTH_ATTEMPTS - secret.passAttempts });
    }
  }

  // OTP verification
  if (secret.otpHash) {
    const otp = (req.headers['x-otp'] || '').trim();
    if (!otp) {
      req.log.debug({ secretId: idFragment(id) }, 'otp required, not yet supplied');
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
        req.log.warn({ secretId: idFragment(id) }, 'secret destroyed: too many otp attempts');
        return res.status(410).json({ error: 'too_many_attempts' });
      }
      req.log.warn({ secretId: idFragment(id), attemptsLeft: 5 - secret.otpAttempts }, 'invalid otp attempt');
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
    req.log.info({ secretId: idFragment(id), viewsLeft, destroyed: viewsLeft <= 0 }, 'secret viewed');

    if (secret.notifyEmail && resendClient) {
      sendViewNotification(secret.notifyEmail, viewsLeft, id)
        .then(() => { stats.emailsSent++; })
        .catch(err => req.log.error({ err, secretId: idFragment(id) }, 'failed to send view notification email'));
    }

    payload.viewsLeft = viewsLeft;
    res.json(payload);
  } catch (err) {
    req.log.warn({ err, secretId: idFragment(id) }, 'secret decryption failed');
    return res.status(400).json({ error: 'Decryption failed. The link may be corrupted.' });
  }
});

// ── GET /api/config ──────────────────────────────────────────────────────────
// Public frontend configuration. The checkout URL is not a secret (it is a
// public payment page) — env keeps it configurable per deployment.
app.get('/api/config', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ proCheckoutUrl: process.env.PRO_CHECKOUT_URL || null, version: APP_VERSION });
});

// ── GET /api/stats ───────────────────────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ secretsCreated: stats.secretsCreated });
});

// ── About page ───────────────────────────────────────────────────────────────
app.get('/about', readLimiter.middleware(), (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'about.html'));
});

// ── Privacy policy page ────────────────────────────────────────────────────
app.get('/privacy', readLimiter.middleware(), (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

// ── View page ────────────────────────────────────────────────────────────────
app.get('/view/:id', readLimiter.middleware(), (req, res) => {
  if (!UUID_RE.test(req.params.id)) return res.redirect('/');
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

// ── 404 ─────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  req.log.debug('no route matched (unknown path or scan)');
  res.status(404).json({ error: 'Not found.' });
});

// ── Global error handler ────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  if (err.type === 'entity.too.large' || err.status === 413) {
    req.log.warn({ contentLength: req.headers['content-length'] }, 'request rejected: payload too large');
    return res.status(413).json({ error: 'Payload too large.' });
  }
  if (err.status && err.status >= 400 && err.status < 500) {
    req.log.warn({ err, status: err.status }, 'request rejected: malformed');
    return res.status(err.status).json({ error: 'Invalid request.' });
  }
  req.log.error({ err }, 'unhandled request error');
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Startup checks ────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'test') {
  if (!process.env.SECRET_KEY) {
    logger.warn('SECRET_KEY not set — K3 HMAC binding is disabled (K2 stored unmasked)');
  }
  if (!process.env.CIPHER_KEY) {
    logger.warn('CIPHER_KEY not set — K4 ciphertext encryption is disabled');
  }
  if (!process.env.RESEND_API_KEY) {
    logger.warn('RESEND_API_KEY not set — email OTP feature is disabled');
  }
  if (!process.env.LS_STORE_ID || !process.env.LS_PRODUCT_ID) {
    logger.warn('LS_STORE_ID / LS_PRODUCT_ID not set — Lemon Squeezy keys from ANY store would validate; Pro effectively limited to BLINK_PRO_DEV_KEY');
  }
  if (!GOOGLE_AUTH_CONFIGURED) {
    logger.warn('Google sign-in not fully configured (GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_REDIRECT_URI/SESSION_SECRET) — Google Pro sign-in is disabled');
  }
  if (!GITHUB_AUTH_CONFIGURED) {
    logger.warn('GitHub sign-in not fully configured (GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET/GITHUB_REDIRECT_URI/SESSION_SECRET) — GitHub Pro sign-in is disabled');
  }
  if (!GOOGLE_AUTH_CONFIGURED && !GITHUB_AUTH_CONFIGURED) {
    logger.warn('No Pro sign-in provider configured — only BLINK_PRO_DEV_KEY dev-login works locally');
  }
  if (process.env.NODE_ENV === 'production' && !process.env.HOST) {
    logger.warn('HOST not set — HTTPS redirect will not work in production');
  }
}

// ── Start ────────────────────────────────────────────────────────────────────
if (require.main === module) {
  const PORT   = parseInt(process.env.PORT || '3000', 10);
  const server = app.listen(PORT, () => {
    logger.info({ port: PORT, env: process.env.NODE_ENV || 'development', logsDir: LOGS_DIR }, 'Blink listening');
  });

  // ── Graceful shutdown ────────────────────────────────────────────────────────
  // process.exit() never waits for pending disk I/O, so logging right before
  // it is not enough on its own — flushLogs() must be awaited first, or the
  // "shutting down" line (and anything just before it) can be lost exactly
  // when it matters most. The 5s timer is the absolute last-resort kill if
  // something above hangs; flushLogs()'s own 2s internal timeout keeps it
  // from ever being what causes that.
  const shutdown = (signal) => {
    logger.info({ signal }, 'shutting down');
    saveStats();
    server.close(() => {
      saveSecretsSnapshot();
      secrets.clear();
      flushLogs().then(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 5_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
}

module.exports = { app };
