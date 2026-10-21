'use strict';

// ── Rate limiter ─────────────────────────────────────────────────────────────
// Fixed-window rate limiter (no external dependencies). server.js creates one
// instance per limit it needs (create, read, email, free-usage, pro-usage);
// each tracks its own IP/account-keyed counts and can be serialized to/from
// a snapshot file so usage survives a graceful restart.
class RateLimiter {
  constructor(windowMs, max, name) {
    this.windowMs = windowMs;
    this.max      = max;
    this.name     = name || null;
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
        req.log?.warn({ limiter: this.name, retryAfter }, 'rate limit exceeded');
        return res.status(429).json({ error: 'Too many requests. Please slow down.' });
      }
      next();
    };
  }

  // For the graceful-restart snapshot — plain [key, entry] pairs, same shape
  // the Map already stores.
  serialize() {
    return [...this.store.entries()];
  }

  // Skips anything already past its window so a restored limiter never
  // holds stale counts longer than a live one would have.
  restore(entries) {
    const now = Date.now();
    for (const [key, entry] of entries) {
      if (entry.resetAt > now) this.store.set(key, entry);
    }
  }
}

module.exports = { RateLimiter };
