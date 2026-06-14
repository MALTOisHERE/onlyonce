'use strict';

// Fixed-window rate limiter (no external dependencies)
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

module.exports = { RateLimiter };
