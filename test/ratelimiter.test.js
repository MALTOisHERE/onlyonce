'use strict';

const { describe, test } = require('node:test');
const assert             = require('node:assert/strict');
const { RateLimiter }    = require('../lib/ratelimiter');

describe('RateLimiter', () => {
  test('allows requests within the limit', () => {
    const rl = new RateLimiter(60_000, 3);
    assert.equal(rl.check('1.2.3.4'), 0);
    assert.equal(rl.check('1.2.3.4'), 0);
    assert.equal(rl.check('1.2.3.4'), 0);
  });

  test('blocks the request that exceeds the limit', () => {
    const rl = new RateLimiter(60_000, 2);
    rl.check('1.2.3.4');
    rl.check('1.2.3.4');
    assert.ok(rl.check('1.2.3.4') > 0, 'should return positive retry-after');
  });

  test('returns a positive retry-after value in seconds', () => {
    const rl = new RateLimiter(60_000, 1);
    rl.check('5.5.5.5');
    const retryAfter = rl.check('5.5.5.5');
    assert.ok(retryAfter > 0 && retryAfter <= 60);
  });

  test('tracks different IPs independently', () => {
    const rl = new RateLimiter(60_000, 1);
    assert.equal(rl.check('10.0.0.1'), 0);
    assert.ok(rl.check('10.0.0.1') > 0, 'first IP should be blocked');
    assert.equal(rl.check('10.0.0.2'), 0, 'second IP should still be allowed');
  });

  test('uses a fallback bucket for null or undefined IP', () => {
    const rl = new RateLimiter(60_000, 1);
    assert.equal(rl.check(null), 0);
    assert.ok(rl.check(undefined) > 0, 'fallback bucket should be exhausted');
  });

  test('middleware returns 429 when limit is exceeded', async () => {
    const rl = new RateLimiter(60_000, 1);
    let blocked = false;
    const req  = { ip: '9.9.9.9' };
    const res  = {
      status(code) { blocked = code === 429; return this; },
      setHeader() { return this; },
      json() { return this; },
    };
    const next = () => {};
    rl.middleware()(req, res, next); // first: allowed
    rl.middleware()(req, res, next); // second: blocked
    assert.ok(blocked);
  });
});
