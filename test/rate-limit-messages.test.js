'use strict';

// ── Free-tier rate-limit message ─────────────────────────────────────────────
// Deliberately low free-tier limit so this test can actually trip it —
// regression coverage for a real bug: the frontend used to show a generic
// "too many requests" message for every 429, masking the server's real one
// (the free-tier daily cap). This asserts the server's response body directly.
process.env.NODE_ENV              = 'test';
process.env.SECRET_KEY            = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY            = 'deadbeef'.repeat(8);
process.env.FREE_USAGE_RATE_LIMIT = '2';
process.env.EMAIL_RATE_LIMIT      = '1000'; // not under test here
process.env.CREATE_RATE_LIMIT     = '1000'; // keep the burst limiter out of the way
process.env.READ_RATE_LIMIT       = '1000';

const { describe, test } = require('node:test');
const assert             = require('node:assert/strict');
const crypto             = require('node:crypto');
const request            = require('supertest');
const { app }           = require('../server');

function makePayload(plaintext = 'test secret value') {
  const key = crypto.randomBytes(32);
  const iv  = crypto.randomBytes(12);
  const k1  = crypto.randomBytes(32);
  const k2  = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) k2[i] = key[i] ^ k1[i];

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();

  return {
    ciphertext: Buffer.concat([enc, tag]).toString('base64'),
    iv:         iv.toString('base64'),
    k2:         k2.toString('base64'),
  };
}

describe('Free-tier daily limit message', () => {
  test('the 3rd secret of the day for a free account returns the real daily-cap message, not a generic one', async () => {
    await request(app).post('/api/secret').send(makePayload());
    await request(app).post('/api/secret').send(makePayload());
    const res = await request(app).post('/api/secret').send(makePayload());

    assert.equal(res.status, 429);
    assert.match(res.body.error, /Free plan is limited to 2 secrets per day/);
    assert.ok(res.headers['retry-after']);
  });
});
