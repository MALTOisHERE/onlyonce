'use strict';

// ── Email rate-limit message ─────────────────────────────────────────────────
// Regression guard: asserts the real "too many verification emails" error
// body on the 2nd OTP request within an hour, not a generic 429 message.
const http = require('node:http');

const mockResend = http.createServer((req, res) => {
  req.on('data', () => {});
  req.on('end', () => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: 'mock-email-id' }));
  });
});
const MOCK_RESEND_PORT = 58733;
mockResend.listen(MOCK_RESEND_PORT, '127.0.0.1');

process.env.NODE_ENV              = 'test';
process.env.SECRET_KEY            = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY            = 'deadbeef'.repeat(8);
process.env.RESEND_API_KEY        = 'test-resend-key';
process.env.RESEND_BASE_URL       = `http://127.0.0.1:${MOCK_RESEND_PORT}`;
process.env.EMAIL_RATE_LIMIT      = '1';
process.env.FREE_USAGE_RATE_LIMIT = '1000'; // not under test here
process.env.CREATE_RATE_LIMIT     = '1000';
process.env.READ_RATE_LIMIT       = '1000';

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const crypto                    = require('node:crypto');
const request                   = require('supertest');
const { app }                  = require('../server');

after(() => { mockResend.close(); });

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

describe('Verification-email rate limit message', () => {
  test('the 2nd OTP email request within an hour returns the real email-limit message', async () => {
    const first = await request(app).post('/api/secret').send({ ...makePayload(), recipientEmail: 'a@example.com' });
    assert.equal(first.status, 201);

    const second = await request(app).post('/api/secret').send({ ...makePayload(), recipientEmail: 'b@example.com' });
    assert.equal(second.status, 429);
    assert.match(second.body.error, /Too many verification emails/);
    assert.ok(second.headers['retry-after']);
  });
});
