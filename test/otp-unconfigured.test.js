'use strict';

process.env.NODE_ENV   = 'test';
process.env.SECRET_KEY = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY = 'deadbeef'.repeat(8);
delete process.env.RESEND_API_KEY;

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

describe('Email OTP when no provider is configured', () => {
  test('POST /api/secret with recipientEmail returns 503', async () => {
    const payload = makePayload();
    const res = await request(app).post('/api/secret').send({ ...payload, recipientEmail: 'friend@example.com' });
    assert.equal(res.status, 503);
  });
});
