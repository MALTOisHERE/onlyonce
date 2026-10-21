'use strict';

process.env.NODE_ENV   = 'test';
process.env.SECRET_KEY = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY = 'deadbeef'.repeat(8);

const { describe, test } = require('node:test');
const assert             = require('node:assert/strict');
const request            = require('supertest');
const { app }            = require('../server');

describe('GET /api/config', () => {
  test('returns the app version and a null checkout url by default', async () => {
    const res = await request(app).get('/api/config');
    assert.equal(res.status, 200);
    assert.equal(typeof res.body.version, 'string');
    assert.equal(res.body.proCheckoutUrl, null);
  });

  test('sets Cache-Control: no-store', async () => {
    const res = await request(app).get('/api/config');
    assert.equal(res.headers['cache-control'], 'no-store');
  });
});
