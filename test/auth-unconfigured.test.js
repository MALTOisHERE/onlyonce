'use strict';

// No SESSION_SECRET, no OAuth client envs, no BLINK_PRO_DEV_KEY — exercises
// the "nothing configured" state every self-hosted instance starts in.
process.env.NODE_ENV   = 'test';
process.env.SECRET_KEY = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY = 'deadbeef'.repeat(8);
delete process.env.SESSION_SECRET;
delete process.env.GOOGLE_CLIENT_ID;
delete process.env.GOOGLE_CLIENT_SECRET;
delete process.env.GOOGLE_REDIRECT_URI;
delete process.env.GITHUB_CLIENT_ID;
delete process.env.GITHUB_CLIENT_SECRET;
delete process.env.GITHUB_REDIRECT_URI;
delete process.env.BLINK_PRO_DEV_KEY;

const { describe, test } = require('node:test');
const assert             = require('node:assert/strict');
const request            = require('supertest');
const { app }            = require('../server');

describe('Auth when no provider is configured', () => {
  test('GET /api/auth/google/start returns 503', async () => {
    const res = await request(app).get('/api/auth/google/start');
    assert.equal(res.status, 503);
  });

  test('GET /api/auth/github/start returns 503', async () => {
    const res = await request(app).get('/api/auth/github/start');
    assert.equal(res.status, 503);
  });

  test('GET /api/auth/google/callback returns 503', async () => {
    const res = await request(app).get('/api/auth/google/callback?code=x&state=y');
    assert.equal(res.status, 503);
  });

  test('GET /api/auth/github/callback returns 503', async () => {
    const res = await request(app).get('/api/auth/github/callback?code=x&state=y');
    assert.equal(res.status, 503);
  });

  test('dev-login route is not registered without BLINK_PRO_DEV_KEY', async () => {
    const res = await request(app).get('/api/auth/dev-login');
    assert.equal(res.status, 404);
  });

  test('GET /api/auth/me reports loggedIn: false without a session secret', async () => {
    const res = await request(app).get('/api/auth/me');
    assert.equal(res.status, 200);
    assert.equal(res.body.loggedIn, false);
  });
});
