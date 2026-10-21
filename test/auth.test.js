'use strict';

// ── Auth: OAuth start/callback + session lifecycle (configured) ────────────
// Google/GitHub sign-in with every provider env var set: the /start
// redirects, state-cookie validation on /callback, dev-login, and
// login/logout via GET /api/auth/me. The real OAuth success path (mocked
// token exchange) lives in oauth-success.test.js; auth-unconfigured.test.js
// covers the opposite case, with nothing configured at all.
process.env.NODE_ENV           = 'test';
process.env.SECRET_KEY         = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY         = 'deadbeef'.repeat(8);
process.env.SESSION_SECRET     = 'test-session-secret';
process.env.BLINK_PRO_DEV_KEY  = 'test-dev-pro-key-000';
process.env.GOOGLE_CLIENT_ID     = 'google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'google-client-secret';
process.env.GOOGLE_REDIRECT_URI  = 'https://blink.example.com/api/auth/google/callback';
process.env.GITHUB_CLIENT_ID     = 'github-client-id';
process.env.GITHUB_CLIENT_SECRET = 'github-client-secret';
process.env.GITHUB_REDIRECT_URI  = 'https://blink.example.com/api/auth/github/callback';
process.env.LICENSES_FILE = require('node:path').join(__dirname, '.tmp-licenses-auth.json');

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const fs                        = require('node:fs');
const request                   = require('supertest');
const { app }                  = require('../server');

after(() => { try { fs.unlinkSync(process.env.LICENSES_FILE); } catch {} });

describe('OAuth start redirects (configured)', () => {
  test('GET /api/auth/google/start redirects to Google with a state cookie', async () => {
    const res = await request(app).get('/api/auth/google/start');
    assert.equal(res.status, 302);
    assert.match(res.headers.location, /^https:\/\/accounts\.google\.com\/o\/oauth2\/v2\/auth\?/);
    assert.match(res.headers.location, /client_id=google-client-id/);
    assert.ok(res.headers['set-cookie'].some(c => c.startsWith('blink_oauth_state=')));
  });

  test('GET /api/auth/github/start redirects to GitHub with a state cookie', async () => {
    const res = await request(app).get('/api/auth/github/start');
    assert.equal(res.status, 302);
    assert.match(res.headers.location, /^https:\/\/github\.com\/login\/oauth\/authorize\?/);
    assert.match(res.headers.location, /client_id=github-client-id/);
    assert.ok(res.headers['set-cookie'].some(c => c.startsWith('blink_oauth_state=')));
  });
});

describe('OAuth callback state validation', () => {
  test('google callback redirects to an error page when state is missing', async () => {
    const res = await request(app).get('/api/auth/google/callback?code=abc');
    assert.equal(res.status, 302);
    assert.equal(res.headers.location, '/?auth=error');
  });

  test('github callback redirects to an error page when state does not match the cookie', async () => {
    const res = await request(app)
      .get('/api/auth/github/callback?code=abc&state=wrong')
      .set('Cookie', 'blink_oauth_state=right');
    assert.equal(res.status, 302);
    assert.equal(res.headers.location, '/?auth=error');
  });
});

describe('Dev-login and session lifecycle', () => {
  test('GET /api/auth/dev-login redirects and sets a session cookie', async () => {
    const res = await request(app).get('/api/auth/dev-login');
    assert.equal(res.status, 302);
    assert.equal(res.headers.location, '/?auth=success');
    assert.ok(res.headers['set-cookie'].some(c => c.startsWith('blink_session=')));
  });

  test('a logged-in session reports loggedIn: true, isPro: false before any license', async () => {
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');
    const res = await agent.get('/api/auth/me');
    assert.equal(res.status, 200);
    assert.equal(res.body.loggedIn, true);
    assert.equal(res.body.email, 'dev@example.com');
    assert.equal(res.body.isPro, false);
  });

  test('logout clears the session so /me reports loggedIn: false again', async () => {
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');
    assert.equal((await agent.get('/api/auth/me')).body.loggedIn, true);

    const logoutRes = await agent.post('/api/auth/logout');
    assert.equal(logoutRes.status, 200);
    assert.equal(logoutRes.body.ok, true);

    const meRes = await agent.get('/api/auth/me');
    assert.equal(meRes.body.loggedIn, false);
  });

  test('without a session cookie, /me reports loggedIn: false', async () => {
    const res = await request(app).get('/api/auth/me');
    assert.equal(res.body.loggedIn, false);
  });
});
