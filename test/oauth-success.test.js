'use strict';

// Google/GitHub's OAuth endpoints are hardcoded in server.js (unlike Resend's
// RESEND_BASE_URL, there's no env var to redirect them to a local server), so
// the only way to exercise the real success path is to stub global.fetch.
// server.js calls `fetch(...)` fresh on every request rather than caching a
// reference at module load, so swapping it in before each test (not just
// once at require time) works fine.
const realFetch = global.fetch;

function jsonResponse(body, ok = true) {
  return { ok, json: async () => body, text: async () => JSON.stringify(body) };
}

process.env.NODE_ENV              = 'test';
process.env.SECRET_KEY            = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY            = 'deadbeef'.repeat(8);
process.env.SESSION_SECRET        = 'test-session-secret';
process.env.GOOGLE_CLIENT_ID      = 'google-client-id';
process.env.GOOGLE_CLIENT_SECRET  = 'google-client-secret';
process.env.GOOGLE_REDIRECT_URI   = 'https://blink.example.com/api/auth/google/callback';
process.env.GITHUB_CLIENT_ID      = 'github-client-id';
process.env.GITHUB_CLIENT_SECRET  = 'github-client-secret';
process.env.GITHUB_REDIRECT_URI   = 'https://blink.example.com/api/auth/github/callback';

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const request                   = require('supertest');
const { app }                  = require('../server');

after(() => { global.fetch = realFetch; });

describe('Google OAuth callback (success path)', () => {
  test('a valid code + matching state logs the user in via a verified email', async () => {
    global.fetch = async (url) => {
      const u = String(url);
      // Check the more specific "/tokeninfo" prefix first - "tokeninfo"
      // itself starts with "token", so the order here matters.
      if (u.startsWith('https://oauth2.googleapis.com/tokeninfo')) {
        return jsonResponse({ aud: 'google-client-id', email_verified: 'true', email: 'googleuser@example.com', sub: 'g-123' });
      }
      if (u.startsWith('https://oauth2.googleapis.com/token')) {
        return jsonResponse({ id_token: 'fake-id-token' });
      }
      throw new Error(`unexpected fetch to ${u}`);
    };

    const agent = request.agent(app);
    const start = await agent.get('/api/auth/google/start');
    const stateCookie = start.headers['set-cookie'].find(c => c.startsWith('blink_oauth_state='));
    const state = stateCookie.split('=')[1].split(';')[0];

    const callback = await agent.get(`/api/auth/google/callback?code=abc&state=${state}`);
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.location, '/?auth=success');

    const me = await agent.get('/api/auth/me');
    assert.equal(me.body.loggedIn, true);
    assert.equal(me.body.email, 'googleuser@example.com');
  });

  test('an unverified email is rejected', async () => {
    global.fetch = async (url) => {
      const u = String(url);
      if (u.startsWith('https://oauth2.googleapis.com/tokeninfo')) {
        return jsonResponse({ aud: 'google-client-id', email_verified: 'false', email: 'unverified@example.com', sub: 'g-456' });
      }
      if (u.startsWith('https://oauth2.googleapis.com/token')) {
        return jsonResponse({ id_token: 'fake-id-token' });
      }
      throw new Error(`unexpected fetch to ${u}`);
    };

    const agent = request.agent(app);
    const start = await agent.get('/api/auth/google/start');
    const state = start.headers['set-cookie'].find(c => c.startsWith('blink_oauth_state=')).split('=')[1].split(';')[0];

    const callback = await agent.get(`/api/auth/google/callback?code=abc&state=${state}`);
    assert.equal(callback.headers.location, '/?auth=error');

    const me = await agent.get('/api/auth/me');
    assert.equal(me.body.loggedIn, false);
  });
});

describe('GitHub OAuth callback (success path)', () => {
  test('a valid code + matching state logs the user in using the primary verified email', async () => {
    global.fetch = async (url) => {
      const u = String(url);
      if (u.startsWith('https://github.com/login/oauth/access_token')) {
        return jsonResponse({ access_token: 'fake-gh-token' });
      }
      if (u.startsWith('https://api.github.com/user/emails')) {
        return jsonResponse([
          { email: 'secondary@example.com', primary: false, verified: true },
          { email: 'ghuser@example.com',    primary: true,  verified: true },
        ]);
      }
      throw new Error(`unexpected fetch to ${u}`);
    };

    const agent = request.agent(app);
    const start = await agent.get('/api/auth/github/start');
    const state = start.headers['set-cookie'].find(c => c.startsWith('blink_oauth_state=')).split('=')[1].split(';')[0];

    const callback = await agent.get(`/api/auth/github/callback?code=abc&state=${state}`);
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.location, '/?auth=success');

    const me = await agent.get('/api/auth/me');
    assert.equal(me.body.loggedIn, true);
    assert.equal(me.body.email, 'ghuser@example.com');
  });

  test('an account with no verified email is rejected', async () => {
    global.fetch = async (url) => {
      const u = String(url);
      if (u.startsWith('https://github.com/login/oauth/access_token')) {
        return jsonResponse({ access_token: 'fake-gh-token' });
      }
      if (u.startsWith('https://api.github.com/user/emails')) {
        return jsonResponse([{ email: 'unverified@example.com', primary: true, verified: false }]);
      }
      throw new Error(`unexpected fetch to ${u}`);
    };

    const agent = request.agent(app);
    const start = await agent.get('/api/auth/github/start');
    const state = start.headers['set-cookie'].find(c => c.startsWith('blink_oauth_state=')).split('=')[1].split(';')[0];

    const callback = await agent.get(`/api/auth/github/callback?code=abc&state=${state}`);
    assert.equal(callback.headers.location, '/?auth=error');
  });
});
