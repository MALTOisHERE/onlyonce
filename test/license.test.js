'use strict';

// ── License activate/deactivate + Pro-gated secret features ─────────────────
// Covers the dev-key activation path end to end (no real Lemon Squeezy
// calls), then every Pro-only option on POST /api/secret - passphrase,
// multi-view, 7-day expiry, view notifications - confirming each is
// rejected for a free account and works once Pro is activated.
process.env.NODE_ENV       = 'test';
process.env.SECRET_KEY     = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY     = 'deadbeef'.repeat(8);
process.env.SESSION_SECRET = 'test-session-secret';
process.env.BLINK_PRO_DEV_KEY     = 'test-dev-pro-key-111';
process.env.CREATE_RATE_LIMIT     = '1000';
process.env.READ_RATE_LIMIT       = '1000';
process.env.FREE_USAGE_RATE_LIMIT = '1000';
process.env.PRO_USAGE_RATE_LIMIT  = '1000';
process.env.LICENSES_FILE = require('node:path').join(__dirname, '.tmp-licenses-license.json');

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const crypto                    = require('node:crypto');
const fs                        = require('node:fs');
const request                   = require('supertest');
const { app }                  = require('../server');

after(() => { try { fs.unlinkSync(process.env.LICENSES_FILE); } catch {} });

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
    payload: {
      ciphertext: Buffer.concat([enc, tag]).toString('base64'),
      iv:         iv.toString('base64'),
      k2:         k2.toString('base64'),
    },
    k1: k1.toString('base64'),
    plaintext,
  };
}

describe('POST /api/license/activate', () => {
  test('requires a session', async () => {
    const res = await request(app).post('/api/license/activate').send({ licenseKey: 'whatever' });
    assert.equal(res.status, 401);
    assert.equal(res.body.valid, false);
    assert.equal(res.body.error, 'login_required');
  });

  test('rejects a malformed license key', async () => {
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');
    const res = await agent.post('/api/license/activate').send({ licenseKey: '!!!' });
    assert.equal(res.status, 200);
    assert.equal(res.body.valid, false);
    assert.equal(res.body.error, 'invalid');
  });

  test('accepts the dev key and marks the account Pro', async () => {
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');
    const res = await agent.post('/api/license/activate').send({ licenseKey: process.env.BLINK_PRO_DEV_KEY });
    assert.equal(res.status, 200);
    assert.equal(res.body.valid, true);

    const me = await agent.get('/api/auth/me');
    assert.equal(me.body.isPro, true);
  });

  test('re-activating the same key is a no-op that stays valid', async () => {
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');
    await agent.post('/api/license/activate').send({ licenseKey: process.env.BLINK_PRO_DEV_KEY });
    const res = await agent.post('/api/license/activate').send({ licenseKey: process.env.BLINK_PRO_DEV_KEY });
    assert.equal(res.body.valid, true);
  });
});

describe('POST /api/license/deactivate', () => {
  test('requires a session', async () => {
    const res = await request(app).post('/api/license/deactivate');
    assert.equal(res.status, 401);
    assert.equal(res.body.ok, false);
  });

  test('clears Pro status for the account', async () => {
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');
    await agent.post('/api/license/activate').send({ licenseKey: process.env.BLINK_PRO_DEV_KEY });
    assert.equal((await agent.get('/api/auth/me')).body.isPro, true);

    const res = await agent.post('/api/license/deactivate');
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal((await agent.get('/api/auth/me')).body.isPro, false);
  });

  test('is a no-op when the account has no active license', async () => {
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');
    const res = await agent.post('/api/license/deactivate');
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
  });
});

// Helper: a logged-in, Pro-activated agent, ready to hit /api/secret.
async function proAgent() {
  const agent = request.agent(app);
  await agent.get('/api/auth/dev-login');
  await agent.post('/api/license/activate').send({ licenseKey: process.env.BLINK_PRO_DEV_KEY });
  return agent;
}

describe('Pro-gated secret features', () => {
  test('passphrase protection is rejected for a free account', async () => {
    const { payload } = makePayload();
    const res = await request(app).post('/api/secret').send({ ...payload, passphrase: 'open-sesame' });
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'pro_required');
    assert.equal(res.body.feature, 'passphrase protection');
  });

  test('multi-view (views > 1) is rejected for a free account', async () => {
    const { payload } = makePayload();
    const res = await request(app).post('/api/secret').send({ ...payload, views: 3 });
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'pro_required');
    assert.equal(res.body.feature, 'multi-view links');
  });

  test('7-day expiry is rejected for a free account', async () => {
    const { payload } = makePayload();
    const res = await request(app).post('/api/secret').send({ ...payload, expiresIn: 168 });
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'pro_required');
    assert.equal(res.body.feature, '7-day expiry');
  });

  test('a Pro account can create a 7-day, multi-view secret', async () => {
    const agent = await proAgent();
    const { payload } = makePayload();
    const res = await agent.post('/api/secret').send({ ...payload, views: 3, expiresIn: 168 });
    assert.equal(res.status, 201);
  });

  test('rejects an out-of-range views value even for Pro', async () => {
    const agent = await proAgent();
    const { payload } = makePayload();
    const res = await agent.post('/api/secret').send({ ...payload, views: 99 });
    assert.equal(res.status, 400);
  });

  test('view notifications without an email provider configured return 503, even for Pro', async () => {
    const agent = await proAgent();
    const { payload } = makePayload();
    const res = await agent.post('/api/secret').send({ ...payload, notifyEmail: 'owner@example.com' });
    assert.equal(res.status, 503);
  });

  describe('passphrase-protected reveal', () => {
    test('full round trip: correct passphrase decrypts, wrong passphrase is rejected', async () => {
      const agent = await proAgent();
      const { payload, k1, plaintext } = makePayload('shh, a real secret');
      const createRes = await agent.post('/api/secret').send({ ...payload, passphrase: 'correct horse' });
      assert.equal(createRes.status, 201);
      const { id } = createRes.body;

      // Missing passphrase entirely
      const missing = await request(app).get(`/api/secret/${id}`).set('X-Key', k1);
      assert.equal(missing.status, 403);
      assert.equal(missing.body.error, 'passphrase_required');

      // Wrong passphrase
      const wrong = await request(app)
        .get(`/api/secret/${id}`)
        .set('X-Key', k1)
        .set('X-Passphrase', 'nope');
      assert.equal(wrong.status, 403);
      assert.equal(wrong.body.error, 'invalid_passphrase');
      assert.equal(wrong.body.attemptsLeft, 4);

      // Correct passphrase
      const right = await request(app)
        .get(`/api/secret/${id}`)
        .set('X-Key', k1)
        .set('X-Passphrase', 'correct horse');
      assert.equal(right.status, 200);
      assert.equal(right.body.plaintext, plaintext);
    });

    test('destroys the secret after 5 wrong passphrase attempts', async () => {
      const agent = await proAgent();
      const { payload, k1 } = makePayload('will self-destruct');
      const createRes = await agent.post('/api/secret').send({ ...payload, passphrase: 'correct horse' });
      const { id } = createRes.body;

      let last;
      for (let i = 0; i < 5; i++) {
        last = await request(app)
          .get(`/api/secret/${id}`)
          .set('X-Key', k1)
          .set('X-Passphrase', 'wrong');
      }
      assert.equal(last.status, 410);
      assert.equal(last.body.error, 'too_many_attempts');

      // Secret is gone even with the right passphrase now
      const after = await request(app)
        .get(`/api/secret/${id}`)
        .set('X-Key', k1)
        .set('X-Passphrase', 'correct horse');
      assert.equal(after.status, 404);
    });
  });

  describe('multi-view secrets', () => {
    test('a 3-view secret survives two reveals and is gone after the third', async () => {
      const agent = await proAgent();
      const { payload, k1, plaintext } = makePayload('shared with a small team');
      const createRes = await agent.post('/api/secret').send({ ...payload, views: 3 });
      const { id } = createRes.body;

      const first = await request(app).get(`/api/secret/${id}`).set('X-Key', k1);
      assert.equal(first.status, 200);
      assert.equal(first.body.plaintext, plaintext);
      assert.equal(first.body.viewsLeft, 2);

      const second = await request(app).get(`/api/secret/${id}`).set('X-Key', k1);
      assert.equal(second.status, 200);
      assert.equal(second.body.viewsLeft, 1);

      const third = await request(app).get(`/api/secret/${id}`).set('X-Key', k1);
      assert.equal(third.status, 200);
      assert.equal(third.body.viewsLeft, 0);

      const fourth = await request(app).get(`/api/secret/${id}`).set('X-Key', k1);
      assert.equal(fourth.status, 404);
    });
  });
});
