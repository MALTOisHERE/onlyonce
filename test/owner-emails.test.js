'use strict';

process.env.NODE_ENV          = 'test';
process.env.SECRET_KEY        = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY        = 'deadbeef'.repeat(8);
process.env.SESSION_SECRET    = 'test-session-secret';
process.env.BLINK_PRO_DEV_KEY = 'test-dev-pro-key-owner';
process.env.OWNER_EMAILS      = 'dev@example.com, someone-else@example.com';
process.env.LICENSES_FILE     = require('node:path').join(__dirname, '.tmp-licenses-owner.json');

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const fs                        = require('node:fs');
const request                   = require('supertest');
const { app }                  = require('../server');

after(() => { try { fs.unlinkSync(process.env.LICENSES_FILE); } catch {} });

describe('OWNER_EMAILS allowlist', () => {
  test('an owner account is Pro with no license activated at all', async () => {
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login'); // logs in as dev@example.com

    const me = await agent.get('/api/auth/me');
    assert.equal(me.body.loggedIn, true);
    assert.equal(me.body.isPro, true);
    assert.equal(me.body.isOwner, true);
  });

  test('an owner account can use Pro-gated secret features without a license', async () => {
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');

    const crypto = require('node:crypto');
    const key = crypto.randomBytes(32);
    const iv  = crypto.randomBytes(12);
    const k1  = crypto.randomBytes(32);
    const k2  = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) k2[i] = key[i] ^ k1[i];
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc    = Buffer.concat([cipher.update('owner secret', 'utf8'), cipher.final()]);
    const tag    = cipher.getAuthTag();

    const res = await agent.post('/api/secret').send({
      ciphertext: Buffer.concat([enc, tag]).toString('base64'),
      iv: iv.toString('base64'),
      k2: k2.toString('base64'),
      passphrase: 'owner-passphrase',
    });
    assert.equal(res.status, 201);
  });
});
