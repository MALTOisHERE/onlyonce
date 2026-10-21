'use strict';

// ── Graceful-restart snapshot ────────────────────────────────────────────────
// Verifies the graceful-restart snapshot round trip: pending secrets and
// rate-limiter usage counts must survive a deploy instead of silently
// resetting. A real SIGTERM can't drive this reliably across platforms
// (Windows in particular doesn't deliver it to a child process the way
// POSIX does), so this calls the exported save functions directly — the
// same ones the real shutdown handler calls — then re-requires the module
// fresh against the same snapshot files to simulate the new process
// starting up, exactly as `loadSecretsSnapshot`/`loadRateLimitsSnapshot` do
// on every real boot.
const path = require('node:path');
const fs   = require('node:fs');

const TMP_DIR = __dirname;
const SECRETS_SNAPSHOT_FILE     = path.join(TMP_DIR, '.tmp-secrets-snapshot.json');
const RATE_LIMITS_SNAPSHOT_FILE = path.join(TMP_DIR, '.tmp-rate-limits-snapshot.json');

process.env.NODE_ENV                  = 'test';
process.env.SECRET_KEY                = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY                = 'deadbeef'.repeat(8);
process.env.SECRETS_SNAPSHOT_FILE     = SECRETS_SNAPSHOT_FILE;
process.env.RATE_LIMITS_SNAPSHOT_FILE = RATE_LIMITS_SNAPSHOT_FILE;
process.env.CREATE_RATE_LIMIT         = '1000';
process.env.READ_RATE_LIMIT           = '1000';
process.env.FREE_USAGE_RATE_LIMIT     = '2';

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const crypto                    = require('node:crypto');
const request                   = require('supertest');

const SERVER_PATH = require.resolve('../server');

function cleanupSnapshotFiles() {
  for (const f of [SECRETS_SNAPSHOT_FILE, RATE_LIMITS_SNAPSHOT_FILE, SECRETS_SNAPSHOT_FILE + '.tmp', RATE_LIMITS_SNAPSHOT_FILE + '.tmp']) {
    try { fs.unlinkSync(f); } catch {}
  }
}
after(cleanupSnapshotFiles);

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

describe('Graceful-restart snapshot', () => {
  test('a pending secret and the free-tier usage count both survive a simulated restart', async () => {
    cleanupSnapshotFiles();

    // ── "Before the deploy" ──────────────────────────────────────────────
    const before = require(SERVER_PATH);
    const { payload, k1, plaintext } = makePayload('still here after the restart');
    const createRes = await request(before.app).post('/api/secret').send(payload);
    assert.equal(createRes.status, 201);
    const { id } = createRes.body;

    // Use up the free-tier daily limit (2) so the restored count can be
    // checked precisely: the secret above was create #1, this is #2.
    const secondCreate = await request(before.app).post('/api/secret').send(makePayload('second').payload);
    assert.equal(secondCreate.status, 201);

    assert.equal(before.secrets.size, 2, 'both secrets should still be pending (unviewed)');

    before.saveSecretsSnapshot();
    before.saveRateLimitsSnapshot();
    assert.ok(fs.existsSync(SECRETS_SNAPSHOT_FILE), 'secrets snapshot file should have been written');
    assert.ok(fs.existsSync(RATE_LIMITS_SNAPSHOT_FILE), 'rate-limits snapshot file should have been written');

    const savedSecrets = JSON.parse(fs.readFileSync(SECRETS_SNAPSHOT_FILE, 'utf8'));
    assert.equal(savedSecrets.length, 2);
    assert.ok(savedSecrets.some(([savedId]) => savedId === id));

    const savedLimits = JSON.parse(fs.readFileSync(RATE_LIMITS_SNAPSHOT_FILE, 'utf8'));
    assert.ok(Array.isArray(savedLimits['free-usage']), 'free-usage limiter state should be serialized by name');

    // ── Simulate the process exiting and a fresh one starting up ──────────
    delete require.cache[SERVER_PATH];
    const after_ = require(SERVER_PATH);

    // The snapshot is single-use: loaded once, then deleted immediately.
    assert.ok(!fs.existsSync(SECRETS_SNAPSHOT_FILE), 'secrets snapshot should be consumed after loading');
    assert.ok(!fs.existsSync(RATE_LIMITS_SNAPSHOT_FILE), 'rate-limits snapshot should be consumed after loading');

    // The pending secret survived and still decrypts correctly.
    const revealRes = await request(after_.app).get(`/api/secret/${id}`).set('X-Key', k1);
    assert.equal(revealRes.status, 200);
    assert.equal(revealRes.body.plaintext, plaintext);

    // The free-tier count (2 used, limit 2) carried over, not reset to 0 -
    // a 3rd create should be rejected immediately on the restored process.
    const thirdCreate = await request(after_.app).post('/api/secret').send(makePayload('third').payload);
    assert.equal(thirdCreate.status, 429);
  });

  test('an already-expired secret in the snapshot is dropped, not restored', async () => {
    cleanupSnapshotFiles();
    delete require.cache[SERVER_PATH]; // fresh instance - the previous test left its rate-limit counters exhausted
    const mod = require(SERVER_PATH);
    const { payload } = makePayload('about to expire');
    const createRes = await request(mod.app).post('/api/secret').send(payload);
    assert.equal(createRes.status, 201);
    const { id } = createRes.body;

    // Force it into the past directly on the live Map, then snapshot it.
    mod.secrets.get(id).expiresAt = Date.now() - 1000;
    mod.saveSecretsSnapshot();
    mod.saveRateLimitsSnapshot();

    delete require.cache[SERVER_PATH];
    const fresh = require(SERVER_PATH);
    assert.equal(fresh.secrets.has(id), false, 'an expired secret should not be restored into the new process');
  });
});
