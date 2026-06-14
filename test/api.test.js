'use strict';

// Set env vars before requiring server (K3/K4/rates read at module load)
process.env.NODE_ENV          = 'test';
process.env.SECRET_KEY        = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY        = 'deadbeef'.repeat(8); // 64 hex chars = 32 bytes
process.env.CREATE_RATE_LIMIT = '1000';
process.env.READ_RATE_LIMIT   = '1000';

const { describe, test } = require('node:test');
const assert             = require('node:assert/strict');
const crypto             = require('node:crypto');
const request            = require('supertest');
const { app }            = require('../server');

// Build a valid AES-256-GCM payload matching what the browser sends
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

describe('POST /api/secret', () => {
  test('creates a secret and returns a UUID', async () => {
    const { payload } = makePayload();
    const res = await request(app).post('/api/secret').send(payload);
    assert.equal(res.status, 201);
    assert.match(res.body.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  test('rejects a payload with missing fields', async () => {
    const res = await request(app).post('/api/secret').send({ ciphertext: 'abc' });
    assert.equal(res.status, 400);
  });

  test('rejects an invalid iv length', async () => {
    const { payload } = makePayload();
    const res = await request(app).post('/api/secret').send({ ...payload, iv: 'tooshort' });
    assert.equal(res.status, 400);
  });

  test('rejects an invalid k2 length', async () => {
    const { payload } = makePayload();
    const res = await request(app).post('/api/secret').send({ ...payload, k2: 'tooshort' });
    assert.equal(res.status, 400);
  });

  test('rejects ciphertext that is too short', async () => {
    const { payload } = makePayload();
    const res = await request(app).post('/api/secret').send({ ...payload, ciphertext: 'abc' });
    assert.equal(res.status, 400);
  });

  test('accepts all valid expiresIn values', async () => {
    for (const expiresIn of [1, 6, 24, 48]) {
      const { payload } = makePayload();
      const res = await request(app).post('/api/secret').send({ ...payload, expiresIn });
      assert.equal(res.status, 201, `expiresIn=${expiresIn} should be accepted`);
    }
  });

  test('ignores an invalid expiresIn and falls back to 48h', async () => {
    const { payload } = makePayload();
    const res = await request(app).post('/api/secret').send({ ...payload, expiresIn: 999 });
    assert.equal(res.status, 201);
  });
});

describe('GET /api/secret/:id', () => {
  test('returns 400 for a non-UUID id', async () => {
    const key = Buffer.alloc(32).toString('base64');
    const res = await request(app).get('/api/secret/not-a-uuid').set('X-Key', key);
    assert.equal(res.status, 400);
  });

  test('returns 400 when the X-Key header is missing', async () => {
    const res = await request(app).get('/api/secret/00000000-0000-4000-8000-000000000000');
    assert.equal(res.status, 400);
  });

  test('returns 404 for an unknown id', async () => {
    const key = Buffer.alloc(32).toString('base64');
    const res = await request(app)
      .get('/api/secret/00000000-0000-4000-8000-000000000000')
      .set('X-Key', key);
    assert.equal(res.status, 404);
  });

  test('full create then reveal flow decrypts plaintext correctly', async () => {
    const { payload, k1, plaintext } = makePayload('super secret password 123!');

    const createRes = await request(app).post('/api/secret').send(payload);
    assert.equal(createRes.status, 201);

    const revealRes = await request(app)
      .get(`/api/secret/${createRes.body.id}`)
      .set('X-Key', k1);
    assert.equal(revealRes.status, 200);
    assert.equal(revealRes.body.plaintext, plaintext);
  });

  test('secret is deleted after the first reveal (view once)', async () => {
    const { payload, k1 } = makePayload('one-time secret');

    const createRes = await request(app).post('/api/secret').send(payload);
    assert.equal(createRes.status, 201);
    const { id } = createRes.body;

    const first = await request(app).get(`/api/secret/${id}`).set('X-Key', k1);
    assert.equal(first.status, 200);

    const second = await request(app).get(`/api/secret/${id}`).set('X-Key', k1);
    assert.equal(second.status, 404);
  });

  test('returns 400 when a wrong key is provided', async () => {
    const { payload } = makePayload('secret');
    const createRes = await request(app).post('/api/secret').send(payload);
    assert.equal(createRes.status, 201);

    const wrongKey = crypto.randomBytes(32).toString('base64');
    const res = await request(app)
      .get(`/api/secret/${createRes.body.id}`)
      .set('X-Key', wrongKey);
    assert.equal(res.status, 400); // decryption fails
  });
});

describe('GET /api/stats', () => {
  test('returns a numeric secretsCreated count', async () => {
    const res = await request(app).get('/api/stats');
    assert.equal(res.status, 200);
    assert.equal(typeof res.body.secretsCreated, 'number');
  });
});
