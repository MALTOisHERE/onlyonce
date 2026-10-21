'use strict';

process.env.NODE_ENV           = 'test';
process.env.SECRET_KEY         = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY         = 'deadbeef'.repeat(8);
process.env.CREATE_RATE_LIMIT     = '1000';
process.env.READ_RATE_LIMIT       = '1000';
process.env.FREE_USAGE_RATE_LIMIT = '1000';

const { describe, test } = require('node:test');
const assert             = require('node:assert/strict');
const crypto             = require('node:crypto');
const request            = require('supertest');
const { app }           = require('../server');

function makeFilePayload(fileBytes = Buffer.from('fake file contents')) {
  const key = crypto.randomBytes(32);
  const iv  = crypto.randomBytes(12);
  const k1  = crypto.randomBytes(32);
  const k2  = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) k2[i] = key[i] ^ k1[i];

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(fileBytes), cipher.final()]);
  const tag    = cipher.getAuthTag();

  return {
    payload: {
      ciphertext: Buffer.concat([enc, tag]).toString('base64'),
      iv:         iv.toString('base64'),
      k2:         k2.toString('base64'),
      isFile:     true,
      filename:   'notes.txt',
      mimetype:   'text/plain',
    },
    k1: k1.toString('base64'),
    fileBytes,
  };
}

describe('File secrets', () => {
  test('creates and reveals a file secret with filename and mimetype intact', async () => {
    const { payload, k1, fileBytes } = makeFilePayload();
    const createRes = await request(app).post('/api/secret').send(payload);
    assert.equal(createRes.status, 201);

    const revealRes = await request(app)
      .get(`/api/secret/${createRes.body.id}`)
      .set('X-Key', k1);
    assert.equal(revealRes.status, 200);
    assert.equal(revealRes.body.filename, 'notes.txt');
    assert.equal(revealRes.body.mimetype, 'text/plain');
    assert.equal(Buffer.from(revealRes.body.data, 'base64').toString(), fileBytes.toString());
  });

  test('rejects a file secret with a missing filename', async () => {
    const { payload } = makeFilePayload();
    delete payload.filename;
    const res = await request(app).post('/api/secret').send(payload);
    assert.equal(res.status, 400);
  });

  test('rejects a file secret with a missing mimetype', async () => {
    const { payload } = makeFilePayload();
    delete payload.mimetype;
    const res = await request(app).post('/api/secret').send(payload);
    assert.equal(res.status, 400);
  });

  test('rejects a filename over the max length', async () => {
    const { payload } = makeFilePayload();
    payload.filename = 'a'.repeat(256);
    const res = await request(app).post('/api/secret').send(payload);
    assert.equal(res.status, 400);
  });
});
