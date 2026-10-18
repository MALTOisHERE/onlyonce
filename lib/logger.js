'use strict';

// Central structured logger (pino). Every log line goes to BOTH the console
// (pretty-printed, for `docker logs` / a terminal) and a rotating file under
// LOGS_DIR (raw NDJSON, for durability across container restarts and for
// any future log tooling to parse). One file per day, gzip the old ones,
// never keep more than 14 days on disk.
//
// Redaction is a backstop, not the whole story: call sites must still never
// pass a whole req.body/req.headers object into a log call. Only ever log
// specific, chosen fields (an id fragment, a boolean, a count) — exactly
// the same discipline the OTP emails already use for link IDs. The `redact`
// list below exists to catch the field names that must NEVER reach a log
// line even if something upstream slips: full secrets, OTP codes, license
// keys, passphrases, encryption keys, session cookies.

const fs   = require('fs');
const path = require('path');
const pino = require('pino');
const { createStream } = require('rotating-file-stream');

const LOG_LEVEL  = process.env.LOG_LEVEL  || (process.env.NODE_ENV === 'test' ? 'silent' : 'info');
const LOGS_DIR   = process.env.LOGS_DIR   || path.join(__dirname, '..', 'data', 'logs');
const LOG_PRETTY = process.env.LOG_PRETTY !== 'false';

fs.mkdirSync(LOGS_DIR, { recursive: true });

const fileStream = createStream('app.log', {
  path:      LOGS_DIR,
  interval:  '1d',
  maxFiles:  14,
  compress:  'gzip',
});

const REDACT_PATHS = [
  'req.headers.cookie',
  'req.headers.authorization',
  'req.headers["x-key"]',
  'req.headers["x-otp"]',
  'req.headers["x-passphrase"]',
  '*.secret', '*.plaintext', '*.ciphertext', '*.otp', '*.passphrase',
  '*.licenseKey', '*.k1', '*.k2', '*.k3', '*.k4', '*.ciphertext',
  'secret', 'plaintext', 'ciphertext', 'otp', 'passphrase',
  'licenseKey', 'k1', 'k2', 'k3', 'k4',
];

const consoleStream = LOG_PRETTY
  ? require('pino-pretty')({
      colorize:      true,
      translateTime: 'yyyy-mm-dd HH:MM:ss.l',
      ignore:        'pid,hostname',
    })
  : process.stdout;

const logger = pino(
  {
    level:     LOG_LEVEL,
    redact:    { paths: REDACT_PATHS, censor: '[redacted]' },
    timestamp: pino.stdTimeFunctions.isoTime,
  },
  pino.multistream([
    { level: LOG_LEVEL, stream: consoleStream },
    { level: LOG_LEVEL, stream: fileStream },
  ])
);

// process.exit() does not wait for pending disk I/O — calling it right after
// a burst of writes can lose every one of them, since the rotating file
// stream batches writes asynchronously. A stream's write callback only fires
// once that exact chunk is flushed, and streams preserve order, so writing
// one more (empty) chunk and waiting for ITS callback guarantees everything
// queued before it already reached disk. Callers MUST await this before
// process.exit() in any deliberate shutdown path. The timeout is a safety
// net so shutdown can never hang forever if the disk itself is stuck.
function flushLogs(timeoutMs = 2000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(); } };
    const timer = setTimeout(finish, timeoutMs);
    if (timer.unref) timer.unref();
    fileStream.write('', () => { clearTimeout(timer); finish(); });
  });
}

// Adding a listener suppresses Node's default crash-on-uncaught behavior, so
// this MUST re-exit itself — leaving the process running after state may be
// corrupted is worse than crashing. flushLogs() first so the fatal line
// (and anything just before it) actually reaches disk before exit.
process.on('uncaughtException', (err) => {
  logger.fatal({ err }, 'uncaught exception');
  flushLogs().then(() => process.exit(1));
});
process.on('unhandledRejection', (reason) => {
  logger.fatal({ err: reason }, 'unhandled rejection');
  flushLogs().then(() => process.exit(1));
});

module.exports = { logger, LOGS_DIR, flushLogs };
