# Blink

Share secrets that disappear. Once seen, forever gone.

Blink is a self-hosted, end-to-end encrypted secret sharing app. Paste a password or generate one, get a one-time link — the secret is deleted the moment it's opened.

## How it works

1. You enter or generate a secret
2. The secret is encrypted **in your browser** using AES-256-GCM (Web Crypto API)
3. Only the encrypted ciphertext is sent to the server — the decryption key never leaves your device
4. The key is embedded in the URL fragment (`#key`) which is never sent to the server
5. When the recipient opens the link, it's decrypted client-side and **immediately deleted from the server**

## Features

- **End-to-end encrypted** — AES-256-GCM, key lives only in the URL fragment
- **View once** — secret is deleted on first read, atomically
- **48-hour TTL** — unviewed secrets are automatically purged after 48 hours
- **Email verification (optional)** — lock a link to a specific recipient; they must enter a 6-digit code sent to their inbox to reveal the secret. Wrong code 5 times → secret self-destructs
- **Password generator** — configurable length, charset, with strength meter
- **Rate limited** — 10 creates / 30 reads per minute per IP; 3 email OTPs per hour per IP
- **No database** — in-memory store, ephemeral by design
- **Security headers** — CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy

## Stack

- **Backend:** Node.js 18 + Express
- **Email:** Resend
- **Frontend:** Vanilla JS, Web Crypto API
- **Deploy:** Docker + nginx reverse proxy + Cloudflare

## Self-hosting

### Requirements

- Docker and Docker Compose
- A domain with Cloudflare (or any reverse proxy)
- A [Resend](https://resend.com) account for email OTP (optional)

### Run locally

```bash
git clone https://github.com/MALTOisHERE/onlyonce.git
cd onlyonce
npm install
node server.js
```

Open `http://localhost:3000`.

### Deploy with Docker

```bash
docker compose up -d --build
```

The container binds to `127.0.0.1:3001` — put nginx in front.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ENV` | `development` | Set to `production` to enable HTTPS redirect and HSTS |
| `PORT` | `3000` | Port to listen on |
| `HOST` | — | Your domain (e.g. `blink.malto.icu`). Required in production |
| `RESEND_API_KEY` | — | Resend API key. Required for email OTP feature |
| `EMAIL_FROM` | `Blink <noreply@malto.icu>` | Sender address (must be a verified domain in Resend) |

Copy `.env.example` to `.env` for local overrides.

### nginx config

```nginx
server {
    listen 80;
    server_name blink.yourdomain.com;
    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
    }
}
```

## Security model

| Threat | Mitigation |
|---|---|
| Server compromise | Key never sent to server (URL fragment only) |
| Replay attack | Secret deleted on first read |
| Link interception | HTTPS enforced; key is in fragment, not query string |
| Brute-force OTP | 5-attempt limit per secret, then self-destructs; 30 reads/min/IP |
| Email rate abuse | 3 OTP emails per hour per IP |
| Brute-force IDs | UUID v4 (122 bits entropy) + rate limiting |
| XSS | Strict CSP (`script-src 'self'`); user content set via `textContent` |
| Host header injection | HTTPS redirect uses `process.env.HOST`, not `req.headers.host` |
| Memory exhaustion | 10 000 secret cap; 48h TTL; purge interval every 60s |

## Project structure

```
blink/
├── server.js          # Express server, rate limiter, secret store, email OTP
├── public/
│   ├── index.html     # Create page
│   ├── view.html      # View-once page
│   ├── app.js         # Encrypt, generate password, create link
│   ├── view.js        # Decrypt, reveal, OTP flow
│   ├── style.css      # Dark theme UI
│   └── logo.png       # App logo
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## License

MIT
