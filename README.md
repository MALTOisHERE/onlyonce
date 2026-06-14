# Blink

Share secrets that disappear. Once seen, forever gone.

Blink is a self-hosted, end-to-end encrypted secret sharing app. Paste a password or generate one, get a one-time link - the secret is deleted the moment it's opened.

## How it works

1. You enter or generate a secret
2. The secret is encrypted **in your browser** using AES-256-GCM (Web Crypto API)
3. The encryption key `K` is split into two halves: `K1` (goes in the URL fragment) and `K2` (sent to the server)
4. Neither half alone can decrypt anything - the server must participate in every reveal
5. The server masks `K2` with `HMAC-SHA256(K3, secret_id)` before storing it, where `K3` is a permanent secret that never leaves the server
6. When the recipient opens the link, the server reconstructs `K`, decrypts server-side, returns plaintext, and **immediately deletes the secret**

## Architecture

[View full architecture diagram on FigJam](https://www.figma.com/board/zyhi0yFeGoiPNghCgV661s/Blink-%E2%80%94-How-It-Works--with-OTP-?node-id=0-1&t=E97FNlCEh2ZNJemb-1)

## Features

- **End-to-end encrypted** - AES-256-GCM with four-factor key splitting (K1 + K2 + K3 + K4)
- **View once** - secret is deleted on first read, atomically
- **Configurable expiry** - choose 1, 6, 24, or 48 hours; unviewed secrets are automatically purged at expiry
- **Email verification (optional)** - lock a link to a specific recipient; they must enter a 6-digit code sent to their inbox to reveal the secret. Wrong code 5 times → secret self-destructs
- **Password generator** - configurable length, charset, with strength meter
- **Rate limited** - 10 creates / 30 reads per minute per IP; 3 email OTPs per hour per IP
- **No database** - in-memory store, ephemeral by design
- **Security headers** - CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy

## Key architecture

| Key | Lives where | Purpose |
|-----|-------------|---------|
| `K` | Browser only (never stored) | AES-256-GCM encryption key |
| `K1` | URL fragment only | Sent to server at reveal time via `X-Key` header |
| `K2` | Server memory (masked) | Stored as `K2 XOR HMAC(K3, id)` - useless without K3 |
| `K3` | Server env var only | HMAC-masks K2 at rest - never transmitted anywhere |
| `K4` | Server env var only | AES-encrypts ciphertext at rest - never transmitted anywhere |

All four factors always required to decrypt. Missing any one → decryption fails completely.

## Stack

- **Backend:** Node.js 22 + Express
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
# Generate a permanent server secret (do this once)
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env

docker compose up -d --build
```

The container binds to `127.0.0.1:3001` - put nginx in front.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ENV` | `development` | Set to `production` to enable HTTPS redirect and HSTS |
| `PORT` | `3000` | Port to listen on |
| `HOST` | - | Your domain (e.g. `blink.malto.icu`). Required in production |
| `SECRET_KEY` | - | K3 - HMAC-masks K2 at rest. Generate with `openssl rand -hex 32` |
| `CIPHER_KEY` | - | K4 - AES-encrypts ciphertext at rest. Generate with `openssl rand -hex 32` |
| `RESEND_API_KEY` | - | Resend API key. Required for email OTP feature |
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
| Server memory dump | `K2` stored masked with `HMAC(K3, id)` - useless without `K3` |
| Replay attack | Secret deleted from memory on first read |
| Link interception | HTTPS enforced; `K1` is in URL fragment, never in request body |
| Browser history exposure | `K1` cleared from URL via `history.replaceState` immediately on page load |
| Offline decryption | Server must participate in every reveal - ciphertext alone is not enough |
| Brute-force OTP | 5-attempt limit per secret, then self-destructs; 30 reads/min/IP |
| Email rate abuse | 3 OTP emails per hour per IP |
| Brute-force IDs | UUID v4 (122 bits entropy) + rate limiting |
| XSS | Strict CSP (`script-src 'self'`); user content set via `textContent` |
| Host header injection | HTTPS redirect uses `process.env.HOST`, not `req.headers.host` |
| Memory exhaustion | 10 000 secret cap; 1–48h TTL (user-chosen); purge interval every 60s |

## Project structure

```
blink/
├── server.js          # Express server, rate limiter, secret store, email OTP
├── public/
│   ├── index.html     # Create page
│   ├── view.html      # View-once page
│   ├── app.js         # Encrypt, key split, generate password, create link
│   ├── view.js        # Reveal flow, OTP flow
│   ├── style.css      # Dark theme UI
│   └── logo.png       # App logo
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## License

MIT
