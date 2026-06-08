# Blink

Share secrets that disappear. Once seen, forever gone.

Blink is a self-hosted, end-to-end encrypted secret sharing app. Paste a password or generate one, get a one-time link — the secret is deleted the moment it's opened.

## How it works

1. You enter or generate a secret
2. The secret is encrypted **in your browser** using AES-256-GCM (Web Crypto API)
3. Only the encrypted ciphertext is sent to the server — the decryption key never leaves your device
4. The key is embedded in the URL fragment (`#key`) which is never sent to the server
5. When the recipient opens the link, it's decrypted client-side and **immediately deleted from the server**
6. Refreshing the view page also destroys the secret

## Features

- **End-to-end encrypted** — AES-256-GCM, key lives only in the URL fragment
- **View once** — secret is deleted on first read, atomically
- **Optional 10-minute TTL** — enable per-link, disabled by default
- **Password generator** — configurable length, charset, with strength meter
- **Rate limited** — 10 creates / 30 reads per minute per IP, no external deps
- **No database** — in-memory store, ephemeral by design
- **Security headers** — CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy

## Stack

- **Backend:** Node.js 18 + Express (zero non-framework dependencies)
- **Frontend:** Vanilla JS, Web Crypto API
- **Deploy:** Docker + nginx reverse proxy + Cloudflare

## Self-hosting

### Requirements

- Docker and Docker Compose
- A domain with Cloudflare (or any reverse proxy)

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
| Brute-force | UUID v4 IDs (122 bits entropy); rate limiting |
| XSS | Strict CSP (`script-src 'self'`); user content set via `textContent` |
| Host header injection | HTTPS redirect uses `process.env.HOST`, not `req.headers.host` |
| Memory exhaustion | 10 000 secret cap; 10-min TTL when enabled; purge interval |

## Project structure

```
blink/
├── server.js          # Express server, rate limiter, secret store
├── public/
│   ├── index.html     # Create page
│   ├── view.html      # View-once page
│   ├── app.js         # Encrypt, generate password, create link
│   ├── view.js        # Decrypt, reveal, auto-clear
│   ├── style.css      # Dark theme UI
│   └── logo.png       # App logo
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## License

MIT
