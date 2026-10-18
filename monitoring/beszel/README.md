# Beszel (VPS monitoring)

[Beszel](https://beszel.dev) is a lightweight dashboard for CPU, memory, disk, network, and Docker container stats. This is **host-wide infrastructure, not part of the Blink app** — it would monitor any other service on this same VPS too, which is why it's kept in its own compose stack here instead of being added to the repo root's `docker-compose.yml`.

It does not read or display Blink's own application logs (see the "Logging" section in the repo's main `README.md`) — those are a separate, unrelated piece. Beszel only ever reports resource/uptime metrics.

## One-time setup

1. **Copy the env file and start the hub only** (the agent needs values the hub hasn't generated yet):
   ```bash
   cd monitoring/beszel
   cp .env.example .env
   docker compose up -d beszel
   ```
2. **Open the hub's dashboard** at `http://<this-vps-ip>:58988` (or `http://localhost:58988` if you're on the box itself) and create the admin account when prompted. (Port 58988 is deliberately not Beszel's well-known default of 8090 — see the comment in `docker-compose.yml`.)
3. In the dashboard, click **Add System** (top right).
4. Name the system (e.g. this VPS's hostname), and set **Host / IP** to the shared socket path: `/beszel_socket/beszel.sock`.
5. The dialog shows a **TOKEN** and a **KEY** — copy both into `.env` in this directory as `BESZEL_AGENT_TOKEN` and `BESZEL_AGENT_KEY`.
6. **Start the agent:**
   ```bash
   docker compose up -d beszel-agent
   ```
7. Back in the dashboard, the new system should turn green within a few seconds — that means it's connected and reporting. Red means something's off; see [Beszel's troubleshooting guide](https://www.beszel.dev/guide/getting-started) (a KEY/TOKEN with an extra stray space is the most common cause).

## Exposing the dashboard remotely

By default the hub is bound to `127.0.0.1:58988` — only reachable from inside the VPS, the same pattern Blink's own `docker-compose.yml` uses for its app port. To reach it from outside, put nginx (or any reverse proxy) in front of it with its own TLS cert and subdomain — the exact steps below are what was actually run and verified live, not just the general idea.

Pick a subdomain name that doesn't advertise what monitoring tool you're running (e.g. `monitor.yourdomain.com` rather than `beszel.yourdomain.com`) — avoids being an easy target for anyone specifically scanning for known Beszel vulnerabilities. Keep the image on `:latest` and pull it periodically (the `deploy-beszel.yml` GitHub Action does this) so you're never stuck on a version with a known, patched CVE if you do expose this publicly.

**1. nginx + a Cloudflare Origin CA certificate.** If you're proxying through Cloudflare (recommended), the simplest cert to use is Cloudflare's own Origin CA cert (dashboard → SSL/TLS → Origin Server → Create Certificate — a wildcard like `*.yourdomain.com` covers this subdomain and any others on the same zone). Add an nginx `server { listen 443 ssl; ... }` block for this subdomain pointing `proxy_pass` at `http://127.0.0.1:58988`, using that cert. Then in Cloudflare, set SSL/TLS mode to **Full (strict)** — this only works cleanly if *every* hostname on the zone has a valid cert on its origin block, not just this one; a host with no cert at all will break the moment you flip that zone-wide setting.

**2. Restrict port 443 at the firewall to Cloudflare's IP ranges.** This is the step that's easy to skip and easy to not notice is missing: Cloudflare terminating TLS at its edge does nothing to stop someone from bypassing Cloudflare entirely and connecting straight to your VPS's IP on port 443. If your UFW already restricts port 80 to Cloudflare's published ranges (a common setup once you're proxying through Cloudflare), port 443 needs the exact same restriction once it's actually serving real content behind it — otherwise anyone can skip Cloudflare and talk directly to your origin. Mirror whatever rules already exist for port 80, applied to 443, then verify: `curl -I https://<vps-ip>:443` from somewhere that isn't Cloudflare should time out or get refused.

**3. The Cloudflare cache trap — this one is easy to lose hours to.** If a "Cache Everything" rule is active on the zone (common for performance), Cloudflare can and will cache `GET` responses from Beszel's own API — including things like `/api/beszel/first-run`, which the hub's frontend uses to decide whether to show the signup screen or a normal login. If that response gets cached once (e.g. the very first time the hub booted, before an admin account existed), Cloudflare will keep serving that same stale answer indefinitely — you'll create an admin account, it'll genuinely exist, and the dashboard will *still* show "create an admin account" forever, no matter how many times you restart the container, because the real fix was never on your server at all. Add a Cloudflare Cache Rule: **If** `URI Path contains /api/` → **Bypass cache** (no hostname condition — scope it to the whole zone's `/api/*`, which also covers Blink's own API routes and anything else you add later, for free).

**4. Tell PocketBase how to find the real visitor IP.** Behind a proxy, the hub by default resolves every visitor to the same internal Docker IP — breaking both the dashboard's own IP-based rate limiting and any IP-based logging. In the hub's admin UI → **Settings → (general/application settings) → Trusted IP proxy headers**, enter `X-Forwarded-For` and set IP priority to **"Use leftmost IP"** (Cloudflare puts the real visitor IP first in that header; nginx appends its own perceived IP after). This is only safe to trust once step 2 is done — if direct non-Cloudflare access to port 443 is still possible, this header becomes spoofable.

## Email alerts (optional)

The hub's own Notifications settings page will warn you to configure SMTP before alerts can be delivered — that configuration actually lives one level down, in PocketBase's own mail settings: **`<your hub URL>/_/#/settings/mail`**. If you already have a [Resend](https://resend.com) account for Blink's own emails, the simplest path is reusing it rather than signing up for a separate provider:

- **SMTP server host:** `smtp.resend.com`
- **Port:** `587`, with **TLS encryption: Auto (StartTLS)** — not port `465`; that's the implicit-TLS port and expects a different handshake, and may also be blocked outbound on some hosts regardless.
- **Username:** `resend` (literally that word)
- **Password:** your `RESEND_API_KEY` value
- **Sender address:** something on a domain already verified in Resend (e.g. a different local-part than Blink's own `EMAIL_FROM`, so alert emails are visually distinguishable from Blink's own transactional emails at a glance)

Save, then use the **Test** button on that same page before relying on it. Once SMTP is confirmed working, the actual alert *rules* (CPU/memory/disk thresholds, system-down notifications) are configured separately, per system — click the bell icon next to a system in the main dashboard table, not in Settings.

## Updating

This stack is **not** touched by the repo's `deploy.yml` GitHub Action — that only redeploys the Blink app itself, on its own schedule. This one has its own separate workflow instead: **Actions tab → "Deploy Beszel" → Run workflow**. It reuses the same `VPS_HOST`/`VPS_USER`/`VPS_SSH_KEY` repo secrets `deploy.yml` already uses — nothing new to configure — and runs `git pull` + `docker compose pull` + `docker compose up -d` on the VPS.

That workflow is for *ongoing* updates only — it assumes `.env` already has real `BESZEL_AGENT_TOKEN`/`BESZEL_AGENT_KEY` values on the VPS from the one-time setup above. Running it before that setup is done just starts the agent with blank credentials, which will fail to connect. For the very first setup, or if you ever need to re-pair the agent, do that part by hand:

```bash
cd monitoring/beszel
docker compose pull
docker compose up -d
```
