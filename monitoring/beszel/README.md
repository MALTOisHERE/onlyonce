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
2. **Open the hub's dashboard** at `http://<this-vps-ip>:8090` (or `http://localhost:8090` if you're on the box itself) and create the admin account when prompted.
3. In the dashboard, click **Add System** (top right).
4. Name the system (e.g. this VPS's hostname), and set **Host / IP** to the shared socket path: `/beszel_socket/beszel.sock`.
5. The dialog shows a **TOKEN** and a **KEY** — copy both into `.env` in this directory as `BESZEL_AGENT_TOKEN` and `BESZEL_AGENT_KEY`.
6. **Start the agent:**
   ```bash
   docker compose up -d beszel-agent
   ```
7. Back in the dashboard, the new system should turn green within a few seconds — that means it's connected and reporting. Red means something's off; see [Beszel's troubleshooting guide](https://www.beszel.dev/guide/getting-started) (a KEY/TOKEN with an extra stray space is the most common cause).

## Exposing the dashboard remotely

By default the hub is bound to `127.0.0.1:8090` — only reachable from inside the VPS, the same pattern Blink's own `docker-compose.yml` uses for its app port. To reach it from outside, put nginx (or any reverse proxy) in front of it with its own TLS cert and subdomain, mirroring the nginx block already documented in the repo's main `README.md` for Blink itself — just pointing `proxy_pass` at `http://127.0.0.1:8090` instead. Then set `BESZEL_APP_URL` in `.env` to that public URL before restarting the hub.

## Updating

This stack is **not** touched by the repo's `deploy.yml` GitHub Action — that only redeploys the Blink app itself, on its own schedule. This one has its own separate workflow instead: **Actions tab → "Deploy Beszel" → Run workflow**. It reuses the same `VPS_HOST`/`VPS_USER`/`VPS_SSH_KEY` repo secrets `deploy.yml` already uses — nothing new to configure — and runs `git pull` + `docker compose pull` + `docker compose up -d` on the VPS.

That workflow is for *ongoing* updates only — it assumes `.env` already has real `BESZEL_AGENT_TOKEN`/`BESZEL_AGENT_KEY` values on the VPS from the one-time setup above. Running it before that setup is done just starts the agent with blank credentials, which will fail to connect. For the very first setup, or if you ever need to re-pair the agent, do that part by hand:

```bash
cd monitoring/beszel
docker compose pull
docker compose up -d
```
