# Honmoon Sync Server

The sync server behind [Honmoon](https://honmoon.app), a household
collaboration app. Run it yourself and your household's data never touches
anyone else's machine.

The server relays end-to-end encrypted messages between the devices in a
household and holds them until every device has picked them up. It cannot read
any of it — the encryption keys never leave the phones.

## Run it

```bash
git clone https://github.com/honmoon-app/honmoon-server
cd honmoon-server
docker compose -f docker-compose.selfhost.yml up -d
curl http://localhost:8080/health     # → {"status":"ok",...}
```

That is the whole setup. There is no `.env` to write and no `openssl rand` to
run: the signing secrets are generated on first boot and stored on the data
volume (`secrets.env`, chmod 600), so they survive restarts. If you would
rather manage them yourself, set `JWT_SECRET` / `TURN_SECRET` /
`FEEDBACK_ADMIN_TOKEN` in the environment and yours are used instead.

Runs on anything with Docker — a VPS, a NAS, an old mini PC, a Raspberry Pi 4
(the image is built for amd64 and arm64).

## Make it reachable

Your phones need to reach the server from outside your home network. The
documented and tested path is [Tailscale
Funnel](https://tailscale.com/kb/1223/funnel), which needs no domain, no public
IP address and no certificate:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up
tailscale funnel 8080
```

Tailscale prints an address like `https://yourbox.your-tailnet.ts.net`. Put it
into the app under **Settings → Sync → Server** — or let the other people in
your household scan the QR code the app shows there. Only you need a Tailscale
account; nobody else installs anything.

**What Tailscale can see:** not your content. Funnel forwards the encrypted TLS
stream and terminates it on *your* machine, and the payloads inside are
end-to-end encrypted on top of that. It does see connection metadata — IP
addresses, timing, and how much data moves. That is a real third party in the
chain, which is why it is written down here rather than glossed over.

**If you already have a domain and a public IP**, skip Tailscale and point any
reverse proxy (Caddy, nginx, Traefik) at port 8080 with TLS in front. That path
works but is not something we test.

## Push notifications (optional)

Without push, the app syncs when you open it. To get background notifications,
bring up the bundled [ntfy](https://ntfy.sh) relay:

```bash
docker compose -f docker-compose.selfhost.yml --profile push up -d
```

Then expose it on a public hostname of its own and set `NTFY_URL` to its
internal address (`http://ntfy:80`) and `NTFY_PUBLIC_URL` to the public one.

## Configuration

Everything has a working default. The ones worth knowing:

| Variable | Default | What it does |
| --- | --- | --- |
| `HONMOON_PORT` | `8080` | Host port the server listens on |
| `MEDIA_QUOTA_MB` | `500` | Storage per household for photos and files |
| `MEDIA_RETENTION_DAYS` | `30` | How long undelivered media is kept |
| `BACKUP_QUOTA_MB` | `1024` | Storage per household for encrypted backups |
| `BACKUP_RETENTION_DAYS` | `365` | Backup expiry; `0` disables it |
| `MAX_UPLOAD_SIZE_MB` | `50` | Largest single upload |
| `NTFY_URL` | `disabled` | UnifiedPush relay for background notifications |
| `TURN_SERVER` | `localhost` | TURN host for voice/video calls |

Set them in the environment or in an `.env` file next to the compose file.

## Everyday operation

```bash
docker compose -f docker-compose.selfhost.yml pull    # update
docker compose -f docker-compose.selfhost.yml up -d
docker compose -f docker-compose.selfhost.yml logs -f
```

Your data lives in two Docker volumes: `postgres-data` (queued messages,
household bookkeeping) and `honmoon-data` (media, backups, `secrets.env`). Back
those two up and you have backed up the server. Note that phones hold the full
household state themselves — the server is a relay, so losing it costs you
undelivered messages, not your history.

To check a running server end to end — including through a Funnel URL, which is
the part that actually tends to break:

```bash
pip install websockets
python3 scripts/smoke_test.py https://yourbox.your-tailnet.ts.net
```

## Build from source

```bash
cargo build --release      # needs Rust 1.88+ and a PostgreSQL instance
docker build -t honmoon-server .
```

Rust, [Axum](https://github.com/tokio-rs/axum), PostgreSQL via sqlx, WebSocket
relay. `src/` is laid out by concern: `websocket/` for the relay itself,
`routes/` for the HTTP API, `db/` for persistence.

## License

AGPL-3.0. You may run, modify and redistribute this server; if you offer it to
others over a network, they get the right to your modified source too.
