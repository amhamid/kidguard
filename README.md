# KidGuard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A DNS proxy that blocks inappropriate content for children, logs all activity to SQLite, and sends daily AI-powered parent reports via email.

## How It Works

KidGuard sits between your child's device and the internet as a DNS server. Every time a device looks up a domain name (e.g. `roblox.com`), the request goes through KidGuard first.

```
Child's device ──DNS query──▶ KidGuard ──allowed──▶ Upstream DNS (Cloudflare/Google)
                                 │                          │
                                 │ blocked                  │
                                 ▼                          ▼
                             NXDOMAIN               Real IP returned
                          (site won't load)         (site loads normally)
```

### Blocking

KidGuard checks every domain against three layers:

| Priority | Layer | Effect |
|----------|-------|--------|
| 1 (highest) | `custom_allow` | Always allowed, even if it appears in a blocklist |
| 2 | `custom_block` | Always blocked |
| 3 | Public blocklists | Blocked by category (ads, malware, adult) |
| 4 (default) | Everything else | Allowed |

Subdomains are matched automatically — blocking `tiktok.com` also blocks `www.tiktok.com`, `cdn.tiktok.com`, etc.

When a more specific rule exists, it wins. For example, if `roblox.com` is in `custom_allow` but `metrics.roblox.com` is in `custom_block`, then `metrics.roblox.com` is blocked while `roblox.com` and `cdn.roblox.com` are allowed.

Blocked domains receive an `NXDOMAIN` response — the browser behaves as if the site doesn't exist.

### Why DNS-Level Blocking Works

Every resource a web page loads makes its own DNS query:

```
https://roblox.com/game          → DNS: roblox.com       ✅ allowed
https://cdn.roblox.com/asset.js  → DNS: cdn.roblox.com   ✅ allowed
https://doubleclick.net/track    → DNS: doubleclick.net   🚫 blocked
https://fbcdn.net/pixel.js       → DNS: fbcdn.net         🚫 blocked
```

Ads and trackers embedded inside allowed sites are blocked automatically because they use different hostnames.

### Logging

Every DNS query — blocked and allowed — is logged to a local SQLite database with:
- Timestamp, client IP, domain, query type
- Whether it was blocked and which rule matched
- The resolved IP address (for allowed queries)
- Response time in milliseconds

Logging is fire-and-forget (via `tokio::spawn`) so it never slows down DNS responses.

### Daily Reports

Once a day (configurable via cron), KidGuard:
1. Aggregates the day's DNS logs into a summary (top domains, blocked attempts, activity by hour)
2. Sends the summary to OpenAI GPT-4o which writes a short, parent-friendly analysis
3. Emails an HTML report with stats, charts, and the AI analysis

If OpenAI is unavailable, a plain-text fallback summary is used instead.

### Blocklist Sync

Public blocklists are fetched on startup and re-synced every 24 hours (configurable). Currently configured sources:

| Source | Domains | Category |
|--------|---------|----------|
| [StevenBlack/hosts](https://github.com/StevenBlack/hosts) | ~92k | Ads & malware |
| [OISD Small](https://oisd.nl/) | ~56k | General |
| [StevenBlack porn-only](https://github.com/StevenBlack/hosts) | ~77k | Adult |

If a fetch fails, the last cached version is used. The server never goes down due to a sync failure.

## Setup

### Prerequisites

- Rust 1.77+ (or Docker)
- An OpenAI API key (optional — only needed for AI reports)
- Gmail app password (optional — only needed for email reports)

### 1. Configure

Edit `config.yaml` to customize:

```yaml
dns:
  listen_addr: "0.0.0.0:53"      # Use 15353 for local testing without root
  upstream_servers:
    - "1.1.1.1:53"                # Cloudflare
    - "8.8.8.8:53"                # Google

blocklist:
  custom_block:
    - "tiktok.com"
    - "snapchat.com"
    - "reddit.com"
    - "4chan.org"
    - "roblox.com"

  custom_allow:
    - "khanacademy.org"
    - "scratch.mit.edu"

analyzer:
  schedule: "0 0 7 * * *"            # Daily at 7am

reporter:
  to_email: "you@gmail.com"
```

Copy `.env.example` to `.env` and fill in your credentials:

```
OPENAI_API_KEY=sk-...
SMTP_USERNAME=you@gmail.com
SMTP_PASSWORD=your_app_password
```

### 2. Run

**Local (development):**

```bash
# Port 53 requires root; use 15353 for testing
cargo run
```

**Ubuntu server (production):**

Build the release binary and deploy:

```bash
cargo build --release
sudo mkdir -p /opt/kidguard/data /opt/kidguard/blocklists
sudo cp target/release/kidguard /opt/kidguard/
sudo cp config.yaml .env /opt/kidguard/
sudo cp -r migrations /opt/kidguard/
```

Create `/etc/systemd/system/kidguard.service`:

```ini
[Unit]
Description=KidGuard DNS Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/kidguard
ExecStart=/opt/kidguard/kidguard
Restart=always
RestartSec=5
EnvironmentFile=/opt/kidguard/.env

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable kidguard
sudo systemctl start kidguard

# Check status / logs
sudo systemctl status kidguard
sudo journalctl -u kidguard -f
```

This auto-starts on boot, restarts on crash, and sends logs to journald.

**Docker:**

```bash
docker compose up -d
```

### 3. Point Your Child's Device

On your router (e.g. FritzBox):

1. Reserve a static IP for the machine running KidGuard (e.g. `192.168.1.50`)
2. Go to the child's device profile in parental controls
3. Set DNS server to `192.168.1.50`

### 4. Verify

```bash
dig @127.0.0.1 -p 53 google.com      # Should resolve
dig @127.0.0.1 -p 53 roblox.com      # Should resolve (custom_allow)
dig @127.0.0.1 -p 53 tiktok.com      # Should return NXDOMAIN (custom_block)
dig @127.0.0.1 -p 53 www.tiktok.com  # Should return NXDOMAIN (subdomain)
```

## Project Structure

```
src/
├── main.rs              # Entry point, wires everything together
├── config.rs            # Config structs, loads config.yaml + .env
├── dns/
│   ├── server.rs        # Binds UDP socket, starts hickory ServerFuture
│   ├── handler.rs       # RequestHandler: blocklist check → forward or NXDOMAIN → log
│   └── forwarder.rs     # Forwards queries to upstream via hickory-resolver
├── blocklist/
│   ├── loader.rs        # Fetches/parses blocklists (hosts file + plain list formats)
│   ├── matcher.rs       # Domain matching with parent-domain walking + specificity
│   └── sync.rs          # Startup sync + periodic re-sync scheduler
├── logger/
│   └── db.rs            # SQLite logging (fire-and-forget writes, range queries)
├── analyzer/
│   ├── aggregator.rs    # Builds DailySummary from log data
│   └── openai.rs        # Sends summary to GPT-4o, parses response
└── reporter/
    └── email.rs         # Builds and sends HTML report via SMTP
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | No | Enables AI-powered daily reports |
| `SMTP_USERNAME` | No | Gmail address for sending reports |
| `SMTP_PASSWORD` | No | Gmail app password (not your login password) |
| `RUST_LOG` | No | Log level — `info` for production, `debug` for development |
