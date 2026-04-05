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
1. Aggregates the day's DNS logs **per client** (grouped by the names in `filtered_clients`)
2. Sends each client's summary to OpenAI GPT-5.4-mini for individual, child-specific analysis
3. Emails a single HTML report with per-child sections — each with their own stats, charts, and AI insights

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
  listen_addr:                     # Use port 15353 for local testing without root
    - "0.0.0.0:53"                # IPv4
    - "[::]:53"                   # IPv6
  upstream_servers:
    - "1.1.1.1:53"                # Cloudflare
    - "8.8.8.8:53"                # Google
  filtered_clients:               # Only filter these devices. Empty = filter all.
    - name: "Samir's Laptop"      # Name shown in daily reports
      ip: "192.168.1.100"         # Match by IP
    - name: "Samir's iPad"
      mac: "aa:bb:cc:dd:ee:ff"    # Match by MAC (resolved via ARP on Linux)

blocklist:
  custom_block:
    # TikTok & ByteDance (TikTok uses many domains — blocking tiktok.com alone is not enough)
    - "tiktok.com"
    - "tiktokv.com"
    - "tiktokw.eu"
    - "tiktokv.eu"
    - "tiktokcdn.com"
    - "tiktokcdn-eu.com"
    - "tiktokcdn-us.com"
    - "musical.ly"
    - "muscdn.com"
    - "bytedance.com"
    - "bytedance.net"
    - "byteoversea.com"
    - "byteoversea.net"
    - "byteimg.com"
    - "ibytedtos.com"
    - "ibyteimg.com"
    - "ipstatp.com"
    - "sgpstatp.com"
    - "ttwstatic.com"
    - "ttdns2.com"
    - "ttdns3.com"
    # YouTube
    - "youtube.com"
    - "youtu.be"
    - "youtubei.googleapis.com"
    - "youtube-nocookie.com"
    - "youtube-ui.l.google.com"
    - "ytimg.com"
    - "yt3.ggpht.com"
    - "googlevideo.com"
    # Gaming sites
    - "poki.com"
    - "poki-cdn.com"
    - "poki-gdn.com"
    - "crazygames.com"
    - "crazygames.io"
    - "crazygames-cdn.com"
    - "roblox.com"
    - "rbxcdn.com"
    - "roblox.cn"
    # Social media
    - "snapchat.com"
    - "snapkit.co"
    - "snap.com"
    - "snapchat.map.fastly.net"
    - "reddit.com"
    - "redd.it"
    - "redditstatic.com"
    - "redditmedia.com"
    - "4chan.org"
    - "4cdn.org"

  custom_allow:
    - "khanacademy.org"
    - "scratch.mit.edu"

analyzer:
  schedule: "0 0 19 * * *"                       # Daily at 19:00
  timezone: "Europe/Amsterdam"                    # IANA timezone

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
sudo chmod 600 /opt/kidguard/.env    # protect credentials
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

**Raspberry Pi 3 (production):**

The systemd setup is identical to Ubuntu. The only difference is building the binary — the Pi 3 is ARM, and compiling Rust on it is slow (1GB RAM), so cross-compiling from your dev machine is recommended.

Cross-compile using [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) (no Docker needed):

```bash
brew install zig              # macOS — or see ziglang.org for Linux
cargo install cargo-zigbuild
rustup target add armv7-unknown-linux-gnueabihf   # or aarch64-unknown-linux-gnu for 64-bit Pi OS

# For 32-bit Pi OS (default on Pi 3)
cargo zigbuild --release --target armv7-unknown-linux-gnueabihf

# For 64-bit Pi OS
cargo zigbuild --release --target aarch64-unknown-linux-gnu
```

Then copy the binary to the Pi and follow the same Ubuntu steps above:

```bash
scp target/armv7-unknown-linux-gnueabihf/release/kidguard pi@<pi-ip>:/tmp/
ssh pi@<pi-ip>

sudo mkdir -p /opt/kidguard/data /opt/kidguard/blocklists
sudo mv /tmp/kidguard /opt/kidguard/
sudo cp config.yaml .env /opt/kidguard/
sudo cp -r migrations /opt/kidguard/
sudo chmod 600 /opt/kidguard/.env    # protect credentials
```

Create the same systemd service as above, then `sudo systemctl enable kidguard && sudo systemctl start kidguard`.

Alternatively, build directly on the Pi (expect ~15-30 min compile time):

```bash
# Add swap if needed (1GB RAM is tight for rustc)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile

cargo build --release
```

**Docker:**

```bash
docker compose up -d
```

### 3. Point Your Child's Device

First, reserve a static IP for the machine running KidGuard (e.g. `192.168.1.50`) in your router settings.

**Option A: Router-level (recommended)** — set your router's DNS server to `192.168.1.50`. All devices on the network use KidGuard at home, and automatically use the local network's DNS when away (school, friends' houses). No per-device config needed. Use `filtered_clients` in `config.yaml` to target specific devices by IP or MAC address — unmatched devices pass through unfiltered.

**Option B: Per-device** — on the child's device, go to Wi-Fi / network settings and set the DNS server to `192.168.1.50`. Only that device is filtered, but DNS will fail when the device leaves your home network. You would need to undo this setting before the device goes off-network.

### 4. Verify

```bash
dig @127.0.0.1 -p 53 google.com      # Should resolve
dig @127.0.0.1 -p 53 roblox.com      # Should return NXDOMAIN (custom_block)
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
│   └── openai.rs        # Sends summary to GPT-5.4-mini, parses response
└── reporter/
    └── email.rs         # Builds and sends HTML report via SMTP
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | No | Enables AI-powered daily reports |
| `SMTP_USERNAME` | No | Gmail address for sending reports |
| `SMTP_PASSWORD` | No | Gmail app password (not your login password) |
| `RUST_LOG` | No | Override log filter. Default is `warn,kidguard=info` (only shows filtered client activity). Set to `info` to see all DNS queries including unfiltered devices, or `debug` for verbose output |
