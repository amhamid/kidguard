# KidGuard — Rust DNS Proxy: Implementation Plan

## Design Principles

- **Allow by default** — all domains pass through unless explicitly blocked
- **Layered blocklist** — curated public lists (ads, adult, malware) + your own custom entries on top
- **NXDOMAIN for blocked domains** — clean, simple, no HTTP server needed
- **OpenAI API** — GPT-4o for daily behavior analysis and parent reports
- **Minimal disruption** — never break legitimate traffic, custom_allow always wins
- **DNS-level resource blocking** — each third-party resource (ads, trackers, CDNs) has
  its own hostname and is evaluated independently, so embedded resources in allowed
  sites are handled automatically

---

## How DNS Resource Blocking Works

DNS only sees hostnames, never full URLs or paths. Every resource a page loads
makes its own DNS query:

```
https://roblox.com/game          → DNS query: roblox.com       ✅ allowed
https://cdn.roblox.com/asset.js  → DNS query: cdn.roblox.com   ✅ allowed (subdomain)
https://doubleclick.net/track    → DNS query: doubleclick.net   🚫 blocked
https://fbcdn.net/pixel.js       → DNS query: fbcdn.net         🚫 blocked (if on list)
```

This means ads and trackers embedded in allowed sites are blocked automatically.
The only gap is resources sharing the exact same hostname as the allowed site
(e.g. `youtube.com/api/track`) — those cannot be distinguished at DNS level.
This is acceptable for an 8-year-old and would only require a transparent HTTPS
proxy to resolve, which is out of scope.

---

## Blocklist Matching Priority

```
custom_allow  →  wins always, even over blocklist sources
custom_block  →  blocked
blocklist sources  →  blocked (by category)
everything else  →  allowed (default)
```

Subdomain rule: blocking `tiktok.com` also blocks `www.tiktok.com`, `cdn.tiktok.com`, etc.
Specificity rule: `custom_block: metrics.roblox.com` beats `custom_allow: roblox.com`.

---

## Project Structure

```
kidguard/
├── Cargo.toml
├── .env.example
├── config.yaml
├── migrations/
│   └── 001_initial.sql
├── blocklists/
│   └── .gitkeep            # cached list files written here on sync
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── dns/
│   │   ├── mod.rs
│   │   ├── server.rs
│   │   ├── handler.rs
│   │   └── forwarder.rs
│   ├── blocklist/
│   │   ├── mod.rs
│   │   ├── loader.rs
│   │   ├── matcher.rs
│   │   └── sync.rs
│   ├── logger/
│   │   ├── mod.rs
│   │   └── db.rs
│   ├── analyzer/
│   │   ├── mod.rs
│   │   ├── aggregator.rs
│   │   └── openai.rs
│   └── reporter/
│       ├── mod.rs
│       └── email.rs
```

---

## Cargo.toml

```toml
[package]
name = "kidguard"
version = "0.1.0"
edition = "2021"

[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# DNS
hickory-server = "0.24"
hickory-resolver = "0.24"
hickory-proto = "0.24"

# Database
sqlx = { version = "0.7", features = ["sqlite", "runtime-tokio", "macros", "migrate"] }

# HTTP (blocklist sync + OpenAI API)
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Config
config = "0.14"

# Scheduling
tokio-cron-scheduler = "0.10"

# Email
lettre = { version = "0.11", features = ["tokio1", "tokio1-native-tls"] }

# Logging / tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Utilities
anyhow = "1"
thiserror = "1"
chrono = { version = "0.4", features = ["serde"] }
dotenv = "0.15"
```

---

## Configuration

### `config.yaml`

```yaml
dns:
  listen_addr: "0.0.0.0:53"
  upstream_servers:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  timeout_ms: 2000

blocklist:
  # Curated public lists — fetched and cached, re-synced daily
  sources:
    - name: "stevenblack"
      url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      category: "ads_malware"
    - name: "oisd_small"
      url: "https://small.oisd.nl/domainswild"
      category: "general"
    - name: "adult"
      url: "https://raw.githubusercontent.com/mhxion/pornographic-domain-blocklist/main/pornographic_domain_blocklist.txt"
      category: "adult"

  # Your own additions — merged on top of the lists above
  custom_block:
    - "tiktok.com"
    - "snapchat.com"
    - "reddit.com"
    - "4chan.org"

  # Always allowed — wins over everything including blocklist sources
  custom_allow:
    - "roblox.com"
    - "khanacademy.org"
    - "scratch.mit.edu"

  sync_interval_hours: 24
  cache_dir: "./blocklists"

database:
  path: "./data/kidguard.db"

analyzer:
  schedule: "0 7 * * *"    # Daily at 7am
  lookback_days: 1
  report_top_domains: 15

reporter:
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  from_email: "you@gmail.com"
  to_email: "you@gmail.com"
```

### `.env.example`

```
OPENAI_API_KEY=sk-...
SMTP_USERNAME=you@gmail.com
SMTP_PASSWORD=your_app_password
DATABASE_URL=sqlite:///data/kidguard.db
RUST_LOG=info
```

---

## Database Schema

### `migrations/001_initial.sql`

```sql
CREATE TABLE IF NOT EXISTS dns_queries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    client_ip     TEXT NOT NULL,
    domain        TEXT NOT NULL,
    query_type    TEXT NOT NULL,
    blocked       INTEGER NOT NULL DEFAULT 0,
    blocked_rule  TEXT,         -- which rule matched e.g. "tiktok.com"
    category      TEXT,         -- e.g. "ads_malware", "adult", "custom"
    resolved_ip   TEXT,         -- first A record if allowed
    response_ms   INTEGER
);

CREATE INDEX idx_timestamp ON dns_queries(timestamp);
CREATE INDEX idx_domain    ON dns_queries(domain);
CREATE INDEX idx_blocked   ON dns_queries(blocked);

CREATE TABLE IF NOT EXISTS blocklist_meta (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name     TEXT NOT NULL UNIQUE,
    last_synced_at  TEXT NOT NULL,
    domain_count    INTEGER NOT NULL
);
```

---

## Implementation Phases

---

### Phase 1: DNS Forwarder

**Goal:** Forward all DNS queries upstream. No blocking yet. Prove the pipe works.

#### `src/config.rs`
- Define structs: `AppConfig`, `DnsConfig`, `BlocklistConfig`, `BlocklistSource`,
  `DatabaseConfig`, `AnalyzerConfig`, `ReporterConfig`
- All derive `serde::Deserialize`
- `pub fn load() -> anyhow::Result<AppConfig>` using the `config` crate
- Load `.env` first via `dotenv::dotenv().ok()`
- Parse upstream server strings into `SocketAddr`

#### `src/dns/forwarder.rs`
- `Forwarder` struct holding a `hickory_resolver::AsyncResolver`
- Build resolver from config upstream servers
- `pub async fn forward(&self, query: &Message) -> anyhow::Result<Message>`
- Wrap resolver call in `tokio::time::timeout` using `config.dns.timeout_ms`
- On timeout or error: return a `SERVFAIL` response (never panic)

#### `src/dns/handler.rs`
- `DnsHandler` struct — fields added incrementally each phase
- Implement `hickory_server::server::RequestHandler` for `DnsHandler`
- Phase 1: extract domain from request, call `forwarder.forward()`, return result
- Helper: `fn extract_domain(request: &Request) -> Option<String>`
  - Get first question, lowercase, strip trailing dot

#### `src/dns/server.rs`
- `pub async fn run(config: Arc<AppConfig>, handler: DnsHandler) -> anyhow::Result<()>`
- Bind UDP socket on `config.dns.listen_addr`
- Start `hickory_server::ServerFuture`
- Log: `tracing::info!("DNS server listening on {}", addr)`

#### `src/main.rs`
- Load config, wrap in `Arc`
- Init tracing subscriber with `RUST_LOG` env filter
- Build `DnsHandler`, call `dns::server::run()`

**Verify:**
```
dig @127.0.0.1 google.com     # resolves correctly
dig @127.0.0.1 roblox.com     # resolves correctly
```

---

### Phase 2: Blocklist Engine

**Goal:** Load all blocklists and custom lists, match domains, return NXDOMAIN
for blocked queries.

#### `src/blocklist/loader.rs`
- `pub async fn fetch(url: &str) -> anyhow::Result<Vec<String>>`
  - HTTP GET the URL with reqwest
  - Detect format:
    - Hosts file: lines matching `0.0.0.0 domain` or `127.0.0.1 domain`
    - Plain list: one domain per line
  - Strip comment lines (starting with `#`)
  - Normalize: lowercase, strip trailing dot
  - Return clean domain strings, deduped
- `pub fn save_cache(name: &str, domains: &[String], cache_dir: &str) -> anyhow::Result<()>`
- `pub fn load_cache(name: &str, cache_dir: &str) -> anyhow::Result<Vec<String>>`
  - Used as fallback if network fetch fails

#### `src/blocklist/matcher.rs`
- `pub struct BlockResult { pub blocked: bool, pub rule: String, pub category: String }`
- `pub struct BlocklistMatcher`
  ```rust
  pub struct BlocklistMatcher {
      allowed: HashSet<String>,              // custom_allow — checked first
      blocked_custom: HashSet<String>,       // custom_block
      blocked_lists: HashMap<String, String>, // domain → category from sources
  }
  ```
- `pub fn new(config: &BlocklistConfig) -> Self` — build from config custom lists only
- `pub fn load_source(&mut self, domains: Vec<String>, category: &str)`
  — add a fetched source into `blocked_lists`
- `pub fn is_blocked(&self, domain: &str) -> Option<BlockResult>`
  - Matching order:
    1. Check `allowed` — exact match or parent domain match → `None` (allow)
    2. Check `blocked_custom` — exact or parent → `Some(BlockResult { category: "custom" })`
    3. Check `blocked_lists` — exact or parent → `Some(BlockResult { category: from map })`
    4. Default → `None` (allow)
  - Parent domain walk: `sub.evil.com` → try `sub.evil.com`, `evil.com`, `com`
    (stop at single-label TLDs)
- Wrap in `Arc<RwLock<BlocklistMatcher>>` for hot-swap on sync

#### `src/blocklist/sync.rs`
- `pub async fn sync_all(config: Arc<AppConfig>, matcher: Arc<RwLock<BlocklistMatcher>>, db: Arc<DbLogger>)`
  - For each source in `config.blocklist.sources`:
    - Try `loader::fetch(url)` — on failure, fall back to `loader::load_cache()`
    - Save successful fetch to cache
  - Build a fresh `BlocklistMatcher` from all fetched data + config custom lists
  - Swap via `matcher.write()`
  - Update `blocklist_meta` table for each source
  - Log: `tracing::info!("Blocklist synced: {} domains total", count)`
- `pub async fn schedule(config: Arc<AppConfig>, matcher: Arc<RwLock<BlocklistMatcher>>, db: Arc<DbLogger>)`
  - Use `tokio-cron-scheduler` to run `sync_all` every `sync_interval_hours`

#### Update `src/dns/handler.rs`
- Add `matcher: Arc<RwLock<BlocklistMatcher>>` field
- Before forwarding: `matcher.read().is_blocked(&domain)`
- If blocked:
  - Build NXDOMAIN response
  - Do NOT forward to upstream
  - Set `blocked: true`, `blocked_rule`, `category` in log entry
- If not blocked: forward normally

#### Update `src/main.rs`
- Build initial `BlocklistMatcher` from config
- Wrap in `Arc<RwLock<>>`
- Run `blocklist::sync::sync_all()` at startup (before DNS server starts)
- Spawn `blocklist::sync::schedule()` as background tokio task

**Verify:**
```
dig @127.0.0.1 tiktok.com         # NXDOMAIN (custom_block)
dig @127.0.0.1 www.tiktok.com     # NXDOMAIN (subdomain match)
dig @127.0.0.1 doubleclick.net    # NXDOMAIN (from stevenblack list)
dig @127.0.0.1 roblox.com         # resolves (custom_allow wins)
dig @127.0.0.1 google.com         # resolves (default allow)
```

---

### Phase 3: SQLite Logging

**Goal:** Log every DNS query — blocked and allowed — without slowing down responses.

#### `src/logger/db.rs`
- `pub struct QueryLog` — mirrors `dns_queries` schema, derives `serde::Serialize`
- `pub struct DbLogger` holding `sqlx::SqlitePool`
- `pub async fn new(database_url: &str) -> anyhow::Result<Self>`
  - Create pool, run `sqlx::migrate!("./migrations")`
- `pub async fn log(&self, entry: QueryLog) -> anyhow::Result<()>`
  - INSERT into `dns_queries`
  - Called via fire-and-forget: `tokio::spawn(db.log(entry))`
  - DNS response path must never await this
- `pub async fn query_range(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> anyhow::Result<Vec<QueryLog>>`
  - Used by analyzer

#### Update `src/dns/handler.rs`
- Add `db: Arc<DbLogger>` field
- Capture `Instant::now()` before forwarding
- After each decision (block or forward), spawn log task:
  ```rust
  let db = self.db.clone();
  let entry = QueryLog { ... };
  tokio::spawn(async move { let _ = db.log(entry).await; });
  ```
- Include `response_ms` from elapsed instant

**Verify:** Run a few queries, open `kidguard.db` in DB Browser for SQLite.
Confirm rows appear with correct `blocked`, `category`, and `response_ms` values.

---

### Phase 4: OpenAI Behavior Analysis

**Goal:** Aggregate the day's DNS logs and get GPT-4o to write a parent-friendly report.

#### `src/analyzer/aggregator.rs`
- `pub struct DomainCount { pub domain: String, pub count: u32 }`
- `pub struct DailySummary`
  ```rust
  pub struct DailySummary {
      pub date: String,
      pub total_queries: u32,
      pub unique_domains: u32,
      pub blocked_attempts: u32,
      pub top_domains: Vec<DomainCount>,
      pub top_blocked: Vec<DomainCount>,
      pub queries_by_hour: Vec<(u8, u32)>,   // (hour 0-23, count)
      pub categories_blocked: HashMap<String, u32>,
  }
  ```
- `pub async fn build(db: &DbLogger, lookback_days: i64) -> anyhow::Result<DailySummary>`
  - Compute time range: now minus `lookback_days`
  - Fetch rows via `db.query_range()`
  - Aggregate entirely in memory — no heavy SQL needed at this scale
  - Sort `top_domains` and `top_blocked` descending by count
  - Trim to `config.analyzer.report_top_domains`

#### `src/analyzer/openai.rs`
- `pub struct OpenAiAnalyzer { api_key: String, client: reqwest::Client }`
- `pub async fn analyze(&self, summary: &DailySummary) -> anyhow::Result<String>`
- System prompt:
  ```
  You are a parental monitoring assistant. You analyze internet activity
  from an 8-year-old child's device and write a short, friendly daily
  report for the parent.

  Your report should include:
  1. A plain-language summary of what the child did online
  2. Any patterns worth noting (unusual hours, heavy usage, unexpected domains)
  3. Positive observations if any (educational or creative content)
  4. One or two brief actionable recommendations if relevant

  Keep the report under 200 words. Write warmly for a non-technical parent.
  Do not be alarmist. Do not list every domain — focus on patterns and insight.
  ```
- User message: `serde_json::to_string_pretty(&summary)`
- POST to `https://api.openai.com/v1/chat/completions`:
  ```json
  {
    "model": "gpt-4o",
    "max_tokens": 500,
    "messages": [
      { "role": "system", "content": "..." },
      { "role": "user", "content": "..." }
    ]
  }
  ```
- Header: `Authorization: Bearer {OPENAI_API_KEY}`
- Parse: `response["choices"][0]["message"]["content"].as_str()`
- On API error: log warning and return a fallback plain-text summary

#### `src/analyzer/mod.rs`
- `pub async fn run(config: Arc<AppConfig>, db: Arc<DbLogger>, api_key: &str) -> anyhow::Result<(DailySummary, String)>`
- Build summary via `aggregator::build()` then analyze via `openai::analyze()`
- Return both so the reporter can use the raw summary for stats

---

### Phase 5: Email Report

**Goal:** Send a daily HTML email combining stats and AI analysis.

#### `src/reporter/email.rs`
- `pub struct EmailReporter` — holds SMTP config fields and credentials from env
- `pub async fn send(&self, summary: &DailySummary, analysis: &str) -> anyhow::Result<()>`
- Build HTML email:
  - Subject: `🛡️ KidGuard Report — {date}`
  - Stats row: Total queries | Unique domains | Blocked attempts
  - Top domains table: domain | visits (top 10)
  - Blocked attempts table: domain | category (if any)
  - Activity by hour: simple text bar chart using `█` chars
    e.g. `14:00 ████████ 32 queries`
  - AI Analysis section: `analysis` string rendered as paragraphs
  - Footer: `Sent by KidGuard`
- Use `lettre::AsyncSmtpTransport::<Tokio1Executor>::starttls_relay()`
- Credentials: `SMTP_USERNAME` / `SMTP_PASSWORD` from env
- On send failure: log error, do not panic

#### Update `src/main.rs`
- After spawning blocklist sync scheduler, add analysis + report job:
  ```rust
  scheduler.add(Job::new_async(&config.analyzer.schedule, move |_, _| {
      let config = config.clone();
      let db = db.clone();
      Box::pin(async move {
          match analyzer::run(config.clone(), db, &api_key).await {
              Ok((summary, analysis)) => {
                  let _ = reporter.send(&summary, &analysis).await;
              }
              Err(e) => tracing::error!("Analysis failed: {}", e),
          }
      })
  })?)?;
  scheduler.start().await?;
  ```

---

### Phase 6: Deploy

#### `Dockerfile`

```dockerfile
FROM rust:1.77-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/kidguard .
COPY config.yaml .
COPY migrations/ migrations/
EXPOSE 53/udp 53/tcp
CMD ["./kidguard"]
```

#### `docker-compose.yml`

```yaml
version: "3.9"
services:
  kidguard:
    build: .
    restart: unless-stopped
    network_mode: host          # Required for DNS port 53
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./data:/app/data
      - ./blocklists:/app/blocklists
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - SMTP_USERNAME=${SMTP_USERNAME}
      - SMTP_PASSWORD=${SMTP_PASSWORD}
      - DATABASE_URL=sqlite:///app/data/kidguard.db
      - RUST_LOG=info
```

#### FritzBox Setup

1. Reserve a static LAN IP for your server via FritzBox DHCP reservation
   (e.g. `192.168.1.50` bound to server MAC address)
2. Go to **Internet → Filters → Parental Controls**
3. Select child's device profile
4. Set DNS server to `192.168.1.50`
5. Verify on child's device:
   ```
   nslookup tiktok.com     # should return NXDOMAIN
   nslookup roblox.com     # should return real IP
   ```

---

## Environment Variables

| Variable | Description |
|---|---|
| `OPENAI_API_KEY` | OpenAI API key |
| `SMTP_USERNAME` | Gmail address |
| `SMTP_PASSWORD` | Gmail app password (not your login password) |
| `DATABASE_URL` | `sqlite:///app/data/kidguard.db` |
| `RUST_LOG` | `info` for prod, `debug` for dev |

---

## Testing Checklist

- [ ] `dig @127.0.0.1 google.com` → real IP (default allow)
- [ ] `dig @127.0.0.1 roblox.com` → real IP (custom_allow)
- [ ] `dig @127.0.0.1 tiktok.com` → NXDOMAIN (custom_block)
- [ ] `dig @127.0.0.1 www.tiktok.com` → NXDOMAIN (subdomain match)
- [ ] `dig @127.0.0.1 doubleclick.net` → NXDOMAIN (stevenblack list)
- [ ] `dig @127.0.0.1 khanacademy.org` → real IP (custom_allow beats list)
- [ ] SQLite has rows after queries with correct `blocked`, `category`, `response_ms`
- [ ] Blocklist re-syncs daily without restarting the server
- [ ] Sync failure falls back to cached lists, server keeps running
- [ ] Daily email arrives with stats and GPT-4o analysis section
- [ ] Adding a domain to `custom_block` in config + restart blocks it immediately
- [ ] Server stays up if upstream DNS is unreachable (returns SERVFAIL, does not crash)
- [ ] Docker container restarts cleanly after reboot

---

## Notes for Claude CLI

- Implement phases strictly in order — do not advance until all verify steps for
  the current phase pass
- Run `cargo clippy -- -D warnings` after each phase and fix all issues before continuing
- Use `anyhow::Result` everywhere in application code
- Use `thiserror` for any custom error types defined in library modules
- Never use `.unwrap()` in non-test code — use `?` or explicit match
- DNS handler must never block the response path — DB writes are always
  fire-and-forget via `tokio::spawn`
- `BlocklistMatcher` is read-heavy — use `Arc<RwLock<>>` with short write
  locks only during sync swap
- Blocklist sync must never crash the server on network failure — log the error,
  fall back to cache, continue
- Log every phase transition and key events with `tracing::info!`
- All public functions must have doc comments
- Use `tracing::instrument` on key async functions for observability