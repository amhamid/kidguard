use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tracing::{error, info};

/// A single DNS query log entry.
#[derive(Debug, Clone, Serialize)]
pub struct QueryLog {
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub client_name: Option<String>,
    pub domain: String,
    pub query_type: String,
    pub blocked: bool,
    pub blocked_rule: Option<String>,
    pub category: Option<String>,
    pub resolved_ip: Option<String>,
    pub response_ms: i64,
}

/// Handles logging DNS queries to SQLite.
pub struct DbLogger {
    pool: SqlitePool,
}

impl DbLogger {
    /// Create a new DbLogger, running migrations on first use.
    pub async fn new(db_path: &str) -> anyhow::Result<Self> {
        // Ensure the parent directory exists
        if let Some(parent) = std::path::Path::new(db_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        // Run migrations
        sqlx::query(include_str!("../../migrations/001_initial.sql"))
            .execute(&pool)
            .await
            .ok(); // Ignore "already exists" errors on subsequent runs

        // Create tables individually if batch execution isn't supported
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS dns_queries (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT NOT NULL,
                client_ip     TEXT NOT NULL,
                domain        TEXT NOT NULL,
                query_type    TEXT NOT NULL,
                blocked       INTEGER NOT NULL DEFAULT 0,
                blocked_rule  TEXT,
                category      TEXT,
                resolved_ip   TEXT,
                response_ms   INTEGER
            )",
        )
        .execute(&pool)
        .await?;

        // Add client_name column if it doesn't exist (migration for existing DBs)
        sqlx::query("ALTER TABLE dns_queries ADD COLUMN client_name TEXT")
            .execute(&pool)
            .await
            .ok();

        // Create indexes (ignore errors if they already exist)
        for idx in &[
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON dns_queries(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_domain ON dns_queries(domain)",
            "CREATE INDEX IF NOT EXISTS idx_blocked ON dns_queries(blocked)",
            "CREATE INDEX IF NOT EXISTS idx_client_name ON dns_queries(client_name)",
        ] {
            sqlx::query(idx).execute(&pool).await?;
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blocklist_meta (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name     TEXT NOT NULL UNIQUE,
                last_synced_at  TEXT NOT NULL,
                domain_count    INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        info!("Database initialized at {}", db_path);
        Ok(Self { pool })
    }

    /// Log a DNS query entry. Called fire-and-forget via tokio::spawn.
    pub async fn log(&self, entry: QueryLog) {
        let result = sqlx::query(
            "INSERT INTO dns_queries (timestamp, client_ip, client_name, domain, query_type, blocked, blocked_rule, category, resolved_ip, response_ms)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(entry.timestamp.to_rfc3339())
        .bind(&entry.client_ip)
        .bind(&entry.client_name)
        .bind(&entry.domain)
        .bind(&entry.query_type)
        .bind(entry.blocked as i32)
        .bind(&entry.blocked_rule)
        .bind(&entry.category)
        .bind(&entry.resolved_ip)
        .bind(entry.response_ms)
        .execute(&self.pool)
        .await;

        if let Err(e) = result {
            error!("Failed to log DNS query: {}", e);
        }
    }

    /// Query DNS log entries within a time range (used by analyzer).
    pub async fn query_range(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> anyhow::Result<Vec<QueryLog>> {
        let rows = sqlx::query_as::<_, QueryLogRow>(
            "SELECT timestamp, client_ip, client_name, domain, query_type, blocked, blocked_rule, category, resolved_ip, response_ms
             FROM dns_queries
             WHERE timestamp >= ? AND timestamp <= ?
             ORDER BY timestamp",
        )
        .bind(from.to_rfc3339())
        .bind(to.to_rfc3339())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Update blocklist metadata after sync.
    pub async fn update_blocklist_meta(
        &self,
        source_name: &str,
        domain_count: usize,
    ) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO blocklist_meta (source_name, last_synced_at, domain_count)
             VALUES (?, ?, ?)
             ON CONFLICT(source_name) DO UPDATE SET last_synced_at = excluded.last_synced_at, domain_count = excluded.domain_count",
        )
        .bind(source_name)
        .bind(&now)
        .bind(domain_count as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// Internal row type for SQLx deserialization.
#[derive(sqlx::FromRow)]
struct QueryLogRow {
    timestamp: String,
    client_ip: String,
    client_name: Option<String>,
    domain: String,
    query_type: String,
    blocked: i32,
    blocked_rule: Option<String>,
    category: Option<String>,
    resolved_ip: Option<String>,
    response_ms: Option<i64>,
}

impl From<QueryLogRow> for QueryLog {
    fn from(row: QueryLogRow) -> Self {
        Self {
            timestamp: DateTime::parse_from_rfc3339(&row.timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            client_ip: row.client_ip,
            client_name: row.client_name,
            domain: row.domain,
            query_type: row.query_type,
            blocked: row.blocked != 0,
            blocked_rule: row.blocked_rule,
            category: row.category,
            resolved_ip: row.resolved_ip,
            response_ms: row.response_ms.unwrap_or(0),
        }
    }
}
