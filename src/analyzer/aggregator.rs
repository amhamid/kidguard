use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde::Serialize;

use crate::logger::db::DbLogger;

/// Count of queries for a single domain.
#[derive(Debug, Clone, Serialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: u32,
}

/// Aggregated daily DNS activity summary.
#[derive(Debug, Clone, Serialize)]
pub struct DailySummary {
    pub date: String,
    pub total_queries: u32,
    pub unique_domains: u32,
    pub blocked_attempts: u32,
    pub top_domains: Vec<DomainCount>,
    pub top_blocked: Vec<DomainCount>,
    pub queries_by_hour: Vec<(u8, u32)>,
    pub categories_blocked: HashMap<String, u32>,
}

/// Build a daily summary from the database logs.
pub async fn build(
    db: &DbLogger,
    lookback_days: i64,
    top_n: usize,
) -> anyhow::Result<DailySummary> {
    let now = Utc::now();
    let from = now - Duration::days(lookback_days);
    let date = now.format("%Y-%m-%d").to_string();

    let rows = db.query_range(from, now).await?;

    let total_queries = rows.len() as u32;
    let mut domain_counts: HashMap<String, u32> = HashMap::new();
    let mut blocked_counts: HashMap<String, u32> = HashMap::new();
    let mut hour_counts: HashMap<u8, u32> = HashMap::new();
    let mut category_counts: HashMap<String, u32> = HashMap::new();
    let mut blocked_attempts: u32 = 0;

    for row in &rows {
        *domain_counts.entry(row.domain.clone()).or_default() += 1;

        let hour = row.timestamp.hour() as u8;
        *hour_counts.entry(hour).or_default() += 1;

        if row.blocked {
            blocked_attempts += 1;
            *blocked_counts.entry(row.domain.clone()).or_default() += 1;
            if let Some(ref cat) = row.category {
                *category_counts.entry(cat.clone()).or_default() += 1;
            }
        }
    }

    let unique_domains = domain_counts.len() as u32;

    let top_domains = top_n_from_map(&domain_counts, top_n);
    let top_blocked = top_n_from_map(&blocked_counts, top_n);

    let mut queries_by_hour: Vec<(u8, u32)> = (0..24)
        .map(|h| (h, *hour_counts.get(&h).unwrap_or(&0)))
        .collect();
    queries_by_hour.sort_by_key(|(h, _)| *h);

    Ok(DailySummary {
        date,
        total_queries,
        unique_domains,
        blocked_attempts,
        top_domains,
        top_blocked,
        queries_by_hour,
        categories_blocked: category_counts,
    })
}

/// Extract the top N entries from a count map, sorted descending.
fn top_n_from_map(map: &HashMap<String, u32>, n: usize) -> Vec<DomainCount> {
    let mut entries: Vec<_> = map
        .iter()
        .map(|(domain, &count)| DomainCount {
            domain: domain.clone(),
            count,
        })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count));
    entries.truncate(n);
    entries
}

use chrono::Timelike;
