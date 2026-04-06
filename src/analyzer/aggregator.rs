use std::collections::HashMap;

use chrono::{Duration, Timelike, Utc};
use serde::Serialize;

use crate::logger::db::DbLogger;

/// Extract the top-level registered domain from a full domain name.
/// e.g. "cdn.roblox.com" → "roblox.com", "youtube.com" → "youtube.com"
fn extract_top_domain(domain: &str) -> &str {
    let parts: Vec<&str> = domain.rsplitn(3, '.').collect();
    if parts.len() >= 2 {
        // Return "sld.tld" — the start of the second-to-last label
        let tld = parts[0];
        let sld = parts[1];
        // Calculate offset: domain ends with "sld.tld"
        let suffix_len = sld.len() + 1 + tld.len(); // +1 for the dot
        &domain[domain.len() - suffix_len..]
    } else {
        domain
    }
}

/// Count of queries for a single domain.
#[derive(Debug, Clone, Serialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: u32,
}

/// Aggregated DNS activity summary for a single client.
#[derive(Debug, Clone, Serialize)]
pub struct ClientSummary {
    pub client_name: String,
    pub date: String,
    pub total_queries: u32,
    pub unique_domains: u32,
    pub blocked_attempts: u32,
    pub top_domains: Vec<DomainCount>,
    pub top_blocked: Vec<DomainCount>,
    pub queries_by_hour: Vec<(u8, u32)>,
    pub categories_blocked: HashMap<String, u32>,
}

/// Build per-client daily summaries from the database logs.
/// If no client names are present in the logs, returns a single summary named "All Devices".
pub async fn build(
    db: &DbLogger,
    lookback_days: i64,
    top_n: usize,
) -> anyhow::Result<Vec<ClientSummary>> {
    let now = Utc::now();
    let from = now - Duration::days(lookback_days);
    let date = now.format("%Y-%m-%d").to_string();

    let rows = db.query_range(from, now).await?;
    Ok(build_from_logs(rows, &date, top_n))
}

fn build_summary(
    client_name: &str,
    date: &str,
    rows: &[crate::logger::db::QueryLog],
    top_n: usize,
) -> ClientSummary {
    let total_queries = rows.len() as u32;
    let mut domain_subdomains: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let mut blocked_subdomains: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let mut hour_counts: HashMap<u8, u32> = HashMap::new();
    let mut category_counts: HashMap<String, u32> = HashMap::new();
    let mut blocked_attempts: u32 = 0;

    for row in rows {
        let top_domain = extract_top_domain(&row.domain).to_string();
        domain_subdomains.entry(top_domain.clone()).or_default().insert(row.domain.clone());

        let hour = row.timestamp.hour() as u8;
        *hour_counts.entry(hour).or_default() += 1;

        if row.blocked {
            blocked_attempts += 1;
            blocked_subdomains.entry(top_domain).or_default().insert(row.domain.clone());
            if let Some(ref cat) = row.category {
                *category_counts.entry(cat.clone()).or_default() += 1;
            }
        }
    }

    let unique_domains = domain_subdomains.len() as u32;
    let domain_counts: HashMap<String, u32> = domain_subdomains
        .into_iter()
        .map(|(domain, subs)| (domain, subs.len() as u32))
        .collect();
    let blocked_counts: HashMap<String, u32> = blocked_subdomains
        .into_iter()
        .map(|(domain, subs)| (domain, subs.len() as u32))
        .collect();
    let top_domains = top_n_from_map(&domain_counts, top_n);
    let top_blocked = top_n_from_map(&blocked_counts, top_n);

    let mut queries_by_hour: Vec<(u8, u32)> = (0..24)
        .map(|h| (h, *hour_counts.get(&h).unwrap_or(&0)))
        .collect();
    queries_by_hour.sort_by_key(|(h, _)| *h);

    ClientSummary {
        client_name: client_name.to_string(),
        date: date.to_string(),
        total_queries,
        unique_domains,
        blocked_attempts,
        top_domains,
        top_blocked,
        queries_by_hour,
        categories_blocked: category_counts,
    }
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

/// Build per-client summaries from pre-fetched query logs (for testing and direct use).
pub fn build_from_logs(
    rows: Vec<crate::logger::db::QueryLog>,
    date: &str,
    top_n: usize,
) -> Vec<ClientSummary> {
    let mut grouped: HashMap<String, Vec<_>> = HashMap::new();
    for row in rows {
        let key = row.client_name.clone().unwrap_or_else(|| "All Devices".to_string());
        grouped.entry(key).or_default().push(row);
    }

    if grouped.is_empty() {
        return vec![ClientSummary {
            client_name: "All Devices".to_string(),
            date: date.to_string(),
            total_queries: 0,
            unique_domains: 0,
            blocked_attempts: 0,
            top_domains: vec![],
            top_blocked: vec![],
            queries_by_hour: (0..24).map(|h| (h, 0)).collect(),
            categories_blocked: HashMap::new(),
        }];
    }

    let mut summaries = Vec::new();
    for (name, rows) in &grouped {
        summaries.push(build_summary(name, date, rows, top_n));
    }
    summaries.sort_by(|a, b| a.client_name.cmp(&b.client_name));
    summaries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::db::QueryLog;
    use chrono::Utc;

    fn make_log(client_name: Option<&str>, domain: &str, blocked: bool) -> QueryLog {
        QueryLog {
            timestamp: Utc::now(),
            client_ip: "192.168.1.100".to_string(),
            client_name: client_name.map(|s| s.to_string()),
            domain: domain.to_string(),
            query_type: "A".to_string(),
            blocked,
            blocked_rule: if blocked { Some("custom_block".to_string()) } else { None },
            category: if blocked { Some("custom".to_string()) } else { None },
            resolved_ip: if !blocked { Some("1.2.3.4".to_string()) } else { None },
            response_ms: 5,
        }
    }

    #[test]
    fn empty_logs_returns_single_all_devices() {
        let summaries = build_from_logs(vec![], "2026-04-05", 10);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].client_name, "All Devices");
        assert_eq!(summaries[0].total_queries, 0);
    }

    #[test]
    fn groups_by_client_name() {
        let logs = vec![
            make_log(Some("Samir"), "youtube.com", false),
            make_log(Some("Samir"), "roblox.com", false),
            make_log(Some("Sara"), "khanacademy.org", false),
        ];

        let summaries = build_from_logs(logs, "2026-04-05", 10);
        assert_eq!(summaries.len(), 2);

        let samir = summaries.iter().find(|s| s.client_name == "Samir").unwrap();
        assert_eq!(samir.total_queries, 2);

        let sara = summaries.iter().find(|s| s.client_name == "Sara").unwrap();
        assert_eq!(sara.total_queries, 1);
    }

    #[test]
    fn no_client_name_groups_as_all_devices() {
        let logs = vec![
            make_log(None, "google.com", false),
            make_log(None, "youtube.com", false),
        ];

        let summaries = build_from_logs(logs, "2026-04-05", 10);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].client_name, "All Devices");
        assert_eq!(summaries[0].total_queries, 2);
    }

    #[test]
    fn blocked_counts_are_per_client() {
        let logs = vec![
            make_log(Some("Samir"), "tiktok.com", true),
            make_log(Some("Samir"), "tiktok.com", true),
            make_log(Some("Samir"), "google.com", false),
            make_log(Some("Sara"), "snapchat.com", true),
        ];

        let summaries = build_from_logs(logs, "2026-04-05", 10);

        let samir = summaries.iter().find(|s| s.client_name == "Samir").unwrap();
        assert_eq!(samir.total_queries, 3);
        assert_eq!(samir.blocked_attempts, 2);

        let sara = summaries.iter().find(|s| s.client_name == "Sara").unwrap();
        assert_eq!(sara.total_queries, 1);
        assert_eq!(sara.blocked_attempts, 1);
    }

    #[test]
    fn top_domains_are_sorted_descending() {
        let logs = vec![
            make_log(Some("Samir"), "youtube.com", false),
            make_log(Some("Samir"), "www.youtube.com", false),
            make_log(Some("Samir"), "i.youtube.com", false),
            make_log(Some("Samir"), "roblox.com", false),
        ];

        let summaries = build_from_logs(logs, "2026-04-05", 10);
        let samir = &summaries[0];
        // youtube.com has 3 unique subdomains, roblox.com has 1
        assert_eq!(samir.top_domains[0].domain, "youtube.com");
        assert_eq!(samir.top_domains[0].count, 3);
        assert_eq!(samir.top_domains[1].domain, "roblox.com");
        assert_eq!(samir.top_domains[1].count, 1);
    }

    #[test]
    fn subdomains_collapse_to_top_domain() {
        let logs = vec![
            make_log(Some("Samir"), "roblox.com", false),
            make_log(Some("Samir"), "cdn.roblox.com", false),
            make_log(Some("Samir"), "metric.roblox.com", false),
            make_log(Some("Samir"), "api.roblox.com", true),
            make_log(Some("Samir"), "youtube.com", false),
            make_log(Some("Samir"), "i.ytimg.com", false),
        ];

        let summaries = build_from_logs(logs, "2026-04-05", 10);
        let samir = &summaries[0];

        // All roblox subdomains collapse into one entry
        assert_eq!(samir.unique_domains, 3); // roblox.com, youtube.com, ytimg.com

        // Count = unique subdomains seen, not total queries
        // roblox.com has 4 unique subdomains: roblox.com, cdn.roblox.com, metric.roblox.com, api.roblox.com
        assert_eq!(samir.top_domains[0].domain, "roblox.com");
        assert_eq!(samir.top_domains[0].count, 4);

        // youtube.com and ytimg.com each have 1 unique subdomain
        assert_eq!(samir.top_domains[1].count, 1);
        assert_eq!(samir.top_domains[2].count, 1);

        // Blocked: only api.roblox.com was blocked → 1 unique subdomain
        assert_eq!(samir.top_blocked[0].domain, "roblox.com");
        assert_eq!(samir.top_blocked[0].count, 1);
    }

    #[test]
    fn extract_top_domain_works() {
        assert_eq!(extract_top_domain("roblox.com"), "roblox.com");
        assert_eq!(extract_top_domain("cdn.roblox.com"), "roblox.com");
        assert_eq!(extract_top_domain("a.b.c.roblox.com"), "roblox.com");
        assert_eq!(extract_top_domain("localhost"), "localhost");
    }
}
