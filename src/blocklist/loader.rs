use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

/// Fetch a blocklist from a URL and return cleaned domain strings.
pub async fn fetch(url: &str) -> anyhow::Result<Vec<String>> {
    info!("Fetching blocklist from {}", url);
    let body = reqwest::get(url).await?.text().await?;
    let domains = parse_list(&body);
    info!("Fetched {} domains from {}", domains.len(), url);
    Ok(domains)
}

/// Parse a blocklist body (hosts file or plain domain list) into clean domain strings.
fn parse_list(body: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut domains = Vec::new();

    for line in body.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        let domain = if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
            // Hosts file format: "0.0.0.0 domain" or "127.0.0.1 domain"
            line.split_whitespace()
                .nth(1)
                .map(|d| d.trim_end_matches('.').to_lowercase())
        } else if line.contains(' ') || line.contains('\t') {
            // Skip lines with spaces that aren't hosts format
            None
        } else {
            // Plain domain list: one domain per line
            // Handle wildcard entries like "*.example.com"
            let d = line.trim_start_matches("*.");
            Some(d.trim_end_matches('.').to_lowercase())
        };

        if let Some(d) = domain {
            // Skip localhost entries and invalid domains
            if !d.is_empty()
                && d != "localhost"
                && d != "local"
                && d.contains('.')
                && seen.insert(d.clone())
            {
                domains.push(d);
            }
        }
    }

    domains
}

/// Save fetched domains to a local cache file.
pub fn save_cache(name: &str, domains: &[String], cache_dir: &str) -> anyhow::Result<()> {
    let path = Path::new(cache_dir).join(format!("{}.txt", name));
    std::fs::create_dir_all(cache_dir)?;
    std::fs::write(&path, domains.join("\n"))?;
    info!("Cached {} domains for '{}' at {}", domains.len(), name, path.display());
    Ok(())
}

/// Load domains from a local cache file (fallback when network fetch fails).
pub fn load_cache(name: &str, cache_dir: &str) -> anyhow::Result<Vec<String>> {
    let path = Path::new(cache_dir).join(format!("{}.txt", name));
    let content = std::fs::read_to_string(&path)?;
    let domains: Vec<String> = content
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();
    warn!("Loaded {} cached domains for '{}'", domains.len(), name);
    Ok(domains)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts_format() {
        let body = "# Comment\n0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.com\n";
        let domains = parse_list(body);
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_parse_plain_list() {
        let body = "# Comment\nads.example.com\ntracker.example.com\n";
        let domains = parse_list(body);
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_parse_dedup() {
        let body = "0.0.0.0 ads.example.com\n0.0.0.0 ads.example.com\n";
        let domains = parse_list(body);
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_parse_wildcard() {
        let body = "*.example.com\nexample.org\n";
        let domains = parse_list(body);
        assert_eq!(domains, vec!["example.com", "example.org"]);
    }

    #[test]
    fn test_skip_localhost() {
        let body = "0.0.0.0 localhost\n0.0.0.0 ads.example.com\n";
        let domains = parse_list(body);
        assert_eq!(domains, vec!["ads.example.com"]);
    }
}
