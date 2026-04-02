use std::collections::{HashMap, HashSet};

use crate::config::BlocklistConfig;

/// Result of checking a domain against the blocklist.
#[derive(Debug, Clone)]
pub struct BlockResult {
    pub rule: String,
    pub category: String,
}

/// Matches domains against allow/block lists with parent domain walking.
pub struct BlocklistMatcher {
    /// custom_allow — checked first, always wins
    allowed: HashSet<String>,
    /// custom_block — checked second
    blocked_custom: HashSet<String>,
    /// domain → category from public blocklist sources
    blocked_lists: HashMap<String, String>,
}

impl BlocklistMatcher {
    /// Build a matcher from the config's custom allow/block lists.
    pub fn new(config: &BlocklistConfig) -> Self {
        let allowed: HashSet<String> = config
            .custom_allow
            .iter()
            .map(|d| d.to_lowercase())
            .collect();

        let blocked_custom: HashSet<String> = config
            .custom_block
            .iter()
            .map(|d| d.to_lowercase())
            .collect();

        Self {
            allowed,
            blocked_custom,
            blocked_lists: HashMap::new(),
        }
    }

    /// Add domains from a fetched source into the blocked lists.
    pub fn load_source(&mut self, domains: Vec<String>, category: &str) {
        for domain in domains {
            self.blocked_lists.insert(domain, category.to_string());
        }
    }

    /// Check if a domain is blocked.
    ///
    /// Matching priority:
    /// 1. custom_allow (exact or parent match) → None (allow)
    /// 2. custom_block (exact or parent match) → Some(BlockResult)
    /// 3. blocked_lists (exact or parent match) → Some(BlockResult)
    /// 4. Default → None (allow)
    ///
    /// Specificity: a more specific custom_block beats a broader custom_allow.
    /// e.g. custom_block: metrics.roblox.com beats custom_allow: roblox.com
    pub fn is_blocked(&self, domain: &str) -> Option<BlockResult> {
        let domain = domain.to_lowercase();

        // Walk parent domains from most specific to least specific
        // For "sub.evil.com" → try "sub.evil.com", "evil.com"
        let labels: Vec<&str> = domain.split('.').collect();

        // Find the most specific allow match
        let allow_depth = self.find_match_depth(&labels, &self.allowed);

        // Find the most specific block match (custom or list)
        let (block_depth, block_result) = self.find_block_match_depth(&labels);

        match (allow_depth, block_depth) {
            (Some(a_depth), Some(b_depth)) => {
                // More specific match wins (lower depth = more specific)
                if b_depth < a_depth {
                    block_result
                } else {
                    None // allow wins on tie or when allow is more specific
                }
            }
            (None, Some(_)) => block_result,
            _ => None, // allowed or not in any list
        }
    }

    /// Returns the total number of blocked domains across all sources.
    pub fn total_blocked_count(&self) -> usize {
        self.blocked_custom.len() + self.blocked_lists.len()
    }

    /// Find how deep in the parent chain a match is found (0 = exact match).
    fn find_match_depth(&self, labels: &[&str], set: &HashSet<String>) -> Option<usize> {
        for i in 0..labels.len().saturating_sub(1) {
            let candidate: String = labels[i..].join(".");
            if set.contains(&candidate) {
                return Some(i);
            }
        }
        None
    }

    /// Find the most specific block match across custom and list blocks.
    fn find_block_match_depth(&self, labels: &[&str]) -> (Option<usize>, Option<BlockResult>) {
        for i in 0..labels.len().saturating_sub(1) {
            let candidate: String = labels[i..].join(".");

            if self.blocked_custom.contains(&candidate) {
                return (
                    Some(i),
                    Some(BlockResult {
                        rule: candidate,
                        category: "custom".to_string(),
                    }),
                );
            }

            if let Some(category) = self.blocked_lists.get(&candidate) {
                return (
                    Some(i),
                    Some(BlockResult {
                        rule: candidate,
                        category: category.clone(),
                    }),
                );
            }
        }
        (None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> BlocklistConfig {
        BlocklistConfig {
            sources: vec![],
            custom_block: vec!["tiktok.com".into(), "metrics.roblox.com".into()],
            custom_allow: vec!["roblox.com".into(), "khanacademy.org".into()],
            sync_interval_hours: 24,
            cache_dir: "./blocklists".into(),
        }
    }

    #[test]
    fn test_custom_block() {
        let matcher = BlocklistMatcher::new(&test_config());
        let result = matcher.is_blocked("tiktok.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().category, "custom");
    }

    #[test]
    fn test_subdomain_block() {
        let matcher = BlocklistMatcher::new(&test_config());
        let result = matcher.is_blocked("www.tiktok.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_custom_allow() {
        let matcher = BlocklistMatcher::new(&test_config());
        let result = matcher.is_blocked("roblox.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_subdomain_allow() {
        let matcher = BlocklistMatcher::new(&test_config());
        let result = matcher.is_blocked("cdn.roblox.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_specificity_block_beats_allow() {
        // custom_block: metrics.roblox.com should beat custom_allow: roblox.com
        let matcher = BlocklistMatcher::new(&test_config());
        let result = matcher.is_blocked("metrics.roblox.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule, "metrics.roblox.com");
    }

    #[test]
    fn test_default_allow() {
        let matcher = BlocklistMatcher::new(&test_config());
        let result = matcher.is_blocked("google.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_list_source_block() {
        let mut matcher = BlocklistMatcher::new(&test_config());
        matcher.load_source(vec!["doubleclick.net".into()], "ads_malware");
        let result = matcher.is_blocked("doubleclick.net");
        assert!(result.is_some());
        assert_eq!(result.unwrap().category, "ads_malware");
    }

    #[test]
    fn test_allow_beats_list_source() {
        let mut matcher = BlocklistMatcher::new(&test_config());
        // Even if khanacademy.org appears in a blocklist, custom_allow wins
        matcher.load_source(vec!["khanacademy.org".into()], "general");
        let result = matcher.is_blocked("khanacademy.org");
        assert!(result.is_none());
    }
}
