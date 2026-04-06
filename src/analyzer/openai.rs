use serde_json::json;
use tracing::{info, warn};

use super::aggregator::ClientSummary;

const SYSTEM_PROMPT: &str = r#"You are a parental monitoring assistant analyzing DNS activity from a child's device. Write a short, insightful daily report for the parent.

You will receive structured JSON with the child's name, top domains, blocked attempts, hourly activity, and categories. Your job is to interpret this data — don't just restate the numbers.

Your report should have these sections:

**What they did today** — Classify the activity into categories the parent understands: gaming (Roblox, Minecraft, Steam), video (YouTube, Netflix, Twitch), social media, education (Khan Academy, Scratch, school platforms), browsing, etc. Estimate how the child split their time across these categories based on query volume.

**Behavioral insights** — What does the pattern tell you? Examples: "Heavily focused on gaming today with very little educational content", "Spent most of the afternoon on YouTube — likely watching videos after school", "Tried to access TikTok 12 times — may be feeling left out if friends use it". Note any unusual hours (late night activity, early morning).

**Interests & development** — Infer what the child might be interested in based on the domains. Examples: "The Scratch activity suggests interest in coding/creative projects", "Frequent Roblox + YouTube combo often means watching game tutorials", "New domain X appeared — could indicate a new hobby or friend recommendation".

**One recommendation** — A single, specific, actionable suggestion. Not generic advice.

Keep it under 250 words. Write warmly. Be honest but not alarmist. The parent is non-technical — use plain language, no domain names unless they help understanding. Refer to the child by their name."#;

/// Client for OpenAI GPT-5.4-mini analysis.
pub struct OpenAiAnalyzer {
    api_key: String,
    client: reqwest::Client,
}

impl OpenAiAnalyzer {
    /// Create a new analyzer with the given API key.
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Send a client summary to GPT-5.4-mini and return the analysis text.
    pub async fn analyze(&self, summary: &ClientSummary) -> anyhow::Result<String> {
        let user_message = serde_json::to_string_pretty(summary)?;

        let body = json!({
            "model": "gpt-5.4-mini",
            "max_completion_tokens": 500,
            "messages": [
                { "role": "system", "content": SYSTEM_PROMPT },
                { "role": "user", "content": user_message }
            ]
        });

        info!("Sending summary for '{}' to OpenAI for analysis", summary.client_name);

        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            warn!("OpenAI API error ({}): {}", status, error_body);
            return Ok(build_fallback_summary(summary));
        }

        let json: serde_json::Value = response.json().await?;

        let analysis = json["choices"][0]["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                warn!("Could not parse OpenAI response, using fallback");
                build_fallback_summary(summary)
            });

        Ok(analysis)
    }
}

/// Build a plain-text fallback summary when OpenAI is unavailable.
fn build_fallback_summary(summary: &ClientSummary) -> String {
    let mut text = format!(
        "Daily Summary for {} ({})\n\nTotal queries: {}\nUnique domains: {}\nBlocked attempts: {}\n",
        summary.client_name, summary.date, summary.total_queries, summary.unique_domains, summary.blocked_attempts
    );

    if !summary.top_domains.is_empty() {
        text.push_str("\nTop domains:\n");
        for d in &summary.top_domains {
            text.push_str(&format!("  {} — {} visits\n", d.domain, d.count));
        }
    }

    if !summary.top_blocked.is_empty() {
        text.push_str("\nTop blocked:\n");
        for d in &summary.top_blocked {
            text.push_str(&format!("  {} — {} attempts\n", d.domain, d.count));
        }
    }

    text
}
