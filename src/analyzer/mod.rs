pub mod aggregator;
pub mod openai;

use tracing::info;

use crate::config::AppConfig;
use crate::logger::db::DbLogger;
use crate::reporter::email::ClientReport;

/// Run the daily analysis: aggregate logs per client and get AI analysis for each.
pub async fn run(
    config: &AppConfig,
    db: &DbLogger,
    api_key: &str,
) -> anyhow::Result<Vec<ClientReport>> {
    info!("Starting daily analysis");

    let summaries =
        aggregator::build(db, config.analyzer.lookback_days, config.analyzer.report_top_domains)
            .await?;

    let analyzer = openai::OpenAiAnalyzer::new(api_key);
    let mut reports = Vec::new();

    for summary in summaries {
        info!(
            "Summary for '{}': {} total queries, {} unique domains, {} blocked",
            summary.client_name, summary.total_queries, summary.unique_domains, summary.blocked_attempts
        );

        let analysis = analyzer.analyze(&summary).await?;
        info!("AI analysis complete for '{}'", summary.client_name);

        reports.push(ClientReport { summary, analysis });
    }

    Ok(reports)
}
