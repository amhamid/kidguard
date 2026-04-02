pub mod aggregator;
pub mod openai;

use tracing::info;

use crate::config::AppConfig;
use crate::logger::db::DbLogger;

use self::aggregator::DailySummary;

/// Run the daily analysis: aggregate logs and get AI analysis.
pub async fn run(
    config: &AppConfig,
    db: &DbLogger,
    api_key: &str,
) -> anyhow::Result<(DailySummary, String)> {
    info!("Starting daily analysis");

    let summary =
        aggregator::build(db, config.analyzer.lookback_days, config.analyzer.report_top_domains)
            .await?;

    info!(
        "Summary: {} total queries, {} unique domains, {} blocked",
        summary.total_queries, summary.unique_domains, summary.blocked_attempts
    );

    let analyzer = openai::OpenAiAnalyzer::new(api_key);
    let analysis = analyzer.analyze(&summary).await?;

    info!("AI analysis complete");

    Ok((summary, analysis))
}
