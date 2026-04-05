use std::env;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;

mod analyzer;
mod blocklist;
mod config;
mod dns;
mod logger;
mod reporter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env and config
    let app_config = config::load()?;

    // Init tracing — user can override with RUST_LOG env var
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    "kidguard=info,hickory_server=warn,tokio_cron_scheduler=warn"
                        .parse()
                        .expect("valid default filter")
                }),
        )
        .init();

    info!("KidGuard starting up");

    let app_config = Arc::new(app_config);

    // Initialize database
    let db = Arc::new(logger::db::DbLogger::new(&app_config.database.path).await?);

    // Build blocklist matcher from config custom lists
    let matcher = Arc::new(RwLock::new(blocklist::matcher::BlocklistMatcher::new(
        &app_config.blocklist,
    )));

    // Sync blocklists from network at startup
    blocklist::sync::sync_all(&app_config, matcher.clone(), Some(db.clone())).await;

    // Schedule periodic blocklist sync
    let sync_config = app_config.clone();
    let sync_matcher = matcher.clone();
    let sync_db = db.clone();
    tokio::spawn(async move {
        if let Err(e) = blocklist::sync::schedule(sync_config, sync_matcher, sync_db).await {
            tracing::error!("Failed to start blocklist sync scheduler: {}", e);
        }
    });

    // Schedule daily analysis + email report
    let api_key = env::var("OPENAI_API_KEY").ok();
    if let Some(api_key) = api_key {
        let report_config = app_config.clone();
        let report_db = db.clone();
        let email_reporter = reporter::email::EmailReporter::new(&app_config.reporter)
            .map(Arc::new)
            .ok();

        tokio::spawn(async move {
            if let Err(e) =
                schedule_analysis(report_config, report_db, api_key, email_reporter).await
            {
                tracing::error!("Failed to start analysis scheduler: {}", e);
            }
        });
    } else {
        info!("OPENAI_API_KEY not set, daily analysis disabled");
    }

    // Build DNS forwarder and handler
    let forwarder = Arc::new(dns::forwarder::Forwarder::new(&app_config.dns)?);
    let handler = dns::handler::DnsHandler::new(forwarder, matcher, db, &app_config.dns.filtered_clients);

    // Run DNS server (blocks until shutdown)
    dns::server::run(&app_config, handler).await?;

    Ok(())
}

/// Schedule the daily analysis + email report job.
async fn schedule_analysis(
    config: Arc<config::AppConfig>,
    db: Arc<logger::db::DbLogger>,
    api_key: String,
    email_reporter: Option<Arc<reporter::email::EmailReporter>>,
) -> anyhow::Result<()> {
    use tokio_cron_scheduler::{Job, JobScheduler};

    let schedule = config.analyzer.schedule.clone();
    let tz: chrono_tz::Tz = config.analyzer.timezone.parse()
        .map_err(|e| anyhow::anyhow!("Invalid timezone '{}': {}", config.analyzer.timezone, e))?;
    let sched = JobScheduler::new().await?;

    sched
        .add(Job::new_async_tz(schedule.as_str(), tz, move |_uuid, _lock| {
            let config = config.clone();
            let db = db.clone();
            let api_key = api_key.clone();
            let email_reporter = email_reporter.clone();
            Box::pin(async move {
                match analyzer::run(&config, &db, &api_key).await {
                    Ok(reports) => {
                        tracing::info!("Daily analysis complete for {} client(s)", reports.len());
                        if let Some(ref reporter) = email_reporter {
                            if let Err(e) = reporter.send(&reports).await {
                                tracing::error!("Failed to send report email: {}", e);
                            }
                        }
                    }
                    Err(e) => tracing::error!("Daily analysis failed: {}", e),
                }
            })
        })?)
        .await?;

    sched.start().await?;
    info!("Daily analysis scheduled with cron: {}", schedule);

    Ok(())
}
