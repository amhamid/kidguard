use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{error, info};

use crate::blocklist::loader;
use crate::blocklist::matcher::BlocklistMatcher;
use crate::config::AppConfig;
use crate::logger::db::DbLogger;

/// Sync all blocklist sources: fetch from network, fall back to cache, load into matcher.
pub async fn sync_all(
    config: &AppConfig,
    matcher: Arc<RwLock<BlocklistMatcher>>,
    db: Option<Arc<DbLogger>>,
) {
    info!("Starting blocklist sync");

    let mut new_matcher = BlocklistMatcher::new(&config.blocklist);

    for source in &config.blocklist.sources {
        let domains = match loader::fetch(&source.url).await {
            Ok(domains) => {
                // Cache the successful fetch
                if let Err(e) =
                    loader::save_cache(&source.name, &domains, &config.blocklist.cache_dir)
                {
                    error!("Failed to cache blocklist '{}': {}", source.name, e);
                }
                domains
            }
            Err(e) => {
                error!(
                    "Failed to fetch blocklist '{}': {}, trying cache",
                    source.name, e
                );
                match loader::load_cache(&source.name, &config.blocklist.cache_dir) {
                    Ok(domains) => domains,
                    Err(e2) => {
                        error!(
                            "Failed to load cache for '{}': {}, skipping",
                            source.name, e2
                        );
                        continue;
                    }
                }
            }
        };

        let count = domains.len();
        new_matcher.load_source(domains, &source.category);
        info!(
            "Loaded {} domains from '{}' ({})",
            count, source.name, source.category
        );

        // Update blocklist metadata in DB
        if let Some(ref db) = db {
            if let Err(e) = db.update_blocklist_meta(&source.name, count).await {
                error!("Failed to update blocklist meta for '{}': {}", source.name, e);
            }
        }
    }

    info!(
        "Blocklist synced: {} domains total",
        new_matcher.total_blocked_count()
    );

    // Hot-swap the matcher
    let mut guard = matcher.write().await;
    *guard = new_matcher;
}

/// Schedule periodic blocklist syncs using tokio-cron-scheduler.
pub async fn schedule(
    config: Arc<AppConfig>,
    matcher: Arc<RwLock<BlocklistMatcher>>,
    db: Arc<DbLogger>,
) -> anyhow::Result<()> {
    use tokio_cron_scheduler::{Job, JobScheduler};

    let interval_hours = config.blocklist.sync_interval_hours;
    let cron_expr = format!("0 0 */{} * * *", interval_hours);

    let sched = JobScheduler::new().await?;

    sched
        .add(Job::new_async(cron_expr.as_str(), move |_uuid, _lock| {
            let config = config.clone();
            let matcher = matcher.clone();
            let db = db.clone();
            Box::pin(async move {
                sync_all(&config, matcher, Some(db)).await;
            })
        })?)
        .await?;

    sched.start().await?;
    info!("Blocklist sync scheduled every {} hours", interval_hours);

    Ok(())
}
