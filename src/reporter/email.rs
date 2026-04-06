use std::env;

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::{error, info};

use crate::analyzer::aggregator::ClientSummary;
use crate::config::ReporterConfig;

/// A client's summary paired with its AI analysis.
pub struct ClientReport {
    pub summary: ClientSummary,
    pub analysis: String,
}

/// Sends daily report emails.
pub struct EmailReporter {
    smtp_host: String,
    smtp_port: u16,
    from_email: String,
    to_emails: Vec<String>,
    username: String,
    password: String,
}

impl EmailReporter {
    /// Create a new email reporter from config and environment credentials.
    pub fn new(config: &ReporterConfig) -> anyhow::Result<Self> {
        let username = env::var("SMTP_USERNAME")
            .unwrap_or_else(|_| config.from_email.clone());
        let password = env::var("SMTP_PASSWORD")?;

        Ok(Self {
            smtp_host: config.smtp_host.clone(),
            smtp_port: config.smtp_port,
            from_email: config.from_email.clone(),
            to_emails: config.to_emails.clone(),
            username,
            password,
        })
    }

    /// Send a daily report email with per-client stats and AI analysis.
    pub async fn send(&self, reports: &[ClientReport]) -> anyhow::Result<()> {
        let date = reports.first().map(|r| r.summary.date.as_str()).unwrap_or("unknown");
        let subject = format!("KidGuard Report -- {}", date);
        let html_body = build_html(reports);

        let creds = Credentials::new(self.username.clone(), self.password.clone());
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.smtp_host)?
            .port(self.smtp_port)
            .credentials(creds)
            .build();

        for to in &self.to_emails {
            let email = Message::builder()
                .from(self.from_email.parse()?)
                .to(to.parse()?)
                .subject(&subject)
                .header(ContentType::TEXT_HTML)
                .body(html_body.clone())?;

            match mailer.send(email).await {
                Ok(_) => info!("Daily report email sent to {}", to),
                Err(e) => error!("Failed to send email to {}: {}", to, e),
            }
        }

        Ok(())
    }
}

/// Build the HTML email body with per-client sections.
fn build_html(reports: &[ClientReport]) -> String {
    let mut html = String::new();

    html.push_str(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333; }
h1 { color: #2563eb; font-size: 22px; }
h2 { color: #1e40af; font-size: 18px; margin-top: 32px; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }
h3 { color: #475569; font-size: 14px; margin-top: 20px; }
.stats { display: flex; gap: 20px; margin: 16px 0; }
.stat-box { background: #f0f9ff; border-radius: 8px; padding: 12px 16px; text-align: center; flex: 1; }
.stat-num { font-size: 24px; font-weight: bold; color: #2563eb; }
.stat-label { font-size: 12px; color: #64748b; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; }
th, td { text-align: left; padding: 6px 12px; border-bottom: 1px solid #e2e8f0; }
th { background: #f8fafc; font-size: 12px; color: #64748b; text-transform: uppercase; }
.hour-bar { background: #3b82f6; height: 14px; border-radius: 2px; display: inline-block; }
.analysis { background: #fefce8; border-left: 4px solid #eab308; padding: 16px; margin: 16px 0; border-radius: 4px; }
.client-section { margin-bottom: 40px; }
.footer { font-size: 12px; color: #94a3b8; margin-top: 32px; border-top: 1px solid #e2e8f0; padding-top: 16px; }
</style></head><body>"#);

    let date = reports.first().map(|r| r.summary.date.as_str()).unwrap_or("unknown");
    html.push_str(&format!(
        "<h1>KidGuard Daily Report</h1><p style='color:#64748b'>{}</p>",
        date
    ));

    for report in reports {
        html.push_str("<div class='client-section'>");
        build_client_section(&mut html, report);
        html.push_str("</div>");
    }

    html.push_str("<div class='footer'>Sent by KidGuard</div></body></html>");
    html
}

fn build_client_section(html: &mut String, report: &ClientReport) {
    let summary = &report.summary;

    // Client header
    html.push_str(&format!("<h2>{}</h2>", summary.client_name));

    // Stats boxes
    html.push_str("<div class='stats'>");
    html.push_str(&format!(
        "<div class='stat-box'><div class='stat-num'>{}</div><div class='stat-label'>Total Queries</div></div>",
        summary.total_queries
    ));
    html.push_str(&format!(
        "<div class='stat-box'><div class='stat-num'>{}</div><div class='stat-label'>Unique Domains</div></div>",
        summary.unique_domains
    ));
    html.push_str(&format!(
        "<div class='stat-box'><div class='stat-num'>{}</div><div class='stat-label'>Blocked</div></div>",
        summary.blocked_attempts
    ));
    html.push_str("</div>");

    // Top domains table
    if !summary.top_domains.is_empty() {
        html.push_str("<h3>Top Domains</h3><table><tr><th>Domain</th><th>Subdomains</th></tr>");
        for (i, d) in summary.top_domains.iter().enumerate() {
            if i >= 10 {
                break;
            }
            html.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", d.domain, d.count));
        }
        html.push_str("</table>");
    }

    // Blocked attempts table
    if !summary.top_blocked.is_empty() {
        html.push_str("<h3>Blocked Attempts</h3><table><tr><th>Domain</th><th>Attempts</th></tr>");
        for d in &summary.top_blocked {
            html.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", d.domain, d.count));
        }
        html.push_str("</table>");
    }

    // Activity by hour
    let max_hour_count = summary
        .queries_by_hour
        .iter()
        .map(|(_, c)| *c)
        .max()
        .unwrap_or(1);

    html.push_str("<h3>Activity by Hour</h3><table>");
    for (hour, count) in &summary.queries_by_hour {
        if *count == 0 {
            continue;
        }
        let bar_width = (*count as f64 / max_hour_count as f64 * 200.0) as u32;
        html.push_str(&format!(
            "<tr><td style='width:50px'>{:02}:00</td><td><span class='hour-bar' style='width:{}px'></span> {}</td></tr>",
            hour, bar_width, count
        ));
    }
    html.push_str("</table>");

    // AI Analysis
    let analysis_html = report.analysis
        .split('\n')
        .filter(|l| !l.is_empty())
        .map(|l| format!("<p>{}</p>", l))
        .collect::<Vec<_>>()
        .join("");
    html.push_str(&format!(
        "<h3>AI Analysis</h3><div class='analysis'>{}</div>",
        analysis_html
    ));
}
