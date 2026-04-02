use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::{RData, Record};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::blocklist::matcher::BlocklistMatcher;
use crate::dns::forwarder::Forwarder;
use crate::logger::db::{DbLogger, QueryLog};

/// Handles incoming DNS requests: checks blocklist, forwards allowed queries, logs results.
pub struct DnsHandler {
    forwarder: Arc<Forwarder>,
    matcher: Arc<RwLock<BlocklistMatcher>>,
    db: Arc<DbLogger>,
}

impl DnsHandler {
    /// Create a new handler with a forwarder, blocklist matcher, and database logger.
    pub fn new(
        forwarder: Arc<Forwarder>,
        matcher: Arc<RwLock<BlocklistMatcher>>,
        db: Arc<DbLogger>,
    ) -> Self {
        Self {
            forwarder,
            matcher,
            db,
        }
    }
}

#[async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let start = Instant::now();
        let domain = extract_domain(request);
        let query_type = request.query().query_type();
        let client_ip = request.src().ip().to_string();

        debug!("DNS query: {} {:?} from {}", domain, query_type, client_ip);

        // Check blocklist
        let block_result = {
            let guard = self.matcher.read().await;
            guard.is_blocked(&domain)
        };

        if let Some(result) = block_result {
            info!("BLOCKED {} (rule: {}, category: {})", domain, result.rule, result.category);
            let response_info = send_nxdomain(request, &mut response_handle).await;

            // Fire-and-forget log
            let db = self.db.clone();
            let entry = QueryLog {
                timestamp: Utc::now(),
                client_ip,
                domain,
                query_type: format!("{:?}", query_type),
                blocked: true,
                blocked_rule: Some(result.rule),
                category: Some(result.category),
                resolved_ip: None,
                response_ms: start.elapsed().as_millis() as i64,
            };
            tokio::spawn(async move { db.log(entry).await });

            return response_info;
        }

        // Forward to upstream
        let (response_info, resolved_ip) = match self.forwarder.forward(request.query().name(), query_type).await {
            Ok(records) => {
                let resolved_ip = extract_first_ip(&records);
                let info = send_response(request, &mut response_handle, &records).await;
                (info, resolved_ip)
            }
            Err(e) => {
                error!("Forward error for {}: {}", domain, e);
                let info = send_servfail(request, &mut response_handle).await;
                (info, None)
            }
        };

        // Fire-and-forget log
        let db = self.db.clone();
        let entry = QueryLog {
            timestamp: Utc::now(),
            client_ip,
            domain,
            query_type: format!("{:?}", query_type),
            blocked: false,
            blocked_rule: None,
            category: None,
            resolved_ip,
            response_ms: start.elapsed().as_millis() as i64,
        };
        tokio::spawn(async move { db.log(entry).await });

        response_info
    }
}

/// Extract the domain name from a DNS request, lowercased and without trailing dot.
fn extract_domain(request: &Request) -> String {
    let name = request.query().name().to_string();
    name.trim_end_matches('.').to_lowercase()
}

/// Extract the first A record IP from the response records.
fn extract_first_ip(records: &[Record]) -> Option<String> {
    for record in records {
        if let Some(RData::A(addr)) = record.data() {
            return Some(addr.to_string());
        }
    }
    None
}

/// Send a successful DNS response with the given records.
async fn send_response<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    records: &[Record],
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut header = Header::response_from_request(request.header());
    header.set_response_code(ResponseCode::NoError);

    let response = builder.build(
        header,
        records.iter(),
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
    );

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to send response: {}", e);
            servfail_info()
        }
    }
}

/// Send an NXDOMAIN response for blocked domains.
async fn send_nxdomain<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.error_msg(request.header(), ResponseCode::NXDomain);

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to send NXDOMAIN: {}", e);
            servfail_info()
        }
    }
}

/// Send a SERVFAIL response for upstream errors.
async fn send_servfail<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.error_msg(request.header(), ResponseCode::ServFail);

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to send SERVFAIL: {}", e);
            servfail_info()
        }
    }
}

/// Fallback ResponseInfo when we can't even send a response.
fn servfail_info() -> ResponseInfo {
    let mut header = Header::new();
    header.set_response_code(ResponseCode::ServFail);
    ResponseInfo::from(header)
}
