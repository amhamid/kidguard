use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::blocklist::matcher::BlocklistMatcher;
use crate::config::FilteredClient;
use crate::dns::arp;
use crate::dns::forwarder::Forwarder;
use crate::logger::db::{DbLogger, QueryLog};

/// Client filtering logic — determines which clients should be filtered and resolves their names.
pub struct ClientFilter {
    /// IP → client name
    ip_to_name: HashMap<String, String>,
    /// MAC (lowercase) → client name
    mac_to_name: HashMap<String, String>,
    /// Whether all clients should be filtered (no filtered_clients configured)
    filter_all: bool,
}

impl ClientFilter {
    pub fn new(filtered_clients: &[FilteredClient]) -> Self {
        let mut ip_to_name = HashMap::new();
        let mut mac_to_name = HashMap::new();

        for client in filtered_clients {
            if let Some(ref ip) = client.ip {
                ip_to_name.insert(ip.trim().to_string(), client.name.clone());
            }
            if let Some(ref mac) = client.mac {
                mac_to_name.insert(mac.trim().to_lowercase(), client.name.clone());
            }
        }

        let filter_all = filtered_clients.is_empty();

        if filter_all {
            info!("No filtered_clients configured — all clients will be filtered");
        } else {
            info!(
                "Filtering {} client(s): {}",
                filtered_clients.len(),
                filtered_clients.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ")
            );
        }

        Self {
            ip_to_name,
            mac_to_name,
            filter_all,
        }
    }

    /// Resolve a client IP to a client name. Returns None if not a filtered client.
    /// MAC is checked first (more specific — tied to hardware), then IP as fallback.
    fn resolve_client_name(&self, client_ip: &str) -> Option<String> {
        // Check MAC via ARP lookup first (hardware identity)
        if !self.mac_to_name.is_empty() {
            if let Some(mac) = arp::lookup_mac(client_ip) {
                if let Some(name) = self.mac_to_name.get(&mac) {
                    return Some(name.clone());
                }
            }
        }

        // Fall back to IP mapping
        if let Some(name) = self.ip_to_name.get(client_ip) {
            return Some(name.clone());
        }

        None
    }

    /// Check if a client should be filtered and return their name if known.
    pub fn check_client(&self, client_ip: &str) -> (bool, Option<String>) {
        if self.filter_all {
            return (true, None);
        }

        match self.resolve_client_name(client_ip) {
            Some(name) => (true, Some(name)),
            None => (false, None),
        }
    }
}

/// Handles incoming DNS requests: checks blocklist, forwards allowed queries, logs results.
pub struct DnsHandler {
    forwarder: Arc<Forwarder>,
    matcher: Arc<RwLock<BlocklistMatcher>>,
    db: Arc<DbLogger>,
    client_filter: ClientFilter,
}

impl DnsHandler {
    /// Create a new handler with a forwarder, blocklist matcher, and database logger.
    pub fn new(
        forwarder: Arc<Forwarder>,
        matcher: Arc<RwLock<BlocklistMatcher>>,
        db: Arc<DbLogger>,
        filtered_clients: &[FilteredClient],
    ) -> Self {
        Self {
            forwarder,
            matcher,
            db,
            client_filter: ClientFilter::new(filtered_clients),
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

        let (should_filter, client_name) = self.client_filter.check_client(&client_ip);

        if !should_filter {
            // Unfiltered client — forward silently, no logging
            let response_info = match self.forwarder.forward(request.query().name(), query_type).await {
                Ok(records) => send_response(request, &mut response_handle, &records).await,
                Err(_) => send_servfail(request, &mut response_handle).await,
            };
            return response_info;
        }

        let display_name = client_name.as_deref().unwrap_or(&client_ip);
        info!("[{}] {} {:?}", display_name, domain, query_type);

        // Check blocklist
        let block_result = {
            let guard = self.matcher.read().await;
            guard.is_blocked(&domain)
        };

        if let Some(result) = block_result {
            info!("[{}] BLOCKED {} (rule: {}, category: {})", display_name, domain, result.rule, result.category);
            let response_info = send_blocked(request, &mut response_handle).await;

            // Fire-and-forget log
            let db = self.db.clone();
            let entry = QueryLog {
                timestamp: Utc::now(),
                client_ip,
                client_name: client_name.clone(),
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
                error!("[{}] Forward error for {}: {}", display_name, domain, e);
                let info = send_servfail(request, &mut response_handle).await;
                (info, None)
            }
        };

        // Only log filtered clients
        if should_filter {
            let db = self.db.clone();
            let entry = QueryLog {
                timestamp: Utc::now(),
                client_ip,
                client_name,
                domain,
                query_type: format!("{:?}", query_type),
                blocked: false,
                blocked_rule: None,
                category: None,
                resolved_ip,
                response_ms: start.elapsed().as_millis() as i64,
            };
            tokio::spawn(async move { db.log(entry).await });
        }

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

/// Send a sinkhole response for blocked domains.
/// Returns 0.0.0.0 (A) or :: (AAAA) instead of NXDOMAIN to prevent fallback DNS resolvers
/// from retrying the query with another upstream server.
async fn send_blocked<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let query_type = request.query().query_type();
    let name = request.query().name().into();
    let ttl = 300; // 5 minutes

    let records: Vec<Record> = match query_type {
        RecordType::A => {
            let rdata = RData::A("0.0.0.0".parse().unwrap());
            vec![Record::from_rdata(name, ttl, rdata)]
        }
        RecordType::AAAA => {
            let rdata = RData::AAAA("::".parse().unwrap());
            vec![Record::from_rdata(name, ttl, rdata)]
        }
        _ => {
            // For HTTPS/SVCB and other types, return NOERROR with empty answer
            vec![]
        }
    };

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
            error!("Failed to send blocked response: {}", e);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client(name: &str, ip: Option<&str>, mac: Option<&str>) -> FilteredClient {
        FilteredClient {
            name: name.to_string(),
            ip: ip.map(|s| s.to_string()),
            mac: mac.map(|s| s.to_string()),
        }
    }

    #[test]
    fn no_filtered_clients_filters_everyone() {
        let filter = ClientFilter::new(&[]);
        let (should_filter, name) = filter.check_client("192.168.1.50");
        assert!(should_filter);
        assert!(name.is_none());
    }

    #[test]
    fn ip_match_returns_name() {
        let clients = vec![make_client("Samir's Laptop", Some("192.168.1.100"), None)];
        let filter = ClientFilter::new(&clients);

        let (should_filter, name) = filter.check_client("192.168.1.100");
        assert!(should_filter);
        assert_eq!(name.unwrap(), "Samir's Laptop");
    }

    #[test]
    fn ip_no_match_passes_through() {
        let clients = vec![make_client("Samir's Laptop", Some("192.168.1.100"), None)];
        let filter = ClientFilter::new(&clients);

        let (should_filter, name) = filter.check_client("192.168.1.200");
        assert!(!should_filter);
        assert!(name.is_none());
    }

    #[test]
    fn multiple_clients_by_ip() {
        let clients = vec![
            make_client("Samir's Laptop", Some("192.168.1.100"), None),
            make_client("Sara's iPad", Some("192.168.1.101"), None),
        ];
        let filter = ClientFilter::new(&clients);

        let (_, name1) = filter.check_client("192.168.1.100");
        assert_eq!(name1.unwrap(), "Samir's Laptop");

        let (_, name2) = filter.check_client("192.168.1.101");
        assert_eq!(name2.unwrap(), "Sara's iPad");

        let (should_filter, _) = filter.check_client("192.168.1.200");
        assert!(!should_filter);
    }

    #[test]
    fn mac_is_normalized_to_lowercase() {
        let clients = vec![make_client("Samir's Phone", None, Some("AA:BB:CC:DD:EE:FF"))];
        let filter = ClientFilter::new(&clients);
        // MAC is stored as lowercase internally
        assert!(filter.mac_to_name.contains_key("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn ip_with_whitespace_is_trimmed() {
        let clients = vec![make_client("Samir's Laptop", Some("  192.168.1.100  "), None)];
        let filter = ClientFilter::new(&clients);

        let (should_filter, _) = filter.check_client("192.168.1.100");
        assert!(should_filter);
    }
}
