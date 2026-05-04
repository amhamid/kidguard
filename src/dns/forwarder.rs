use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Record, RecordType};
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::AsyncResolver;

use crate::config::DnsConfig;

/// Forwards DNS queries to upstream resolvers.
pub struct Forwarder {
    resolver: AsyncResolver<hickory_resolver::name_server::TokioConnectionProvider>,
    timeout: Duration,
}

impl Forwarder {
    /// Build a forwarder from the DNS config's upstream servers.
    pub fn new(config: &DnsConfig) -> anyhow::Result<Self> {
        let addrs = config.upstream_addrs()?;

        let mut resolver_config = ResolverConfig::new();
        for addr in &addrs {
            resolver_config.add_name_server(NameServerConfig::new(*addr, Protocol::Udp));
            resolver_config.add_name_server(NameServerConfig::new(*addr, Protocol::Tcp));
        }

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(config.timeout_ms);
        opts.attempts = 2;

        let resolver = AsyncResolver::tokio(resolver_config, opts);

        Ok(Self {
            resolver,
            timeout: Duration::from_millis(config.timeout_ms),
        })
    }

    /// Forward a DNS query and return the upstream outcome.
    /// A NODATA / NXDOMAIN response from upstream is a successful answer (just empty),
    /// not an error — the caller relays it verbatim. Only timeouts and protocol/IO
    /// failures bubble up as `ForwardError`.
    pub async fn forward(
        &self,
        name: &hickory_proto::rr::LowerName,
        record_type: RecordType,
    ) -> Result<ForwardOutcome, ForwardError> {
        let result = tokio::time::timeout(
            self.timeout,
            self.resolver.lookup(name.clone(), record_type),
        )
        .await;

        match result {
            Ok(Ok(lookup)) => Ok(ForwardOutcome::Records(lookup.records().to_vec())),
            Ok(Err(e)) => {
                if let ResolveErrorKind::NoRecordsFound { response_code, .. } = e.kind() {
                    let code = if *response_code == ResponseCode::NXDomain {
                        ResponseCode::NXDomain
                    } else {
                        ResponseCode::NoError
                    };
                    Ok(ForwardOutcome::Empty(code))
                } else {
                    Err(ForwardError::Resolve(e))
                }
            }
            Err(_) => Err(ForwardError::Timeout),
        }
    }
}

/// What upstream returned for a forwarded query.
#[derive(Debug)]
pub enum ForwardOutcome {
    /// Upstream returned answer records.
    Records(Vec<Record>),
    /// Upstream returned no answer records — either NODATA (NoError + empty) or NXDOMAIN.
    /// The contained ResponseCode tells us which to relay back to the client.
    Empty(ResponseCode),
}

/// Errors that can occur during forwarding.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("upstream DNS resolution failed: {0}")]
    Resolve(#[from] hickory_resolver::error::ResolveError),
    #[error("upstream DNS query timed out")]
    Timeout,
}
