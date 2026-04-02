use hickory_server::ServerFuture;
use tokio::net::UdpSocket;
use tracing::info;

use crate::config::AppConfig;
use crate::dns::handler::DnsHandler;

/// Start the DNS server, binding to the configured listen address.
pub async fn run(config: &AppConfig, handler: DnsHandler) -> anyhow::Result<()> {
    let addr = &config.dns.listen_addr;

    let socket = UdpSocket::bind(addr).await?;
    info!("DNS server listening on {}", addr);

    let mut server = ServerFuture::new(handler);
    server.register_socket(socket);
    server.block_until_done().await?;

    Ok(())
}
