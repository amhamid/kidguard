use std::net::SocketAddr;

use hickory_server::ServerFuture;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::info;

use crate::config::AppConfig;
use crate::dns::handler::DnsHandler;

/// Start the DNS server, binding to the configured listen addresses.
pub async fn run(config: &AppConfig, handler: DnsHandler) -> anyhow::Result<()> {
    let mut server = ServerFuture::new(handler);

    for addr in &config.dns.listen_addr {
        let sock_addr: SocketAddr = addr.parse()?;
        let socket = bind_udp(sock_addr)?;
        info!("DNS server listening on {}", addr);
        server.register_socket(socket);
    }

    server.block_until_done().await?;

    Ok(())
}

/// Bind a UDP socket. For IPv6, sets IPV6_V6ONLY so it doesn't conflict with the IPv4 socket.
fn bind_udp(addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    Ok(UdpSocket::from_std(socket.into())?)
}
