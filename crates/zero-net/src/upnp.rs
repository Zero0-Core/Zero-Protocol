use std::net::{SocketAddrV4, Ipv4Addr};
use igd::Gateway;
use tracing::{info, warn};
use crate::NetError;

/// Attempts to use UPnP (IGD) to map an external port to our local UDP port.
pub fn map_port(local_port: u16, external_port: u16) -> Result<Gateway, NetError> {
    info!("Attempting UPnP discovery...");

    // Explicit map_err avoids any ambiguity with the ? operator and From trait resolution.
    let gateway = igd::search_gateway(Default::default())
        .map_err(NetError::Upnp)?;

    info!("Found UPnP gateway: {}", gateway);

    // Discover our actual LAN IP address to provide to the UPnP gateway.
    let local_ip = match std::net::UdpSocket::bind("0.0.0.0:0").and_then(|s| {
        s.connect("8.8.8.8:80")?;
        s.local_addr()
    }) {
        Ok(addr) => match addr.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => Ipv4Addr::UNSPECIFIED,
        },
        Err(_) => Ipv4Addr::UNSPECIFIED,
    };
    
    let local_addr = SocketAddrV4::new(local_ip, local_port);

    gateway.add_port(
        igd::PortMappingProtocol::UDP,
        external_port,
        local_addr,
        3600,
        "Zero Protocol UDP",
    )
    .map_err(|e| {
        warn!("UPnP port mapping failed: {}", e);
        NetError::UpnpAddPort(e)
    })?;

    info!("Successfully mapped external port {} via UPnP.", external_port);
    Ok(gateway)
}
