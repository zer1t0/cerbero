//! Module to provide means to transport Kerberos messages
//!

mod channel_trait;
pub use channel_trait::KrbChannel;

mod tcp_channel;
use tcp_channel::TcpChannel;

mod udp_channel;
use udp_channel::UdpChannel;

use crate::Result;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use trust_dns_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::Resolver;

/// Transport protocols available to send Kerberos messages
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TransportProtocol {
    TCP,
    UDP,
}

#[derive(Debug)]
pub struct Kdcs {
    kdcs: HashMap<String, IpAddr>,
}

impl Kdcs {
    pub fn new() -> Self {
        return Self {
            kdcs: HashMap::new(),
        };
    }

    pub fn insert(&mut self, realm: String, ip: IpAddr) {
        self.kdcs.insert(realm.to_lowercase(), ip);
    }

    pub fn get(&self, realm: &str) -> Option<&IpAddr> {
        return self.kdcs.get(&realm.to_lowercase());
    }

    pub fn get_clone(&self, realm: &str) -> Option<IpAddr> {
        return self.get(realm).map(|ip| ip.clone());
    }
}

/// Generates a transporter given and address and transport protocol
pub fn new_krb_channel(
    dst_address: SocketAddr,
    transport_protocol: TransportProtocol,
) -> Box<dyn KrbChannel> {
    match transport_protocol {
        TransportProtocol::TCP => {
            return Box::new(TcpChannel::new(dst_address));
        }
        TransportProtocol::UDP => {
            return Box::new(UdpChannel::new(dst_address));
        }
    }
}

const KERBEROS_PORT: u16 = 88;

pub fn resolve_and_get_krb_channel(
    realm: &str,
    kdc_ip: Option<IpAddr>,
    dns_servers: Vec<SocketAddr>,
    channel_protocol: TransportProtocol,
) -> Result<Box<dyn KrbChannel>> {
    let kdc_ip = match kdc_ip {
        Some(ip) => ip,
        None => resolve_host(&realm, dns_servers)?,
    };

    let kdc_address = SocketAddr::new(kdc_ip, KERBEROS_PORT);
    return Ok(new_krb_channel(kdc_address, channel_protocol));
}

pub fn resolve_host(
    realm: &str,
    dns_servers: Vec<SocketAddr>,
) -> Result<IpAddr> {
    let resolver;
    if dns_servers.is_empty() {
        resolver = Resolver::from_system_conf().map_err(|err| {
            format!("Unable to use dns system configuration: {}", err)
        })?;
    } else {
        let mut resolver_config = ResolverConfig::new();
        for server in dns_servers {
            resolver_config.add_name_server(NameServerConfig {
                socket_addr: server,
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                trust_nx_responses: false,
            });
        }
        resolver =
            Resolver::new(resolver_config, ResolverOpts::default()).unwrap();
    }
    let ips = resolver
        .lookup_ip(realm)
        .map_err(|err| format!("Error resolving '{}' : '{}'", realm, err))?;

    let ip = ips
        .iter()
        .next()
        .ok_or(format!("Error resolving '{}': No entries found", realm))?;

    return Ok(ip);
}
