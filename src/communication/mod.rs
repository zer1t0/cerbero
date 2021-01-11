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

    pub fn ips(&self) -> Vec<&IpAddr> {
        return self.kdcs.iter().map(|(_, ip)| ip).collect();
    }

    pub fn get_clone(&self, realm: &str) -> Option<IpAddr> {
        return self.get(realm).map(|ip| ip.clone());
    }
}

pub struct KdcComm {
    kdcs: Kdcs,
    protocol: TransportProtocol,
}

impl KdcComm {
    pub fn new(kdcs: Kdcs, protocol: TransportProtocol) -> Self {
        return Self { kdcs, protocol };
    }

    pub fn create_channel(
        &mut self,
        realm: &str,
    ) -> Result<Box<dyn KrbChannel>> {
        return resolve_krb_channel(
            realm,
            &mut self.kdcs,
            self.protocol,
        );
    }
}

const KERBEROS_PORT: u16 = 88;
/// Generates a transporter given and address and transport protocol
pub fn new_krb_channel(
    dst_ip: IpAddr,
    transport_protocol: TransportProtocol,
) -> Box<dyn KrbChannel> {
    let dst_address = SocketAddr::new(dst_ip, KERBEROS_PORT);
    match transport_protocol {
        TransportProtocol::TCP => {
            return Box::new(TcpChannel::new(dst_address));
        }
        TransportProtocol::UDP => {
            return Box::new(UdpChannel::new(dst_address));
        }
    }
}

pub fn resolve_krb_channel(
    realm: &str,
    kdcs: &mut Kdcs,
    channel_protocol: TransportProtocol,
) -> Result<Box<dyn KrbChannel>> {
    let kdc_ip = resolve_kdc_ip(realm, kdcs)?;
    kdcs.insert(realm.to_string(), kdc_ip.clone());

    return Ok(new_krb_channel(kdc_ip, channel_protocol));
}

pub fn resolve_kdc_ip(realm: &str, kdcs: &Kdcs) -> Result<IpAddr> {
    Ok(match kdcs.get_clone(realm) {
        Some(ip) => ip,
        None => {
            let dns_servers = kdcs
                .ips()
                .iter()
                .map(|ip| SocketAddr::new(*ip.clone(), 53))
                .collect();
            resolve_host(realm, dns_servers)?
        }
    })
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
