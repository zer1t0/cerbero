use crate::core::CredFormat;
use crate::error::Result;
use crate::transporter::new_transporter;
use crate::transporter::{KerberosTransporter, TransportProtocol};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use trust_dns_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::Resolver;

pub fn resolve_and_get_tranporter(
    kdc_ip: Option<IpAddr>,
    realm: &str,
    kdc_port: u16,
    transport_protocol: TransportProtocol,
) -> Result<Box<dyn KerberosTransporter>> {
    let kdc_ip = match kdc_ip {
        Some(ip) => ip,
        None => resolve_host(&realm, Vec::new())?,
    };

    let kdc_address = SocketAddr::new(kdc_ip, kdc_port);
    return Ok(new_transporter(kdc_address, transport_protocol));
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

pub fn get_ticket_file(
    args_file: Option<String>,
    username: &String,
    cred_format: &CredFormat,
) -> String {
    if let Some(file) = args_file {
        return file;
    }

    if let Some(file) = get_env_ticket_file() {
        return file;
    }

    return format!("{}.{}", username, cred_format);
}

pub fn get_env_ticket_file() -> Option<String> {
    return env::var("KRB5CCNAME").ok();
}

pub fn read_file_lines(filename: &str) -> Result<Vec<String>> {
    let fd = File::open(filename).map_err(|error| {
        format!("Unable to read the file '{}': {}", filename, error)
    })?;
    let file_lines: Vec<String> = BufReader::new(fd)
        .lines()
        .filter_map(std::result::Result::ok)
        .collect();

    return Ok(file_lines);
}
