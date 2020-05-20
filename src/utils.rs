use crate::core::CredentialFormat;
use crate::error::Result;
use crate::transporter::new_transporter;
use crate::transporter::{KerberosTransporter, TransportProtocol};
use dns_lookup;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};

pub fn resolve_and_get_tranporter(
    kdc_ip: Option<IpAddr>,
    realm: &str,
    kdc_port: u16,
    transport_protocol: TransportProtocol,
) -> Result<Box<dyn KerberosTransporter>> {
    let kdc_ip = match kdc_ip {
        Some(ip) => ip,
        None => resolve_host(&realm)?,
    };

    let kdc_address = SocketAddr::new(kdc_ip, kdc_port);
    return Ok(new_transporter(kdc_address, transport_protocol));
}

pub fn resolve_host(realm: &str) -> Result<IpAddr> {
    let ips = dns_lookup::lookup_host(realm)
        .map_err(|err| format!("Error resolving '{}' : '{}'", realm, err))?;

    if ips.len() == 0 {
        return Err(format!("Error resolving '{}': No entries found", realm))?;
    }

    return Ok(ips[0]);
}

pub fn get_ticket_file(
    args_file: Option<String>,
    username: &String,
    cred_format: &CredentialFormat,
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
