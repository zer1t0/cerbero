//! Module to provide means to transport Kerberos messages
//!

use std::net::SocketAddr;

mod transporter_trait;
pub use transporter_trait::KerberosTransporter;

mod tcp_transporter;
use tcp_transporter::TcpTransporter;

mod udp_transporter;
use udp_transporter::UdpTransporter;

/// Transport protocols available to send Kerberos messages
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TransportProtocol {
    TCP,
    UDP,
}

/// Generates a transporter given and address and transport protocol
pub fn new_transporter(
    dst_address: SocketAddr,
    transport_protocol: TransportProtocol,
) -> Box<dyn KerberosTransporter> {
    match transport_protocol {
        TransportProtocol::TCP => {
            return Box::new(TcpTransporter::new(dst_address));
        }
        TransportProtocol::UDP => {
            return Box::new(UdpTransporter::new(dst_address));
        }
    }
}
