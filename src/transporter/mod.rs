//! Module to provide means to transport Kerberos messages
//!

use std::net::SocketAddr;

mod channel_trait;
pub use channel_trait::KrbChannel;

mod tcp_channel;
use tcp_channel::TcpChannel;

mod udp_channel;
use udp_channel::UdpChannel;

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
