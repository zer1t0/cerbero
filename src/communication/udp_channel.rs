use crate::communication::{KrbChannel, TransportProtocol};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

/// Send Kerberos messages over UDP
#[derive(Debug)]
pub struct UdpChannel {
    dst_addr: SocketAddr,
}

impl UdpChannel {
    pub fn new(dst_addr: SocketAddr) -> Self {
        return Self { dst_addr };
    }
}

impl KrbChannel for UdpChannel {
    fn send_recv(&self, raw: &[u8]) -> io::Result<Vec<u8>> {
        return send_recv_udp(&self.dst_addr, raw);
    }

    fn protocol(&self) -> TransportProtocol {
        return TransportProtocol::UDP;
    }

    fn ip(&self) -> IpAddr {
        return self.dst_addr.ip();
    }
}

pub fn send_recv_udp(
    dst_addr: &SocketAddr,
    raw_request: &[u8],
) -> io::Result<Vec<u8>> {
    let udp_socket = UdpSocket::bind("0.0.0.0:0")?;
    udp_socket.connect(dst_addr)?;

    udp_socket.send(raw_request)?;

    let data_length = calculate_response_size(&udp_socket)?;

    let mut raw_response = vec![0; data_length as usize];
    udp_socket.recv(&mut raw_response)?;

    return Ok(raw_response);
}

fn calculate_response_size(udp_socket: &UdpSocket) -> io::Result<usize> {
    let mut raw_response = vec![0; 2048];
    let mut data_length = udp_socket.peek(&mut raw_response)?;
    while data_length == raw_response.len() {
        raw_response.append(&mut raw_response.clone());
        data_length = udp_socket.peek(&mut raw_response)?;
    }
    return Ok(data_length);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::*;

    #[should_panic(expected = "NetworkError")]
    #[test]
    fn test_request_networks_error() {
        let requester = UdpTransporter::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            88,
        ));
        requester.send_recv(&vec![]).unwrap();
    }
}
