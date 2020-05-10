use std::io;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time;

use kerberos_asn1::{AsReq, KrbError, AsRep, Asn1Object};

pub enum Rep {
    AsRep(AsRep),
    KrbError(KrbError),
    Raw(Vec<u8>),
}

pub fn send_recv_as(dst_addr: &SocketAddr, as_req: &AsReq) -> io::Result<Rep> {
    return send_recv(dst_addr, &as_req.build());
}


pub fn send_recv(dst_addr: &SocketAddr, raw: &[u8]) -> io::Result<Rep> {
    let raw_rep = send_recv_tcp(dst_addr, raw)?;

    if let Ok((_, krb_error)) = KrbError::parse(&raw_rep) {
        return Ok(Rep::KrbError(krb_error));
    }

    if let Ok((_, as_rep)) = AsRep::parse(&raw_rep) {
        return Ok(Rep::AsRep(as_rep));
    }

    return Ok(Rep::Raw(raw_rep));
}

fn send_recv_tcp(
    dst_addr: &SocketAddr,
    raw_request: &[u8],
) -> io::Result<Vec<u8>> {
    let mut tcp_stream =
        TcpStream::connect_timeout(dst_addr, time::Duration::new(5, 0))?;

    let raw_sized_request = set_size_header_to_request(raw_request);
    tcp_stream.write(&raw_sized_request)?;

    let mut len_data_bytes = [0 as u8; 4];
    tcp_stream.read_exact(&mut len_data_bytes)?;
    let data_length = u32::from_be_bytes(len_data_bytes);

    let mut raw_response: Vec<u8> = vec![0; data_length as usize];
    tcp_stream.read_exact(&mut raw_response)?;

    return Ok(raw_response);
}

fn set_size_header_to_request(raw_request: &[u8]) -> Vec<u8> {
    let request_length = raw_request.len() as u32;
    let mut raw_sized_request: Vec<u8> = request_length.to_be_bytes().to_vec();
    raw_sized_request.append(&mut raw_request.to_vec());

    return raw_sized_request;
}
