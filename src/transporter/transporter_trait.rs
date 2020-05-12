use std::io;

/// Trait implemented by classes which deliver Kerberos messages
pub trait KerberosTransporter {
    /// Sends a message and retrieves the response
    fn send_recv(&self, raw: &[u8]) -> io::Result<Vec<u8>>;
}
