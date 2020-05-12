use crate::transporter::KerberosTransporter;
use kerberos_asn1::{AsRep, Asn1Object, KrbError, TgsRep};
use std::io;

pub enum Rep {
    AsRep(AsRep),
    TgsRep(TgsRep),
    KrbError(KrbError),
    Raw(Vec<u8>),
}

pub fn send_recv(
    transporter: &dyn KerberosTransporter,
    raw: &[u8],
) -> io::Result<Rep> {
    let raw_rep = transporter.send_recv(raw)?;

    if let Ok((_, krb_error)) = KrbError::parse(&raw_rep) {
        return Ok(Rep::KrbError(krb_error));
    }

    if let Ok((_, as_rep)) = AsRep::parse(&raw_rep) {
        return Ok(Rep::AsRep(as_rep));
    }

    if let Ok((_, rep)) = TgsRep::parse(&raw_rep) {
        return Ok(Rep::TgsRep(rep));
    }

    return Ok(Rep::Raw(raw_rep));
}
