use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_asn1::{AsRep, AsReq, Asn1Object, KrbError, TgsRep, TgsReq};
use std::io;
use crate::core::stringifier::as_rep_to_string;

use log::debug;

pub enum Rep {
    AsRep(AsRep),
    TgsRep(TgsRep),
    KrbError(KrbError),
    Raw(Vec<u8>),
}

/// Send an array of bytes, which should be a kerberos request
/// coded in ASN1/DER format and retrieves the response, by parsing
/// it to a known Kerberos response
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

/// Function to send a TGS-REQ message and receive a TGS-REP
pub fn send_recv_tgs(
    transporter: &dyn KerberosTransporter,
    req: &TgsReq,
) -> Result<TgsRep> {
    let rep = send_recv(transporter, &req.build())
        .map_err(|err| ("Error sending TGS-REQ", err))?;

    match rep {
        Rep::KrbError(krb_error) => {
            return Err(krb_error)?;
        }

        Rep::Raw(_) => {
            return Err("Error parsing response")?;
        }

        Rep::AsRep(_) => {
            return Err("Unexpected: server responded with AS-REP to TGS-REQ")?;
        }

        Rep::TgsRep(tgs_rep) => {
            return Ok(tgs_rep);
        }
    }
}

/// Function to send an AS-REQ message and receive an AS-REP
pub fn send_recv_as(
    transporter: &dyn KerberosTransporter,
    req: &AsReq,
) -> Result<AsRep> {
    let rep = send_recv(transporter, &req.build())
        .map_err(|err| ("Error sending TGS-REQ", err))?;

    match rep {
        Rep::KrbError(krb_error) => {
            return Err(krb_error)?;
        }

        Rep::Raw(_) => {
            return Err("Error parsing response")?;
        }

        Rep::AsRep(as_rep) => {
            debug!("AS-REP\n{}", as_rep_to_string(&as_rep, 0));
            return Ok(as_rep);
        }

        Rep::TgsRep(_) => {
            return Err(
                "Unexpected: server responded with a TGS-REQ to an AS-REP",
            )?;
        }
    }
}
