use super::senders::send_recv_as;
use crate::core::forge::KerberosUser;
use crate::core::forge::{build_as_req, extract_krb_cred_from_as_rep};
use crate::core::Cipher;
use crate::core::TicketCredInfo;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_asn1::AsRep;
use kerberos_crypto::Key;

/// Uses user credentials to request a TGT
pub fn request_tgt(
    user: KerberosUser,
    user_key: &Key,
    etype: Option<i32>,
    transporter: &dyn KerberosTransporter,
) -> Result<TicketCredInfo> {
    let cipher = Cipher::generate(user_key, &user, etype);

    let rep = request_as_rep(user.clone(), Some(&cipher), None, transporter)?;
    return extract_krb_cred_from_as_rep(rep, &cipher);
}

/// Uses user credentials to obtain an AS-REP response
pub fn request_as_rep(
    user: KerberosUser,
    cipher: Option<&Cipher>,
    etypes: Option<Vec<i32>>,
    transporter: &dyn KerberosTransporter,
) -> Result<AsRep> {
    let as_req = build_as_req(user, cipher, etypes);
    return send_recv_as(transporter, &as_req);
}
