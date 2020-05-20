use super::senders::send_recv_as;
use crate::core::krb_user::KerberosUser;
use crate::core::forge::{extract_krb_cred_from_as_rep, build_as_req};
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_asn1::{KrbCred, AsRep};
use kerberos_crypto::Key;

/// Uses user credentials to request a TGT
pub fn request_tgt(
    user: &KerberosUser,
    user_key: &Key,
    preauth: bool,
    transporter: &dyn KerberosTransporter,
) -> Result<KrbCred> {
    let rep = request_as_rep(user, user_key, preauth, transporter)?;
    return extract_krb_cred_from_as_rep(rep, user, user_key);
}

/// Uses user credentials to obtain an AS-REP response
pub fn request_as_rep(
    user: &KerberosUser,
    user_key: &Key,
    preauth: bool,
    transporter: &dyn KerberosTransporter,
) -> Result<AsRep> {
    let as_req = build_as_req(user, user_key, preauth);
    return send_recv_as(transporter, &as_req);
}
