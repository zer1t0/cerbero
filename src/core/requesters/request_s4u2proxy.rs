use super::senders::send_recv_tgs;
use crate::core::forge::{
    build_s4u2proxy_req, new_krb_cred_info, decrypt_tgs_rep_enc_part,
};
use crate::core::krb_cred_plain::TicketCredInfo;
use crate::core::forge::KerberosUser;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_asn1::{Asn1Object, EncTgsRepPart, Ticket};
use log::info;

/// Use a TGT and TGS of impersonated user
/// to request a new TGS for a service on behalf the impersonated user
pub fn request_s4u2proxy(
    user: KerberosUser,
    impersonate_username: &str,
    service: &str,
    tgt_info: TicketCredInfo,
    tgs_imp: Ticket,
    transporter: &dyn KerberosTransporter,
) -> Result<TicketCredInfo> {
    info!(
        "Request {} S4U2Proxy TGS for {}",
        service, impersonate_username
    );
    let session_key = tgt_info.cred_info.key.keyvalue.clone();
    let tgs_req = build_s4u2proxy_req(user, &service, tgt_info, tgs_imp)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(&session_key, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = new_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs).into());
}
