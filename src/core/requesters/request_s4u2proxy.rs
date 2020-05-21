use super::senders::send_recv_tgs;
use crate::core::forge::KerberosUser;
use crate::core::forge::{
    build_tgs_req, extract_ticket_from_tgs_rep, S4u2options,
};
use crate::core::krb_cred_plain::TicketCredInfo;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_asn1::Ticket;
use log::info;

/// Use a TGT and TGS of impersonated user
/// to request a new TGS for a service on behalf the impersonated user
pub fn request_s4u2proxy(
    user: KerberosUser,
    impersonate_username: &str,
    service: String,
    tgt_info: TicketCredInfo,
    tgs_imp: Ticket,
    transporter: &dyn KerberosTransporter,
) -> Result<TicketCredInfo> {
    info!(
        "Request {} S4U2Proxy TGS for {}",
        service, impersonate_username
    );
    let cipher = tgt_info.cred_info.key.into();
    let tgs_req = build_tgs_req(
        user,
        tgt_info.ticket,
        &cipher,
        S4u2options::S4u2proxy(tgs_imp, service),
    );

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    return extract_ticket_from_tgs_rep(tgs_rep, &cipher);
}
