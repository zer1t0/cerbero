use super::senders::send_recv_tgs;
use crate::core::forge::KerberosUser;
use crate::core::forge::{
    build_tgs_req, extract_ticket_from_tgs_rep, S4u2options,
};
use crate::core::krb_cred_plain::TicketCredInfo;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use log::info;

/// Use a TGT to request a TGS for user itself on behalf other user
pub fn request_s4u2self(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    tgt: TicketCredInfo,
    transporter: &dyn KerberosTransporter,
) -> Result<TicketCredInfo> {
    info!(
        "Request {} S4U2Self TGS for {}",
        user.name, impersonate_user.name
    );
    let cipher = tgt.cred_info.key.into();
    let tgs_req = build_tgs_req(
        user,
        tgt.ticket,
        &cipher,
        S4u2options::S4u2self(impersonate_user),
    );

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    return extract_ticket_from_tgs_rep(tgs_rep, &cipher);
}
