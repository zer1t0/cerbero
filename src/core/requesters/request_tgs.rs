use super::senders::send_recv_tgs;
use crate::core::forge::KerberosUser;
use crate::core::forge::{build_tgs_req, extract_ticket_from_tgs_rep};
use crate::core::krb_cred_plain::TicketCredInfo;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use log::info;

/// Use a TGT to request a TGS
pub fn request_tgs(
    user: KerberosUser,
    service: &str,
    ticket_info: TicketCredInfo,
    transporter: &dyn KerberosTransporter,
) -> Result<TicketCredInfo> {
    info!("Request {} TGS for {}", service, user.name);
    let cipher = ticket_info.cred_info.key.clone().into();
    let tgs_req = build_tgs_req(user, service, ticket_info)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    return extract_ticket_from_tgs_rep(tgs_rep, &cipher);
}
