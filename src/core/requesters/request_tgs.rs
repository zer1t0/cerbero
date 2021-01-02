use super::senders::send_recv_tgs;
use crate::core::forge::KrbUser;
use crate::core::forge::{
    build_tgs_req, extract_ticket_from_tgs_rep, S4u2options,
};
use crate::core::TicketCred;
use crate::core::Cipher;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_asn1::{TgsRep, Ticket};

/// Use a TGT to request a TGS
pub fn request_tgs(
    user: KrbUser,
    tgt: TicketCred,
    s4u2options: S4u2options,
    etypes: Option<Vec<i32>>,
    transporter: &dyn KerberosTransporter,
) -> Result<TicketCred> {
    let cipher = tgt.cred_info.key.into();
    let tgs_rep = request_tgs_rep(
        user,
        tgt.ticket,
        &cipher,
        s4u2options,
        etypes,
        transporter,
    )?;

    return extract_ticket_from_tgs_rep(tgs_rep, &cipher);
}

pub fn request_tgs_rep(
    user: KrbUser,
    tgt: Ticket,
    cipher: &Cipher,
    s4u2options: S4u2options,
    etypes: Option<Vec<i32>>,
    transporter: &dyn KerberosTransporter,
) -> Result<TgsRep> {
    let tgs_req = build_tgs_req(user, tgt, &cipher, s4u2options, etypes);

    return send_recv_tgs(transporter, &tgs_req);
}
