use super::senders::send_recv_tgs;
use crate::core::forge::KrbUser;
use crate::core::forge::{
    build_tgs_req, extract_ticket_from_tgs_rep, S4u2options,
};
use crate::core::Cipher;
use crate::core::TicketCred;
use crate::error::Result;
use crate::communication::KrbChannel;
use kerberos_asn1::{TgsRep, Ticket};

/// Use a TGT to request a TGS
pub fn request_tgs(
    user: KrbUser,
    server_realm: String,
    tgt: TicketCred,
    s4u2options: S4u2options,
    etypes: Option<Vec<i32>>,
    channel: &dyn KrbChannel,
) -> Result<TicketCred> {
    let cipher = tgt.cred_info.key.into();
    let tgs_rep = request_tgs_rep(
        user,
        server_realm,
        tgt.ticket,
        &cipher,
        s4u2options,
        etypes,
        channel,
    )?;

    return extract_ticket_from_tgs_rep(tgs_rep, &cipher);
}

pub fn request_tgs_rep(
    user: KrbUser,
    server_realm: String,
    tgt: Ticket,
    cipher: &Cipher,
    s4u2options: S4u2options,
    etypes: Option<Vec<i32>>,
    channel: &dyn KrbChannel,
) -> Result<TgsRep> {
    let tgs_req =
        build_tgs_req(user, server_realm, tgt, &cipher, s4u2options, etypes);

    return send_recv_tgs(channel, &tgs_req);
}
