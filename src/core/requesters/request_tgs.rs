use crate::core::stringifier::ticket_cred_to_string;
use super::senders::send_recv_tgs;
use crate::core::forge::KrbUser;
use crate::core::forge::{
    build_tgs_req, extract_ticket_from_tgs_rep, S4u,
};
use crate::core::Cipher;
use crate::core::TicketCred;
use crate::error::Result;
use crate::communication::{KrbChannel, KdcComm};
use kerberos_asn1::{TgsRep, Ticket, PrincipalName};
use log::debug;

/// Request a TGS for the desired service by handling the possible referral
/// tickets.
pub fn request_regular_tgs(
    user: KrbUser,
    service: PrincipalName,
    tgt: TicketCred,
    etypes: Option<Vec<i32>>,
    kdccomm: &mut KdcComm,
) -> Result<TicketCred> {
    let channel = kdccomm.create_channel(&user.realm)?;

    let mut tgs = request_tgs(
        user.clone(),
        user.realm.clone(),
        tgt,
        S4u::None(service.clone()),
        etypes.clone(),
        &*channel,
    )?;

    let max_hops = 5;
    let mut hops = 0;
    while tgs.is_tgt() && !tgs.is_for_service(&service) && hops < max_hops {
        hops += 1;
        let referral_tgt = tgs;
        let dst_realm = referral_tgt
            .service_host()
            .ok_or("Unable to get the referral TGT domain")?
            .clone();

        debug!(
            "{} referral TGT for {}\n{}",
            dst_realm,
            user,
            ticket_cred_to_string(&referral_tgt, 0)
        );

        let channel = kdccomm.create_channel(&dst_realm)?;

        tgs = request_tgs(
            user.clone(),
            dst_realm.to_string(),
            referral_tgt,
            S4u::None(service.clone()),
            etypes.clone(),
            &*channel,
        )?;
    }

    debug!(
        "{} TGS for {}\n{}",
        service.to_string(),
        user,
        ticket_cred_to_string(&tgs, 0)
    );

    return Ok(tgs);
}

/// Use a TGT to request a TGS
pub fn request_tgs(
    user: KrbUser,
    server_realm: String,
    tgt: TicketCred,
    s4u2options: S4u,
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
    s4u2options: S4u,
    etypes: Option<Vec<i32>>,
    channel: &dyn KrbChannel,
) -> Result<TgsRep> {
    let tgs_req =
        build_tgs_req(user, server_realm, tgt, &cipher, s4u2options, etypes);

    return send_recv_tgs(channel, &tgs_req);
}
