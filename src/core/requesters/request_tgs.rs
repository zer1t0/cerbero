use super::senders::send_recv_tgs;
use crate::communication::{KdcComm, KrbChannel};
use crate::core::forge;
use crate::core::forge::KrbUser;
use crate::core::forge::{build_tgs_req, extract_ticket_from_tgs_rep, S4u};
use crate::core::stringifier::ticket_cred_to_string;
use crate::core::Cipher;
use crate::core::TicketCred;
use crate::error::Result;
use kerberos_asn1::{PrincipalName, TgsRep, Ticket};
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

    let mut dst_realm = user.realm.clone();
    let mut tgs = request_tgs(
        user.clone(),
        dst_realm.clone(),
        tgt,
        S4u::None(service.clone()),
        etypes.clone(),
        &*channel,
    )?;

    let max_hops = 5;
    let mut hops = 0;
    while tgs.is_tgt() && !tgs.is_tgt_for_realm(&dst_realm) && hops < max_hops {
        hops += 1;
        let referral_tgt = tgs;
        dst_realm = referral_tgt
            .service_host()
            .ok_or("Unable to get the referral TGT domain")?
            .clone();

        debug!(
            "{} referral TGT for {}\n{}",
            user,
            dst_realm,
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
        user,
        service.to_string(),
        ticket_cred_to_string(&tgs, 0)
    );

    return Ok(tgs);
}

/// Request a S4U2Self ticket by handling the possible referrals across domains.
pub fn request_s4u2self_tgs(
    user: KrbUser,
    impersonate_user: KrbUser,
    user_service: Option<String>,
    mut tgt: TicketCred,
    kdccomm: &mut KdcComm,
) -> Result<TicketCred> {
    let mut dst_realm = tgt
        .service_host()
        .ok_or("Unable to get the TGT domain")?
        .clone();

    let mut channel = kdccomm.create_channel(&user.realm)?;

    let imp_user_krbtgt =
        forge::new_nt_srv_inst(&format!("krbtgt/{}", impersonate_user.realm));
    while !tgt.is_for_service(&imp_user_krbtgt) {
        tgt = request_tgs(
            user.clone(),
            dst_realm.to_string(),
            tgt,
            S4u::None(imp_user_krbtgt.clone()),
            None,
            &*channel,
        )?;

        dst_realm = tgt
            .service_host()
            .ok_or("Unable to get the TGT domain")?
            .clone();

        debug!(
            "{} referral TGT for {}\n{}",
            user,
            dst_realm,
            ticket_cred_to_string(&tgt, 0)
        );

        channel = kdccomm.create_channel(&dst_realm)?;
    }

    let mut s4u2self_tgs = request_tgs(
        user.clone(),
        dst_realm,
        tgt,
        S4u::S4u2self(impersonate_user.clone(), user_service.clone()),
        None,
        &*channel,
    )?;

    while s4u2self_tgs.is_tgt() {
        dst_realm = s4u2self_tgs
            .service_host()
            .ok_or("Unable to get the TGT domain")?
            .clone();

        debug!(
            "{} referral TGT for {}\n{}",
            user,
            dst_realm,
            ticket_cred_to_string(&s4u2self_tgs, 0)
        );

        channel = kdccomm.create_channel(&dst_realm)?;

        s4u2self_tgs = request_tgs(
            user.clone(),
            dst_realm,
            s4u2self_tgs,
            S4u::S4u2self(impersonate_user.clone(), user_service.clone()),
            None,
            &*channel,
        )?;
    }

    debug!(
        "{} S4U2Self TGS for {}\n{}",
        impersonate_user,
        user,
        ticket_cred_to_string(&s4u2self_tgs, 0)
    );

    return Ok(s4u2self_tgs);
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
