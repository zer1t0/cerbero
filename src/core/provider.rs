use super::Vault;
use crate::communication::{KdcComm, KrbChannel};
use crate::core::forge;
use crate::core::stringifier::ticket_cred_to_string;
use crate::core::KrbUser;
use crate::core::TicketCred;
use crate::core::{request_tgs, request_tgt, S4u};
use crate::error::Result;
use kerberos_crypto::Key;
use log::{debug, info, warn};

/// Function to get a TGT from the credentials file
/// or request it if it is necessary
pub fn get_user_tgt(
    user: KrbUser,
    user_key: Option<&Key>,
    etype: Option<i32>,
    vault: &mut dyn Vault,
    channel: &dyn KrbChannel,
) -> Result<TicketCred> {
    let tgt_result = get_user_tgt_from_file(&user, vault, etype);

    if let Ok(tgt_info) = tgt_result {
        info!("Get TGT for {} from {}", user, vault.id());
        return Ok(tgt_info);
    }
    let err = tgt_result.unwrap_err();
    warn!("No TGT found in {}: {}", vault.id(), err);

    let user_key =
        user_key.ok_or("Unable to request TGT without user credentials")?;

    if let Some(etype) = etype {
        if !user_key.etypes().contains(&etype) {
            return Err(format!(
                "Incompatible etype {} with provided key",
                etype
            ))?;
        }
    }

    info!("Request TGT for {}", user.name);
    let tgt_info = request_tgt(user.clone(), user_key, etype, channel)?;

    info!("Save TGT for {} in {}", user.name, vault.id());
    vault.add(tgt_info.clone())?;

    return Ok(tgt_info);
}

/// Try to get the TGT user from the credentials file
fn get_user_tgt_from_file(
    user: &KrbUser,
    vault: &dyn Vault,
    etype: Option<i32>,
) -> Result<TicketCred> {
    let mut tgts = vault.get_user_tgts(user)?;

    if tgts.is_empty() {
        return Err(format!("No TGT found for '{}", user.name))?;
    }

    if let Some(etype) = etype {
        tgts = tgts.etype(etype);

        if tgts.is_empty() {
            return Err(format!(
                "No TGT with etype '{}' found for '{}'",
                etype, user.name
            ))?;
        }
    }

    return Ok(tgts.get(0).unwrap().clone());
}

/// Function to get a TGS of an impersonated user from file
/// or request it if it is necessary
pub fn get_impersonation_ticket(
    user: KrbUser,
    impersonate_user: KrbUser,
    tgt: TicketCred,
    vault: &mut dyn Vault,
    kdccomm: &mut KdcComm,
) -> Result<TicketCred> {
    let tickets = vault.s4u2self_tgss(&user, &impersonate_user)?;

    if !tickets.is_empty() {
        info!(
            "Get {} S4U2Self TGS for {} from {}",
            user,
            impersonate_user,
            vault.id()
        );
        let s4u2self_tgs = tickets.get(0).unwrap();

        debug!(
            "{} S4U2Self TGS for {}\n{}",
            user,
            impersonate_user,
            ticket_cred_to_string(&s4u2self_tgs, 0)
        );

        return Ok(s4u2self_tgs.clone());
    }

    warn!("No {} S4U2Self TGS for {} found", user, impersonate_user,);

    info!("Request {} S4U2Self TGS for {}", user, impersonate_user,);

    let s4u2self_tgs =
        request_s4u2self_tgs(user, impersonate_user, tgt, vault, kdccomm)?;

    return Ok(s4u2self_tgs);
}

pub fn request_s4u2self_tgs(
    user: KrbUser,
    impersonate_user: KrbUser,
    mut tgt: TicketCred,
    vault: &mut dyn Vault,
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

        info!("Received inter-realm TGT for domain {}", dst_realm);
        let dst_realm = tgt
            .service_host()
            .ok_or("Unable to get the TGT domain")?
            .clone();
        debug!(
            "{} inter-realm TGT for {}\n{}",
            dst_realm,
            user,
            ticket_cred_to_string(&tgt, 0)
        );

        info!(
            "Save {} inter-realm TGT for {} in {}",
            dst_realm,
            user,
            vault.id()
        );
        vault.add(tgt.clone())?;

        channel = kdccomm.create_channel(&dst_realm)?;
    }

    info!("Request {} S4U2Self TGS for {}", user, impersonate_user);

    let mut s4u2self_tgs = request_tgs(
        user.clone(),
        dst_realm,
        tgt,
        S4u::S4u2self(impersonate_user.clone()),
        None,
        &*channel,
    )?;

    while s4u2self_tgs.is_tgt() {
        dst_realm = s4u2self_tgs
            .service_host()
            .ok_or("Unable to get the TGT domain")?
            .clone();

        info!("Received inter-realm TGT for domain {}", dst_realm);

        debug!(
            "{} inter-realm TGT for {}\n{}",
            dst_realm,
            user,
            ticket_cred_to_string(&s4u2self_tgs, 0)
        );

        info!(
            "Save {} inter-realm TGT for {} in {}",
            dst_realm,
            user,
            vault.id()
        );
        vault.add(s4u2self_tgs.clone())?;

        channel = kdccomm.create_channel(&dst_realm)?;

        s4u2self_tgs = request_tgs(
            user.clone(),
            dst_realm,
            s4u2self_tgs,
            S4u::S4u2self(impersonate_user.clone()),
            None,
            &*channel,
        )?;
    }

    debug!(
        "{} S4U2Self TGS for {}\n{}",
        user,
        impersonate_user,
        ticket_cred_to_string(&s4u2self_tgs, 0)
    );

    info!(
        "Save {} S4U2Self TGS for {} in {}",
        user,
        impersonate_user,
        vault.id()
    );
    vault.add(s4u2self_tgs.clone())?;

    return Ok(s4u2self_tgs);
}
