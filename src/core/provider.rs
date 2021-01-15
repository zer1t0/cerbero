use super::Vault;
use crate::communication::{KdcComm, KrbChannel};
use crate::core::request_s4u2self_tgs;
use crate::core::request_tgt;
use crate::core::stringifier::ticket_cred_to_string;
use crate::core::KrbUser;
use crate::core::TicketCred;
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

    if let Ok(tgt) = tgt_result {
        info!("Get {} TGT for {} from {}", user, user.realm, vault.id());
        debug!(
            "{} TGT for {} info\n{}",
            user,
            user.realm,
            ticket_cred_to_string(&tgt, 0)
        );
        return Ok(tgt);
    }
    let err = tgt_result.unwrap_err();
    warn!(
        "No {} TGT for {} found in {}: {}",
        user,
        user.realm,
        vault.id(),
        err
    );

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

    info!("Request {} TGT for {}", user, user.realm);
    let tgt = request_tgt(user.clone(), user_key, etype, channel)?;

    debug!(
        "{} TGT for {} info\n{}",
        user,
        user.realm,
        ticket_cred_to_string(&tgt, 0)
    );

    info!("Save {} TGT for {} in {}", user, user.realm, vault.id());
    vault.add(tgt.clone())?;

    return Ok(tgt);
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
    user_service: Option<String>,
    tgt: TicketCred,
    vault: &mut dyn Vault,
    kdccomm: &mut KdcComm,
) -> Result<TicketCred> {
    let target_str = user_service.clone().unwrap_or(user.to_string());
    let tickets =
        vault.s4u2self_tgss(&user, &impersonate_user, user_service.as_ref())?;

    if !tickets.is_empty() {
        info!(
            "Get {} S4U2Self TGS for {} from {}",
            impersonate_user,
            target_str,
            vault.id()
        );
        let s4u2self_tgs = tickets.get(0).unwrap();

        debug!(
            "{} S4U2Self TGS for {}\n{}",
            impersonate_user,
            target_str,
            ticket_cred_to_string(&s4u2self_tgs, 0)
        );

        return Ok(s4u2self_tgs.clone());
    }

    warn!(
        "No {} S4U2Self TGS for {} found",
        impersonate_user, target_str
    );

    info!(
        "Request {} S4U2Self TGS for {}",
        impersonate_user, target_str
    );

    let s4u2self_tgs = request_s4u2self_tgs(
        user,
        impersonate_user.clone(),
        user_service,
        tgt,
        kdccomm,
    )?;

    info!(
        "Save {} S4U2Self TGS for {} in {}",
        impersonate_user,
        target_str,
        vault.id()
    );
    vault.add(s4u2self_tgs.clone())?;

    return Ok(s4u2self_tgs);
}
