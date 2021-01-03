use super::Vault;
use crate::core::{TicketCred};
use crate::core::KrbUser;
use crate::core::{request_tgs, request_tgt, S4u2options};
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::{info, warn};

/// Function to get a TGT from the credentials file
/// or request it if it is necessary
pub fn get_user_tgt(
    user: KrbUser,
    vault: &mut dyn Vault,
    user_key: Option<&Key>,
    transporter: &dyn KerberosTransporter,
    etype: Option<i32>,
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
    let tgt_info = request_tgt(user.clone(), user_key, etype, transporter)?;

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
                etype,
                user.name
            ))?;
        }
    }

    return Ok(tgts.get(0).unwrap().clone());
}

/// Function to get a TGS of an impersonated user from file
/// or request it if it is necessary
pub fn get_impersonation_ticket(
    vault: &mut dyn Vault,
    user: KrbUser,
    impersonate_user: KrbUser,
    transporter: &dyn KerberosTransporter,
    tgt: TicketCred,
) -> Result<TicketCred> {
    let tickets = vault.s4u2self_tgss(&user, &impersonate_user)?;

    if !tickets.is_empty() {
        info!("Get {} S4U2Self TGS for {} from {}", user, impersonate_user, vault.id());
        return Ok(tickets.get(0).unwrap().clone());
    }

    warn!(
        "No {} S4U2Self TGS for {} found",
        user, impersonate_user,
    );

    info!(
        "Request {} S4U2Self TGS for {}",
        user, impersonate_user,
    );

    let s4u2self_tgs = request_tgs(
        user.clone(),
        tgt,
        S4u2options::S4u2self(impersonate_user.clone()),
        None,
        transporter,
    )?;

    info!(
        "Save {} S4U2Self TGS for {} in {}",
        impersonate_user.name,
        user.name,
        vault.id()
    );
    vault.add(s4u2self_tgs.clone())?;

    return Ok(s4u2self_tgs);
}
