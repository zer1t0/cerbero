use super::Vault;
use crate::core::{TicketCreds, TicketCred};
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
    vault: &dyn Vault,
    user_key: Option<&Key>,
    transporter: &dyn KerberosTransporter,
    etype: Option<i32>,
) -> Result<TicketCred> {
    let tgt_result = get_user_tgt_from_file(&user, vault, etype);

    if let Ok(tgt_info) = tgt_result {
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
    let tgt_info = request_tgt(user, user_key, etype, transporter)?;

    info!("Save TGT for {} in {}", user.name, vault.id());
    vault.append_ticket(tgt_info);

    return Ok(tgt_info);
}

/// Try to get the TGT user from the credentials file
fn get_user_tgt_from_file(
    user: &KrbUser,
    vault: &dyn Vault,
    etype: Option<i32>,
) -> Result<TicketCred> {
    let krb_cred_plain = vault.dump()?;

    let tgts_info = krb_cred_plain.user_tgt_realm(user, &user.realm);

    if tgts_info.is_empty() {
        return Err(format!("No TGT found for '{}", user.name))?;
    }

    if let Some(etype) = etype {
        tgts_info = tgts_info.etype(etype);

        if tgts_info.is_empty() {
            return Err(format!(
                "No TGT with etype '{}' found for '{}'",
                etype,
                user.name
            ))?;
        }
    }

    return Ok(tgts_info.get(0).unwrap().clone());
}

/// Function to get a TGS of an impersonated user from file
/// or request it if it is necessary
pub fn get_impersonation_ticket(
    mut krb_cred_plain: TicketCreds,
    user: KrbUser,
    impersonate_user: KrbUser,
    transporter: &dyn KerberosTransporter,
    tgt: TicketCred,
) -> Result<(TicketCreds, TicketCred)> {
    let result = krb_cred_plain
        .look_for_impersonation_ticket(&user.name, &impersonate_user.name);

    match result {
        Some(ticket_info) => {
            return Ok((krb_cred_plain, ticket_info));
        }
        None => {
            warn!(
                "No {} S4U2Self TGS for {} found",
                impersonate_user.name, user.name,
            );

            info!(
                "Request {} S4U2Self TGS for {}",
                impersonate_user.name, user.name,
            );
            let tgs_self = request_tgs(
                user,
                tgt,
                S4u2options::S4u2self(impersonate_user),
                None,
                transporter,
            )?;
            krb_cred_plain.push(tgs_self.clone());

            return Ok((krb_cred_plain, tgs_self));
        }
    }
}
