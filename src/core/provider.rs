use super::Vault;
use crate::core::krb_cred_plain::{KrbCredPlain, TicketCredInfo};
use crate::core::CredentialFormat;
use crate::core::KerberosUser;
use crate::core::{request_tgs, request_tgt, S4u2options};
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::{info, warn};

/// Function to get a TGT from the credentials file
/// or request it if it is necessary
pub fn get_user_tgt(
    user: KerberosUser,
    vault: &dyn Vault,
    user_key: Option<&Key>,
    transporter: &dyn KerberosTransporter,
    cred_format: CredentialFormat,
) -> Result<(KrbCredPlain, CredentialFormat, TicketCredInfo)> {
    let tgt_result = get_user_tgt_from_file(&user, vault, None);
    if let Ok(creds) = tgt_result {
        return Ok(creds);
    }
    let err = tgt_result.unwrap_err();
    warn!("No TGT found in {}: {}", vault.id(), err);

    let user_key =
        user_key.ok_or("Unable to request TGT without user credentials")?;

    info!("Request TGT for {}", user.name);
    let tgt_info = request_tgt(user, user_key, transporter)?;
    let krb_cred_plain = KrbCredPlain::new(vec![tgt_info.clone()]);
    return Ok((krb_cred_plain, cred_format, tgt_info));
}

/// Try to get the TGT user from the credentials file
fn get_user_tgt_from_file(
    user: &KerberosUser,
    vault: &dyn Vault,
    etype: Option<i32>,
) -> Result<(KrbCredPlain, CredentialFormat, TicketCredInfo)> {
    let (krb_cred_plain, cred_format) = vault.load()?;

    let ticket_cred_info = krb_cred_plain
        .look_for_tgt(&user)
        .ok_or(format!("No TGT found for '{}", user.name))?;

    if let Some(etype) = etype {
        if ticket_cred_info.cred_info.key.keytype != etype {
            return Err(format!(
                "TGT of '{}' with incompatible etype",
                user.name
            ))?;
        }
    }

    return Ok((krb_cred_plain, cred_format, ticket_cred_info));
}

/// Function to get a TGS of an impersonated user from file
/// or request it if it is necessary
pub fn get_impersonation_ticket(
    mut krb_cred_plain: KrbCredPlain,
    user: KerberosUser,
    impersonate_user: KerberosUser,
    transporter: &dyn KerberosTransporter,
    tgt: TicketCredInfo,
) -> Result<(KrbCredPlain, TicketCredInfo)> {
    let result = krb_cred_plain
        .look_for_impersonation_ticket(&user.name, &impersonate_user.name);

    match result {
        Some(ticket_info) => {
            return Ok((krb_cred_plain, ticket_info));
        }
        None => {
            warn!(
                "No {} S4U2Self TGS for {} found",
                impersonate_user.name, user.name
            );
            let tgs_self = request_tgs(
                user,
                tgt,
                S4u2options::S4u2self(impersonate_user),
                transporter,
            )?;
            krb_cred_plain.push(tgs_self.clone());

            return Ok((krb_cred_plain, tgs_self));
        }
    }
}
