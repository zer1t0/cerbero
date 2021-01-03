use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::core::{
    get_impersonation_ticket, get_user_tgt, request_tgs, S4u2options,
};
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::info;

/// Main function to request a new TGS for a user for the selected service
pub fn ask_tgs(
    user: KrbUser,
    service: String,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredFormat,
    vault: &mut dyn Vault,
) -> Result<()> {
    let username = user.name.clone();
    let tgt =
        get_user_tgt(user.clone(), vault, user_key, transporter, None)?;

    info!("Request {} TGS for {}", service, user.name);
    let tgs = request_tgs(
        user,
        tgt,
        S4u2options::Normal(service.clone()),
        None,
        transporter,
    )?;

    info!("Save {} TGS for {} in {}", username, service, vault.id());
    vault.add(tgs)?;
    vault.change_format(cred_format)?;

    return Ok(());
}

/// Main function to perform an S4U2Self operation
pub fn ask_s4u2self(
    user: KrbUser,
    impersonate_user: KrbUser,
    vault: &mut dyn Vault,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredFormat,
) -> Result<()> {
    let imp_username = impersonate_user.name.clone();
    let username = user.name.clone();
    let tgt_info = get_user_tgt(
        user.clone(),
        vault,
        user_key,
        transporter,
        None,
    )?;

    info!(
        "Request {} S4U2Self TGS for {}",
        impersonate_user.name, user.name
    );
    let tgs = request_tgs(
        user,
        tgt_info,
        S4u2options::S4u2self(impersonate_user),
        None,
        transporter,
    )?;

    info!(
        "Save {} S4U2Self TGS for {} in {}",
        imp_username,
        username,
        vault.id()
    );
    vault.add(tgs)?;
    vault.change_format(cred_format)?;

    return Ok(());
}

/// Main function to perform an S4U2Proxy operation
pub fn ask_s4u2proxy(
    user: KrbUser,
    impersonate_user: KrbUser,
    service: String,
    vault: &mut dyn Vault,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredFormat,
) -> Result<()> {
    let imp_username = impersonate_user.name.clone();
    let tgt = get_user_tgt(
        user.clone(),
        vault,
        user_key,
        transporter,
        None,
    )?;

    let s4u2self_tgs = get_impersonation_ticket(
        vault,
        user.clone(),
        impersonate_user,
        transporter,
        tgt.clone(),
    )?;

    info!("Request {} S4U2Proxy TGS for {}", service, imp_username);
    let tgs_proxy = request_tgs(
        user,
        tgt,
        S4u2options::S4u2proxy(s4u2self_tgs.ticket, service.clone()),
        None,
        transporter,
    )?;

    info!(
        "Save {} S4U2Proxy TGS for {} in {}",
        imp_username,
        service,
        vault.id()
    );
    vault.add(tgs_proxy)?;
    vault.change_format(cred_format)?;

    return Ok(());
}
