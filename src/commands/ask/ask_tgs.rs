use crate::core::CredentialFormat;
use crate::core::KerberosUser;
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
    user: KerberosUser,
    service: String,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredentialFormat,
    vault: &dyn Vault,
) -> Result<()> {
    let username = user.name.clone();
    let (mut krb_cred_plain, cred_format, tgt_info) =
        get_user_tgt(user.clone(), vault, user_key, transporter, cred_format)?;

    info!("Request {} TGS for {}", service, user.name);
    let tgs_info = request_tgs(
        user,
        tgt_info,
        S4u2options::Normal(service.clone()),
        transporter,
    )?;

    krb_cred_plain.push(tgs_info);

    info!("Save {} TGS for {} in {}", username, service, vault.id());
    vault.save(krb_cred_plain, cred_format)?;

    return Ok(());
}

/// Main function to perform an S4U2Self operation
pub fn ask_s4u2self(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    vault: &dyn Vault,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredentialFormat,
) -> Result<()> {
    let imp_username = impersonate_user.name.clone();
    let username = user.name.clone();
    let (mut krb_cred_plain, cred_format, tgt_info) =
        get_user_tgt(user.clone(), vault, user_key, transporter, cred_format)?;

    info!(
        "Request {} S4U2Self TGS for {}",
        user.name, impersonate_user.name
    );
    let tgs = request_tgs(
        user,
        tgt_info,
        S4u2options::S4u2self(impersonate_user),
        transporter,
    )?;

    krb_cred_plain.push(tgs);

    info!(
        "Save {} S4U2Self TGS for {} in {}",
        imp_username,
        username,
        vault.id()
    );
    vault.save(krb_cred_plain, cred_format)?;

    return Ok(());
}

/// Main function to perform an S4U2Proxy operation
pub fn ask_s4u2proxy(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    service: String,
    vault: &dyn Vault,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredentialFormat,
) -> Result<()> {
    let imp_username = impersonate_user.name.clone();
    let (krb_cred_plain, cred_format, tgt) =
        get_user_tgt(user.clone(), vault, user_key, transporter, cred_format)?;

    let (mut krb_cred_plain, imp_ticket) = get_impersonation_ticket(
        krb_cred_plain,
        user.clone(),
        impersonate_user,
        transporter,
        tgt.clone(),
    )?;

    info!(
        "Request {} S4U2Proxy TGS for {}",
        service, imp_username
    );
    let tgs_proxy = request_tgs(
        user,
        tgt,
        S4u2options::S4u2proxy(imp_ticket.ticket, service.clone()),
        transporter,
    )?;

    krb_cred_plain.push(tgs_proxy);

    info!(
        "Save {} S4U2Proxy TGS for {} in {}",
        imp_username,
        service,
        vault.id()
    );
    vault.save(krb_cred_plain, cred_format)?;

    return Ok(());
}
