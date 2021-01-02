use crate::core::request_tgt;
use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::info;

/// Main function to ask a TGT
pub fn ask_tgt(
    user: KrbUser,
    user_key: &Key,
    transporter: &dyn KerberosTransporter,
    cred_format: CredFormat,
    vault: &dyn Vault,
) -> Result<()> {
    let username = user.name.clone();

    info!("Request TGT for {}", user.name);
    let tgt_info = request_tgt(user, user_key, None, transporter)?;

    info!("Save {} TGT in {}", username, vault.id());
    vault.append_ticket(tgt_info);

    return Ok(());
}
