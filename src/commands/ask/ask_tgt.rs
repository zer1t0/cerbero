use crate::core::request_tgt;
use crate::core::stringifier::ticket_cred_to_string;
use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::error::Result;
use crate::transporter::KrbChannel;
use kerberos_crypto::Key;
use log::{debug, info};

/// Main function to ask a TGT
pub fn ask_tgt(
    user: KrbUser,
    user_key: &Key,
    channel: &dyn KrbChannel,
    cred_format: CredFormat,
    vault: &mut dyn Vault,
) -> Result<()> {
    info!("Request TGT for {}", user);
    let tgt = request_tgt(user.clone(), user_key, None, channel)?;

    debug!("TGT for {} info\n{}", user, ticket_cred_to_string(&tgt, 0));

    info!("Save {} TGT in {}", user, vault.id());
    vault.add(tgt)?;
    vault.change_format(cred_format)?;

    return Ok(());
}
