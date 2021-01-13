use crate::communication::KdcComm;
use crate::core::request_tgt;
use crate::core::stringifier::ticket_cred_to_string;
use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::error::Result;
use kerberos_crypto::Key;
use log::{debug, info};

/// Main function to ask a TGT
pub fn ask_tgt(
    user: KrbUser,
    user_key: &Key,
    cred_format: CredFormat,
    vault: &mut dyn Vault,
    mut kdccomm: KdcComm,
) -> Result<()> {
    let channel = kdccomm.create_channel(&user.realm)?;

    info!("Request {} TGT for {}", user, user.realm);
    let tgt = request_tgt(user.clone(), user_key, None, &*channel)?;

    debug!(
        "{} TGT for {} info\n{}",
        user,
        user.realm,
        ticket_cred_to_string(&tgt, 0)
    );

    info!("Save {} TGT for {} in {}", user, user.realm, vault.id());
    vault.add(tgt)?;
    vault.change_format(cred_format)?;

    return Ok(());
}
