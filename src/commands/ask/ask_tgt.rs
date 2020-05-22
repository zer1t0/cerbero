use crate::core::request_tgt;
use crate::core::CredentialFormat;
use crate::core::KerberosUser;
use crate::core::KrbCredPlain;
use crate::core::Vault;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::info;

/// Main function to ask a TGT
pub fn ask_tgt(
    user: KerberosUser,
    user_key: &Key,
    transporter: &dyn KerberosTransporter,
    cred_format: CredentialFormat,
    vault: &dyn Vault,
) -> Result<()> {
    let username = user.name.clone();

    info!("Request TGT for {}", user.name);
    let tgt_info = request_tgt(user, user_key, None, transporter)?;

    let krb_cred_plain = KrbCredPlain::new(vec![tgt_info]);

    info!("Save {} TGT in {}", username, vault.id());
    vault.save(krb_cred_plain, cred_format)?;

    return Ok(());
}
