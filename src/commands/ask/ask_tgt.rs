use crate::core::request_tgt;
use crate::core::save_cred_in_file;
use crate::core::CredentialFormat;
use crate::core::KerberosUser;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::info;

/// Main function to ask a TGT
pub fn ask_tgt(
    user: &KerberosUser,
    user_key: &Key,
    preauth: bool,
    transporter: &dyn KerberosTransporter,
    cred_format: CredentialFormat,
    creds_file: &str,
) -> Result<()> {
    let username = user.name.clone();

    info!("Request TGT for {}", user.name);
    let krb_cred = request_tgt(user, user_key, preauth, transporter)?;

    info!("Save {} TGT in {}", username, creds_file);
    save_cred_in_file(creds_file, krb_cred, cred_format)?;

    return Ok(());
}
