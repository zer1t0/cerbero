use crate::cred_format::CredentialFormat;
use crate::error::Result;
use crate::file::save_cred_in_file;
use crate::krb_user::KerberosUser;
use crate::transporter::KerberosTransporter;
use crate::requesters::request_tgt;
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
