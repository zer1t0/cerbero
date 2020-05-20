//! Module to provide the operations required
//! in order to retrieve a ticket from the KDC

mod request_tgt;
mod senders;
pub use request_tgt::{request_as_rep, request_tgt};

mod request_tgs;
pub use request_tgs::request_tgs;

mod request_s4u2self;
pub use request_s4u2self::request_s4u2self;

mod request_s4u2proxy;
pub use request_s4u2proxy::request_s4u2proxy;

use crate::core::krb_cred_plain::{KrbCredPlain, TicketCredInfo};
use crate::core::krb_user::KerberosUser;
use crate::core::parse_creds_file;
use crate::core::CredentialFormat;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::{info, warn};
use std::convert::TryInto;

/// Function to get a TGT from the credentials file
/// or request it if it is necessary
pub fn get_user_tgt(
    user: &KerberosUser,
    creds_file: &str,
    user_key: Option<&Key>,
    transporter: &dyn KerberosTransporter,
    cred_format: CredentialFormat,
) -> Result<(KrbCredPlain, CredentialFormat, TicketCredInfo)> {
    match get_user_tgt_from_file(user, creds_file) {
        Ok(ok) => return Ok(ok),
        Err(err) => {
            warn!("No TGT found in {}: {}", creds_file, err);

            match user_key {
                Some(user_key) => {
                    info!("Request TGT for {}", user.name);
                    let krb_cred =
                        request_tgt(user, user_key, true, transporter)?;
                    let krb_cred_plain: KrbCredPlain = krb_cred.try_into()?;

                    let ticket_cred_info =
                        krb_cred_plain.look_for_tgt(user).unwrap();

                    return Ok((krb_cred_plain, cred_format, ticket_cred_info));
                }
                None => {
                    return Err(
                        "Unable to request TGT without user credentials",
                    )?;
                }
            }
        }
    }
}

/// Try to get the TGT user from the credentials file
fn get_user_tgt_from_file(
    user: &KerberosUser,
    creds_file: &str,
) -> Result<(KrbCredPlain, CredentialFormat, TicketCredInfo)> {
    let (krb_cred, cred_format) = parse_creds_file(creds_file)?;
    let krb_cred_plain: KrbCredPlain = krb_cred.try_into()?;

    let ticket_cred_info = krb_cred_plain
        .look_for_tgt(&user)
        .ok_or(format!("No TGT found for '{}", user.name))?;

    return Ok((krb_cred_plain, cred_format, ticket_cred_info));
}

/// Function to get a TGS of an impersonated user from file
/// or request it if it is necessary
pub fn get_impersonation_ticket(
    mut krb_cred_plain: KrbCredPlain,
    user: KerberosUser,
    impersonate_user: KerberosUser,
    transporter: &dyn KerberosTransporter,
    tgt: TicketCredInfo,
) -> Result<(KrbCredPlain, TicketCredInfo)> {
    let result = krb_cred_plain
        .look_for_impersonation_ticket(&user.name, &impersonate_user.name);

    match result {
        Some(ticket_info) => {
            return Ok((krb_cred_plain, ticket_info));
        }
        None => {
            warn!(
                "No {} S4U2Self TGS for {} found",
                impersonate_user.name, user.name
            );
            let tgs_self =
                request_s4u2self(user, impersonate_user, tgt, transporter)?;
            krb_cred_plain.push(tgs_self.clone());

            return Ok((krb_cred_plain, tgs_self));
        }
    }
}
