mod ask_tgs;
mod ask_tgt;

pub use ask_tgs::{
    ask_s4u2proxy, ask_s4u2self, ask_tgs,
};
pub use ask_tgt::{ask_tgt};

use crate::krb_user::KerberosUser;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use crate::cred_format::CredentialFormat;

pub fn ask(
    user: KerberosUser,
    impersonate_user: Option<KerberosUser>,
    service: Option<String>,
    creds_file: &str,
    transporter: &dyn KerberosTransporter,
    user_key: Option<Key>,
    credential_format: CredentialFormat,
    preauth: bool,
) -> Result<()> {
    match service {
        Some(service) => match impersonate_user {
            Some(impersonate_user) => {
                return ask_s4u2proxy(
                    user,
                    impersonate_user,
                    service,
                    creds_file,
                    transporter,
                    user_key.as_ref(),
                    credential_format,
                );
            }
            None => {
                return ask_tgs(
                    user,
                    service,
                    creds_file,
                    transporter,
                    user_key.as_ref(),
                    credential_format,
                );
            }
        },
        None => match impersonate_user {
            Some(impersonate_user) => {
                return ask_s4u2self(
                    user,
                    impersonate_user,
                    creds_file,
                    transporter,
                    user_key.as_ref(),
                    credential_format,
                );
            }
            None => match user_key {
                Some(user_key) => {
                    return ask_tgt(
                        &user,
                        &user_key,
                        preauth,
                        transporter,
                        credential_format,
                        creds_file,
                    );
                }
                None => {
                    return Err("Required credentials to request a TGT")?;
                }
            },
        },
    }
}
