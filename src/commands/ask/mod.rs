mod ask_tgs;
mod ask_tgt;

use ask_tgs::{ask_s4u2proxy, ask_s4u2self, ask_tgs};
use ask_tgt::ask_tgt;

use crate::core::CredentialFormat;
use crate::core::KerberosUser;
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use crate::core::Vault;

pub fn ask(
    user: KerberosUser,
    impersonate_user: Option<KerberosUser>,
    service: Option<String>,
    vault: &dyn Vault,
    transporter: &dyn KerberosTransporter,
    user_key: Option<Key>,
    credential_format: CredentialFormat,
) -> Result<()> {
    match service {
        Some(service) => match impersonate_user {
            Some(impersonate_user) => {
                return ask_s4u2proxy(
                    user,
                    impersonate_user,
                    service,
                    vault,
                    transporter,
                    user_key.as_ref(),
                    credential_format,
                );
            }
            None => {
                return ask_tgs(
                    user,
                    service,
                    transporter,
                    user_key.as_ref(),
                    credential_format,
                    vault,
                );
            }
        },
        None => match impersonate_user {
            Some(impersonate_user) => {
                return ask_s4u2self(
                    user,
                    impersonate_user,
                    vault,
                    transporter,
                    user_key.as_ref(),
                    credential_format,
                );
            }
            None => match user_key {
                Some(user_key) => {
                    return ask_tgt(
                        user,
                        &user_key,
                        transporter,
                        credential_format,
                        vault,
                    );
                }
                None => {
                    return Err("Required credentials to request a TGT")?;
                }
            },
        },
    }
}
