mod ask_tgs;
mod ask_tgt;

use ask_tgs::{ask_s4u2proxy, ask_s4u2self, ask_tgs};
use ask_tgt::ask_tgt;

use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::error::Result;
use kerberos_crypto::Key;
use crate::communication::{KdcComm};

pub fn ask(
    user: KrbUser,
    user_key: Option<Key>,
    impersonate_user: Option<KrbUser>,
    service: Option<String>,
    user_service: Option<String>,
    rename_service: Option<String>,
    vault: &mut dyn Vault,
    credential_format: CredFormat,
    kdccomm: KdcComm,
) -> Result<()> {
    match service {
        Some(service) => match impersonate_user {
            Some(impersonate_user) => {
                return ask_s4u2proxy(
                    user,
                    impersonate_user,
                    service,
                    user_service,
                    rename_service,
                    vault,
                    user_key.as_ref(),
                    credential_format,
                    kdccomm
                );
            }
            None => {
                return ask_tgs(
                    user,
                    service,
                    rename_service,
                    user_key.as_ref(),
                    credential_format,
                    vault,
                    kdccomm,
                );
            }
        },
        None => match impersonate_user {
            Some(impersonate_user) => {
                return ask_s4u2self(
                    user,
                    impersonate_user,
                    user_service,
                    vault,
                    user_key.as_ref(),
                    credential_format,
                    kdccomm
                );
            }
            None => match user_key {
                Some(user_key) => {
                    return ask_tgt(
                        user,
                        &user_key,
                        credential_format,
                        vault,
                        kdccomm,
                    );
                }
                None => {
                    return Err("Required credentials to request a TGT")?;
                }
            },
        },
    }
}
