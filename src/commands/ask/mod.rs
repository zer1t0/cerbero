mod ask_tgs;
mod ask_tgt;

use ask_tgs::{ask_s4u2proxy, ask_s4u2self, ask_tgs};
use ask_tgt::ask_tgt;

use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::error::Result;
use crate::communication::KrbChannel;
use kerberos_crypto::Key;
use std::collections::HashMap;
use std::net::IpAddr;

pub fn ask(
    user: KrbUser,
    impersonate_user: Option<KrbUser>,
    service: Option<String>,
    vault: &mut dyn Vault,
    channel: &dyn KrbChannel,
    user_key: Option<Key>,
    credential_format: CredFormat,
    kdcs: &HashMap<String, IpAddr>
) -> Result<()> {
    match service {
        Some(service) => match impersonate_user {
            Some(impersonate_user) => {
                return ask_s4u2proxy(
                    user,
                    impersonate_user,
                    service,
                    vault,
                    channel,
                    user_key.as_ref(),
                    credential_format,
                    kdcs
                );
            }
            None => {
                return ask_tgs(
                    user,
                    service,
                    channel,
                    user_key.as_ref(),
                    credential_format,
                    vault,
                    kdcs,
                );
            }
        },
        None => match impersonate_user {
            Some(impersonate_user) => {
                return ask_s4u2self(
                    user,
                    impersonate_user,
                    vault,
                    channel,
                    user_key.as_ref(),
                    credential_format,
                );
            }
            None => match user_key {
                Some(user_key) => {
                    return ask_tgt(
                        user,
                        &user_key,
                        channel,
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
