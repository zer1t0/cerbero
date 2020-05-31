use crate::core::{craft_ticket_info, CredentialFormat, KrbCredPlain, Vault};
use crate::KerberosUser;
use crate::Result;
use kerberos_crypto::Key;
use ms_pac::PISID;

pub fn craft(
    user: KerberosUser,
    service: Option<String>,
    user_key: Key,
    user_rid: u32,
    realm_sid: PISID,
    groups: &[u32],
    etype: Option<i32>,
    cred_format: CredentialFormat,
    vault: &dyn Vault,
) -> Result<()> {
    let ticket_info = craft_ticket_info(
        user, service, user_key, user_rid, realm_sid, groups, etype,
    );

    let krb_cred_plain = KrbCredPlain::new(vec![ticket_info]);

    vault.save(krb_cred_plain, cred_format)?;

    return Ok(());
}
