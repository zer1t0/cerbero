use crate::core::{craft_ticket_info, CredentialFormat, KrbCredPlain, Vault};
use crate::KerberosUser;
use crate::Result;
use kerberos_crypto::Key;
use ms_pac::PISID;
use log::info;

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
    let username = user.name.clone();
    
    let ticket_info = craft_ticket_info(
        user, service.clone(), user_key, user_rid, realm_sid, groups, etype,
    );

    let krb_cred_plain = KrbCredPlain::new(vec![ticket_info]);

    if let Some(service) = service {
        info!("Save {} TGS for {} in {}", username, service, vault.id());
    } else {
        info!("Save {} TGT in {}", username, vault.id());        
    }
    vault.save(krb_cred_plain, cred_format)?;

    return Ok(());
}
