use crate::core::stringifier::{
    etype_to_string, kerberos_flags_to_string, kerberos_time_to_string,
};
use crate::core::Vault;
use crate::Result;

pub fn list(
    vault: &dyn Vault,
    only_tgts: bool,
    srealm: Option<&String>,
) -> Result<()> {
    let mut krb_creds = vault.dump()?;

    if only_tgts {
        krb_creds = krb_creds.tgt();
    }

    if let Some(srealm) = srealm {
        krb_creds = krb_creds.srealm(srealm);
    }

    let cred_format = vault
        .support_cred_format()?
        .ok_or("Unknown input file format: Maybe an empty file?")?;

    println!("Ticket cache ({}): FILE:{}", cred_format, vault.id());

    for ticket_info in krb_creds.iter() {
        println!("");
        let ticket = &ticket_info.ticket;
        let cred_info = &ticket_info.cred_info;

        let realm = &ticket.realm;
        let service = ticket.sname.name_string.join("/");
        let user_name = cred_info.pname.as_ref().unwrap().name_string.join("/");
        let user_realm = cred_info.prealm.as_ref().unwrap();

        println!("{}@{} => {}@{}", user_name, user_realm, service, realm);

        if let Some(starttime) = &cred_info.starttime {
            println!("Valid starting: {}", kerberos_time_to_string(starttime));
        }

        if let Some(endtime) = &cred_info.endtime {
            println!("Expires: {}", kerberos_time_to_string(endtime));
        }

        if let Some(renew_till) = &cred_info.renew_till {
            println!("Renew until: {}", kerberos_time_to_string(renew_till));
        }

        let flags = cred_info.flags.as_ref().unwrap().flags;
        println!("Flags: {}", kerberos_flags_to_string(flags));

        let etype_skey = cred_info.key.keytype;
        let etype_tkt = ticket.enc_part.etype;
        println!(
            "Etype (skey, tkt): {}, {}",
            etype_to_string(etype_skey),
            etype_to_string(etype_tkt)
        )
    }

    return Ok(());
}
