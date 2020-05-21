use crate::core::Vault;
use crate::Result;
use chrono::Local;
use kerberos_asn1::KerberosTime;
use kerberos_constants::etypes;
use kerberos_constants::ticket_flags;

pub fn list(
    vault: &dyn Vault,
    show_etypes: bool,
    show_flags: bool,
) -> Result<()> {
    let (krb_creds, cred_format) = vault.load()?;
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

        let starttime = get_formatted_time(cred_info.starttime.as_ref());
        println!("Valid starting: {}", starttime);
        let endtime = get_formatted_time(cred_info.endtime.as_ref());
        println!("Expires : {}", endtime);
        let renew_till = get_formatted_time(cred_info.renew_till.as_ref());
        println!("Renew until: {}", renew_till);

        if show_flags {
            let flags = cred_info.flags.as_ref().unwrap().flags;
            println!("Flags: {}", kerberos_flags_to_string(flags));
        }

        if show_etypes {
            let etype_skey = cred_info.key.keytype;
            let etype_tkt = ticket.enc_part.etype;
            println!(
                "Etype (skey, tkt): {}, {}",
                etype_to_string(etype_skey),
                etype_to_string(etype_tkt)
            )
        }
    }

    return Ok(());
}

fn get_formatted_time(krb_time: Option<&KerberosTime>) -> String {
    match krb_time {
        None => "???".into(),
        Some(krb_time) => krb_time
            .with_timezone(&Local)
            .format("%m/%d/%Y %H:%M:%S")
            .to_string(),
    }
}
fn kerberos_flags_to_string(flags: u32) -> String {
    let mut flags_strs = Vec::new();

    if (flags & ticket_flags::FORWARDABLE) != 0 {
        flags_strs.push("F")
    }
    if (flags & ticket_flags::FORWARDED) != 0 {
        flags_strs.push("f")
    }
    if (flags & ticket_flags::PROXIABLE) != 0 {
        flags_strs.push("P")
    }
    if (flags & ticket_flags::PROXY) != 0 {
        flags_strs.push("p")
    }
    if (flags & ticket_flags::MAY_POSTDATE) != 0 {
        flags_strs.push("D")
    }
    if (flags & ticket_flags::POSTDATE) != 0 {
        flags_strs.push("d")
    }
    if (flags & ticket_flags::RENEWABLE) != 0 {
        flags_strs.push("R")
    }
    if (flags & ticket_flags::INITIAL) != 0 {
        flags_strs.push("I")
    }
    if (flags & ticket_flags::INVALID) != 0 {
        flags_strs.push("i")
    }
    if (flags & ticket_flags::HW_AUTHENT) != 0 {
        flags_strs.push("H")
    }
    if (flags & ticket_flags::PRE_AUTHENT) != 0 {
        flags_strs.push("A")
    }
    if (flags & ticket_flags::TRANSITED_POLICY_CHECKED) != 0 {
        flags_strs.push("T")
    }
    if (flags & ticket_flags::OK_AS_DELEGATE) != 0 {
        flags_strs.push("O")
    }

    return flags_strs.join("");
}

fn etype_to_string(etype: i32) -> String {
    match etype {
        etypes::AES128_CTS_HMAC_SHA1_96 => {
            format!("aes128-cts-hmac-sha1-96 ({})", etype)
        }
        etypes::AES256_CTS_HMAC_SHA1_96 => {
            format!("aes256-cts-hmac-sha1-96 ({})", etype)
        }
        etypes::DES_CBC_CRC => format!("des-cbc-crc ({})", etype),
        etypes::DES_CBC_MD5 => format!("des-cbc-md5 ({})", etype),
        etypes::NO_ENCRYPTION => format!("no encryption ({})", etype),
        etypes::RC4_HMAC => format!("rc4-hmac ({})", etype),
        etypes::RC4_HMAC_EXP => format!("rc4-hmac-exp ({})", etype),
        etypes::RC4_HMAC_OLD_EXP => format!("rc4-hmac-old-exp ({})", etype),
        _ => format!("Unknown ({})", etype),
    }
}
