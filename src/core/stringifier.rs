use crate::core::TicketCred;
use chrono::Local;
use kerberos_asn1::{
    EncryptedData, EncryptionKey, KerberosTime, KrbCredInfo, PrincipalName,
    Ticket,
};
use kerberos_constants::etypes;
use kerberos_constants::principal_names;
use kerberos_constants::ticket_flags;

const NONE: &str = "-";
const UNKNOWN: &str = "???";

pub fn ticket_cred_to_string(tc: &TicketCred, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}[Ticket]\n\
         {}\n\
         {}[KrbCredInfo]\n\
         {}",
        indentation,
        ticket_to_string(&tc.ticket, indent_level),
        indentation,
        krb_cred_info_to_string(&tc.cred_info, indent_level)
    )
}

pub fn ticket_to_string(tkt: &Ticket, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}tkt-vno: {}\n\
         {}realm: {}\n\
         {}sname:\n{}\n\
         {}enc-part:\n{}",
        indentation,
        tkt.tkt_vno,
        indentation,
        tkt.realm,
        indentation,
        principal_name_to_string(&tkt.sname, indent_level + 2),
        indentation,
        encrypted_data_to_string(&tkt.enc_part, indent_level + 2)
    )
}

pub fn encrypted_data_to_string(
    ed: &EncryptedData,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}etype: {}\n\
         {}kvno: {}\n\
         {}cipher: {}",
        indentation,
        etype_to_string(ed.etype),
        indentation,
        ed.kvno.map(|v| format!("{}", v)).unwrap_or(NONE.into()),
        indentation,
        format!("{} bytes", ed.cipher.len())
    )
}

fn indent(level: usize) -> String {
    let mut ind = "".to_string();
    for _ in 0..level {
        ind = format!(" {}", ind);
    }
    return ind;
}

pub fn krb_cred_info_to_string(
    kci: &KrbCredInfo,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}key:\n{}\n\
         {}prealm: {}\n\
         {}pname:\n{}\n\
         {}flags: {}\n\
         {}authtime: {}\n\
         {}starttime: {}\n\
         {}endtime: {}\n\
         {}renew-till: {}\n\
         {}srealm: {}\n\
         {}sname:\n{}\n\
         {}caddr: <Not Implemented>",
        indentation,
        encryption_key_to_string(&kci.key, indent_level + 2),
        indentation,
        &kci.prealm.as_ref().unwrap_or(&NONE.to_string()),
        indentation,
        &kci.pname
            .as_ref()
            .map(|v| principal_name_to_string(&v, indent_level + 2))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.flags
            .as_ref()
            .map(|v| kerberos_flags_to_string(v.flags))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.authtime
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.starttime
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.endtime
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.renew_till
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.srealm.as_ref().unwrap_or(&NONE.into()),
        indentation,
        &kci.sname
            .as_ref()
            .map(|v| principal_name_to_string(&v, indent_level + 2))
            .unwrap_or(NONE.into()),
        indentation
    )
}

pub fn encryption_key_to_string(
    ek: &EncryptionKey,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}keytype: {}\n\
         {}keyvalue: {}",
        indentation,
        etype_to_string(ek.keytype),
        indentation,
        octet_string_to_string(&ek.keyvalue)
    )
}

pub fn octet_string_to_string(os: &Vec<u8>) -> String {
    let mut vs = Vec::new();

    for o in os.iter() {
        vs.push(format!("{:02x}", o));
    }
    return vs.join("");
}

pub fn principal_name_to_string(
    pname: &PrincipalName,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}name-type: {} -> {}\n\
         {}name-string: {}",
        indentation,
        pname.name_type,
        name_type_name(pname.name_type),
        indentation,
        pname.name_string.join("/")
    )
}

pub fn kerberos_time_to_string(krb_time: &KerberosTime) -> String {
    krb_time
        .with_timezone(&Local)
        .format("%m/%d/%Y %H:%M:%S")
        .to_string()
}

pub fn kerberos_flags_to_string(flags: u32) -> String {
    let mut flags_strs = Vec::new();

    if (flags & ticket_flags::FORWARDABLE) != 0 {
        flags_strs.push("forwardable")
    }
    if (flags & ticket_flags::FORWARDED) != 0 {
        flags_strs.push("forwarded")
    }
    if (flags & ticket_flags::PROXIABLE) != 0 {
        flags_strs.push("proxiable")
    }
    if (flags & ticket_flags::PROXY) != 0 {
        flags_strs.push("proxy")
    }
    if (flags & ticket_flags::MAY_POSTDATE) != 0 {
        flags_strs.push("may_postdate")
    }
    if (flags & ticket_flags::POSTDATE) != 0 {
        flags_strs.push("postdate")
    }
    if (flags & ticket_flags::RENEWABLE) != 0 {
        flags_strs.push("renewable")
    }
    if (flags & ticket_flags::INITIAL) != 0 {
        flags_strs.push("initial")
    }
    if (flags & ticket_flags::INVALID) != 0 {
        flags_strs.push("invalid")
    }
    if (flags & ticket_flags::HW_AUTHENT) != 0 {
        flags_strs.push("hw_authent")
    }
    if (flags & ticket_flags::PRE_AUTHENT) != 0 {
        flags_strs.push("pre_authent")
    }
    if (flags & ticket_flags::TRANSITED_POLICY_CHECKED) != 0 {
        flags_strs.push("transited_policy_checked")
    }
    if (flags & ticket_flags::OK_AS_DELEGATE) != 0 {
        flags_strs.push("ok_as_delegate")
    }
    if (flags & ticket_flags::REQUEST_ANONYMOUS) != 0 {
        flags_strs.push("anonymous")
    }
    if (flags & ticket_flags::NAME_CANONICALIZE) != 0 {
        flags_strs.push("name_canonicalize")
    }

    return format!("{:#06x} -> {}", flags, flags_strs.join(" "));
}

fn etype_to_string(etype: i32) -> String {
    format!("{} -> {}", etype, etype_name(etype))
}

fn etype_name(etype: i32) -> &'static str {
    match etype {
        etypes::AES128_CTS_HMAC_SHA1_96 => "aes128-cts-hmac-sha1-96",
        etypes::AES256_CTS_HMAC_SHA1_96 => "aes256-cts-hmac-sha1-96",
        etypes::DES_CBC_CRC => "des-cbc-crc",
        etypes::DES_CBC_MD5 => "des-cbc-md5",
        etypes::NO_ENCRYPTION => "no encryption",
        etypes::RC4_HMAC => "rc4-hmac",
        etypes::RC4_HMAC_EXP => "rc4-hmac-exp",
        etypes::RC4_HMAC_OLD_EXP => "rc4-hmac-old-exp",
        _ => UNKNOWN,
    }
}

fn name_type_name(name_type: i32) -> &'static str {
    match name_type {
        principal_names::NT_UNKNOWN => "nt-unknown",
        principal_names::NT_PRINCIPAL => "nt-principal",
        principal_names::NT_SRV_INST => "nt-srv-inst",
        principal_names::NT_SRV_HST => "nt-srv-hst",
        principal_names::NT_SRV_XHST => "nt-srv-xhst",
        principal_names::NT_UID => "nt-uid",
        principal_names::NT_X500_PRINCIPAL => "nt-x500-principal",
        principal_names::NT_SMTP_NAME => "nt-smtp-name",
        principal_names::NT_ENTERPRISE => "nt-enterprise",
        _ => UNKNOWN,
    }
}
