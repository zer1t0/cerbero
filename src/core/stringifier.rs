use crate::core::TicketCred;
use chrono::Local;
use kerberos_asn1::{
    AsRep, EncryptedData, EncryptionKey, KerberosTime, KrbCredInfo, PaData,
    PrincipalName, Ticket, EtypeInfo2Entry
};
use kerberos_constants::etypes;
use kerberos_constants::message_types;
use kerberos_constants::pa_data_types;
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

pub fn as_rep_to_string(ar: &AsRep, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}pvno: {}\n\
         {}msg-type: {}\n\
         {}padata: {}\n\
         {}crealm: {}\n\
         {}cname:\n{}\n\
         {}ticket:\n{}\n\
         {}enc-part:\n{}",
        indentation,
        ar.pvno,
        indentation,
        msg_type_to_string(ar.msg_type),
        indentation,
        &ar.padata
            .as_ref()
            .map(|pds| format!(
                "\n{}",
                padatas_to_string(&pds, indent_level + 2)
            ))
            .unwrap_or(NONE.into()),
        indentation,
        ar.crealm,
        indentation,
        principal_name_to_string(&ar.cname, indent_level + 2),
        indentation,
        ticket_to_string(&ar.ticket, indent_level + 2),
        indentation,
        encrypted_data_to_string(&ar.enc_part, indent_level + 2)
    )
}

pub fn padatas_to_string(padatas: &Vec<PaData>, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    let mut vs = Vec::new();

    for (i, pd) in padatas.iter().enumerate() {
        vs.push(format!(
            "{}[{}]\n\
             {}",
            indentation,
            i,
            padata_to_string(pd, indent_level)
        ))
    }

    return vs.join("\n");
}

pub fn padata_to_string(padata: &PaData, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}padata-type: {}\n\
         {}padata-value: {}",
        indentation,
        padata_type_to_string(padata.padata_type),
        indentation,
        octet_string_to_string(&padata.padata_value)
    )
}

pub fn padata_type_to_string(padata_type: i32) -> String {
    format!("{} -> {}", padata_type, padata_type_name(padata_type))
}

pub fn padata_type_name(padata_type: i32) -> &'static str {
    match padata_type {
        pa_data_types::PA_TGS_REQ => "pa-tgs-req",
        pa_data_types::PA_ENC_TIMESTAMP => "pa-enc-timestamp",
        pa_data_types::PA_PW_SALT => "pa-pw-salt",
        pa_data_types::PA_ENC_UNIX_TIME => "pa-enc-unix-time",
        pa_data_types::PA_SANDIA_SECUREID => "pa-sandia-secureid",
        pa_data_types::PA_SESAME => "pa-sesame",
        pa_data_types::PA_OSF_DCE => "pa-osf-dce",
        pa_data_types::PA_CYBERSAFE_SECUREID => "pa-cybersafe-secureid",
        pa_data_types::PA_AFS3_SALT => "pa-afs3-salt",
        pa_data_types::PA_ETYPE_INFO => "pa-etype-info",
        pa_data_types::PA_SAM_CHALLENGE => "pa-sam-challenge",
        pa_data_types::PA_SAM_RESPONSE => "pa-sam-response",
        pa_data_types::PA_PK_AS_REQ_OLD => "pa-pk-as-req-old",
        pa_data_types::PA_PK_AS_REP_OLD => "pa-pk-as-rep-old",
        pa_data_types::PA_PK_AS_REQ => "pa-pk-as-req",
        pa_data_types::PA_PK_AS_REP => "pa-pk-as-rep",
        pa_data_types::PA_ETYPE_INFO2 => "pa-etype-info2",
        pa_data_types::PA_SVR_REFERRAL_INFO => {
            "pa-srv-referral-info | pa-use-specified-kvno"
        }
        pa_data_types::PA_SAM_REDIRECT => "pa-sam-redirect",
        pa_data_types::PA_GET_FROM_TYPED_DATA => {
            "pa-get-from-typed-data | td-padata"
        }
        pa_data_types::PA_SAM_ETYPE_INFO => "pa-sam-etype-info",
        pa_data_types::PA_ALT_PRINC => "pa-alt-princ",
        pa_data_types::PA_SAM_CHALLENGE2 => "pa-sam-challenge2",
        pa_data_types::PA_SAM_RESPONSE2 => "pa-sam-response2",
        pa_data_types::PA_EXTRA_TGT => "pa-extra-tgt",
        pa_data_types::TD_PKINIT_CMS_CERTIFICATES => {
            "td-pkinit-cms-certificates"
        }
        pa_data_types::TD_KRB_PRINCIPAL => "td-krb-principal",
        pa_data_types::TD_KRB_REALM => "td-krb-realm",
        pa_data_types::TD_TRUSTED_CERTIFIERS => "td-trusted-certifiers",
        pa_data_types::TD_CERTIFICATE_INDEX => "td-certificate-index",
        pa_data_types::TD_APP_DEFINED_ERROR => "td-app-defined-error",
        pa_data_types::TD_REQ_NONCE => "td-req-nonce",
        pa_data_types::TD_REQ_SEQ => "td-req-seq",
        pa_data_types::PA_PAC_REQUEST => "pa-pac-request",
        pa_data_types::PA_FOR_USER => "pa-for-user",
        pa_data_types::PA_FX_COOKIE => "pa-fx-cookien",
        pa_data_types::PA_FX_FAST => "pa-fx-fast",
        pa_data_types::PA_FX_ERROR => "pa-fx-error",
        pa_data_types::PA_ENCRYPTED_CHALLENGE => "pa-encrypted-challenge",
        pa_data_types::KERB_KEY_LIST_REQ => "kerb-key-list-req",
        pa_data_types::KERB_KEY_LIST_REP => "kerb-key-list-rep",
        pa_data_types::PA_SUPPORTED_ENCTYPES => "pa-supported-enctypes",
        pa_data_types::PA_PAC_OPTIONS => "pa-pac-options",
        _ => UNKNOWN,
    }
}

pub fn msg_type_to_string(msg_type: i32) -> String {
    format!("{} -> {}", msg_type, msg_type_name(msg_type))
}

pub fn msg_type_name(msg_type: i32) -> &'static str {
    match msg_type {
        message_types::KRB_AS_REQ => "krb-as-req",
        message_types::KRB_AS_REP => "krb-as-rep",
        message_types::KRB_TGS_REQ => "krb-tgs-req",
        message_types::KRB_TGS_REP => "krb-tgs-rep",
        message_types::KRB_AP_REQ => "krb-ap-req",
        message_types::KRB_AP_REP => "krb-ap-rep",
        message_types::KRB_RESERVED16 => "krb-reserved16",
        message_types::KRB_RESERVED17 => "krb-reserved17",
        message_types::KRB_SAFE => "krb-safe",
        message_types::KRB_PRIV => "krb-priv",
        message_types::KRB_CRED => "krb-cred",
        message_types::KRB_ERROR => "krb-error",
        _ => UNKNOWN,
    }
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


pub fn etype_info2_entry_to_string(entry: EtypeInfo2Entry, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}etype: {}\n\
         {}salt: {}\n\
         {}s2kparams: {}",
        indentation,
        etype_to_string(entry.etype),
        indentation,
    )
}
