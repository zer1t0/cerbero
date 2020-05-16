use crate::cred_format::CredentialFormat;
use crate::error::Result;
use dns_lookup;
use kerberos_asn1::{
    Asn1Object, EncKdcRepPart, EncKrbCredPart, EncryptedData, KrbCred,
    KrbCredInfo, PrincipalName, Ticket,
};
use kerberos_constants::{etypes, principal_names};
use std::env;
use std::net::IpAddr;

pub fn username_to_principal_name(username: String) -> PrincipalName {
    return PrincipalName {
        name_type: principal_names::NT_PRINCIPAL,
        name_string: vec![username],
    };
}

pub fn gen_krbtgt_principal_name(realm: String, name_type: i32) -> PrincipalName {
    return PrincipalName {
        name_type,
        name_string: vec!["krbtgt".into(), realm],
    };
}

pub fn create_krb_cred(
    enc_as_rep_part: EncKdcRepPart,
    ticket: Ticket,
    prealm: String,
    pname: PrincipalName,
) -> KrbCred {
    let krb_cred_info = create_krb_cred_info(enc_as_rep_part, prealm, pname);

    let mut enc_krb_cred_part = EncKrbCredPart::default();
    enc_krb_cred_part.ticket_info.push(krb_cred_info);

    let mut krb_cred = KrbCred::default();
    krb_cred.tickets.push(ticket);
    krb_cred.enc_part = EncryptedData {
        etype: etypes::NO_ENCRYPTION,
        kvno: None,
        cipher: enc_krb_cred_part.build(),
    };

    return krb_cred;
}

pub fn create_krb_cred_info(
    enc_as_rep_part: EncKdcRepPart,
    prealm: String,
    pname: PrincipalName,
) -> KrbCredInfo {
    return KrbCredInfo {
        key: enc_as_rep_part.key,
        prealm: Some(prealm),
        pname: Some(pname),
        flags: Some(enc_as_rep_part.flags),
        authtime: Some(enc_as_rep_part.authtime),
        starttime: enc_as_rep_part.starttime,
        endtime: Some(enc_as_rep_part.endtime),
        renew_till: enc_as_rep_part.renew_till,
        srealm: Some(enc_as_rep_part.srealm),
        sname: Some(enc_as_rep_part.sname),
        caddr: enc_as_rep_part.caddr,
    };
}

pub fn resolve_host(realm: &str) -> Result<IpAddr> {
    let ips = dns_lookup::lookup_host(realm)
        .map_err(|err| format!("Error resolving '{}' : '{}'", realm, err))?;

    if ips.len() == 0 {
        return Err(format!("Error resolving '{}': No entries found", realm))?;
    }

    return Ok(ips[0]);
}

pub fn get_ticket_file(
    args_file: Option<String>,
    username: &String,
    cred_format: &CredentialFormat,
) -> String {
    if let Some(file) = args_file {
        return file;
    }

    if let Some(file) = get_env_ticket_file() {
        return file;
    }

    return format!("{}.{}", username, cred_format);
}

pub fn get_env_ticket_file() -> Option<String> {
    return env::var("KRB5CCNAME").ok();
}
