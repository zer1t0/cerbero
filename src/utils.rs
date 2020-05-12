use kerberos_constants::{error_codes, etypes, principal_names};
use std::convert::TryInto;
use std::fs;

use crate::cred_format::CredentialFormat;
use kerberos_asn1::{
    Asn1Object, EncKdcRepPart, EncKrbCredPart, EncryptedData, KrbCred,
    KrbCredInfo, KrbError, PrincipalName, Ticket,
};
use kerberos_ccache::CCache;

pub fn username_to_principal_name(username: String) -> PrincipalName {
    return PrincipalName {
        name_type: principal_names::NT_PRINCIPAL,
        name_string: vec![username],
    };
}

pub fn parse_creds_file(
    creds_file: &str,
) -> Result<(KrbCred, CredentialFormat), String> {
    let data = fs::read(creds_file).map_err(|err| {
        format!("Unable to read the file '{}': {}", creds_file, err)
    })?;

    match CCache::parse(&data) {
        Ok((_, ccache)) => {
            let krb_cred = ccache.try_into().map_err(|_| {
                format!(
                    "Error parsing ccache data content of file '{}'",
                    creds_file
                )
            })?;

            return Ok((krb_cred, CredentialFormat::Ccache));
        }
        Err(_) => {
            let (_, krb_cred) = KrbCred::parse(&data).map_err(|_| {
                format!("Error parsing content of file '{}'", creds_file)
            })?;
            return Ok((krb_cred, CredentialFormat::Krb));
        }
    }
}

pub fn save_cred_in_file(
    krb_cred: KrbCred,
    cred_format: &CredentialFormat,
    out_file: &str,
) -> Result<(), String> {
    let raw_cred = match cred_format {
        CredentialFormat::Krb => krb_cred.build(),
        CredentialFormat::Ccache => {
            let ccache: CCache = krb_cred
                .try_into()
                .map_err(|_| format!("Error converting KrbCred to CCache"))?;
            ccache.build()
        }
    };

    fs::write(out_file, raw_cred).map_err(|_| {
        format!("Unable to write credentials in file {}", out_file)
    })?;

    return Ok(());
}

pub fn create_krb_error_msg(krb_error: &KrbError) -> String {
    let error_string = error_codes::error_code_to_string(krb_error.error_code);
    return format!("Error {}: {}", krb_error.error_code, error_string);
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