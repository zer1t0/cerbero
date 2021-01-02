use super::krb_cred::new_krb_cred_info;
use crate::core::Cipher;
use crate::core::TicketCred;
use crate::error::Result;
use kerberos_asn1::{
    AsRep, Asn1Object, EncAsRepPart, EncTgsRepPart, EncryptedData, TgsRep,
};
use kerberos_constants;
use kerberos_constants::key_usages;

pub fn extract_krb_cred_from_as_rep(
    as_rep: AsRep,
    cipher: &Cipher,
) -> Result<TicketCred> {
    let raw_enc_as_rep_part =
        decrypt_as_rep_enc_part(cipher, &as_rep.enc_part)?;

    let (_, enc_as_rep_part) = EncAsRepPart::parse(&raw_enc_as_rep_part)
        .map_err(|_| format!("Error decoding AS-REP"))?;

    let krb_cred_info =
        new_krb_cred_info(enc_as_rep_part.into(), as_rep.crealm, as_rep.cname);

    return Ok(TicketCred::new(as_rep.ticket, krb_cred_info));
}

/// Decrypts the AS-REP enc-part by using the use credentials
fn decrypt_as_rep_enc_part(
    cipher: &Cipher,
    enc_part: &EncryptedData,
) -> Result<Vec<u8>> {
    if cipher.etype() != enc_part.etype {
        return Err("Unable to decrypt KDC response AS-REP: mistmach etypes")?;
    }

    let raw_enc_as_req_part = cipher
        .decrypt(key_usages::KEY_USAGE_AS_REP_ENC_PART, &enc_part.cipher)
        .map_err(|error| {
            format!("Error decrypting KDC response AS-REP: {}", error)
        })?;

    return Ok(raw_enc_as_req_part);
}

pub fn extract_ticket_from_tgs_rep(
    tgs_rep: TgsRep,
    cipher: &Cipher,
) -> Result<TicketCred> {
    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(&cipher, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = new_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs).into());
}

/// Decrypts the TGS-REP enc-part by using the session key
fn decrypt_tgs_rep_enc_part(
    cipher: &Cipher,
    enc_part: &EncryptedData,
) -> Result<Vec<u8>> {
    let raw_enc_as_req_part = cipher
        .decrypt(
            key_usages::KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY,
            &enc_part.cipher,
        )
        .map_err(|error| format!("Error decrypting TGS-REP: {}", error))?;

    return Ok(raw_enc_as_req_part);
}
