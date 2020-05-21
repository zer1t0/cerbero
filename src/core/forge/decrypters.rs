use super::krb_cred::new_krb_cred;
use crate::core::krb_user::KerberosUser;
use crate::error::Result;
use kerberos_asn1::KrbCred;
use kerberos_asn1::{AsRep, Asn1Object, EncAsRepPart, EncryptedData};
use kerberos_constants;
use kerberos_constants::key_usages;
use kerberos_crypto::{new_kerberos_cipher, Key};

pub fn extract_krb_cred_from_as_rep(
    as_rep: AsRep,
    user: &KerberosUser,
    user_key: &Key,
) -> Result<KrbCred> {
    let raw_enc_as_rep_part =
        decrypt_as_rep_enc_part(user, user_key, &as_rep.enc_part)?;

    let (_, enc_as_rep_part) = EncAsRepPart::parse(&raw_enc_as_rep_part)
        .map_err(|_| format!("Error decoding AS-REP"))?;

    return Ok(new_krb_cred(
        enc_as_rep_part.into(),
        as_rep.ticket,
        as_rep.crealm,
        as_rep.cname,
    ));
}

/// Decrypts the AS-REP enc-part by using the use credentials
fn decrypt_as_rep_enc_part(
    user: &KerberosUser,
    user_key: &Key,
    enc_part: &EncryptedData,
) -> Result<Vec<u8>> {
    if !user_key.etypes().contains(&enc_part.etype) {
        return Err("Unable to decrypt KDC response AS-REP: mistmach etypes")?;
    }

    let cipher = new_kerberos_cipher(enc_part.etype).unwrap();

    let key = match &user_key {
        Key::Secret(secret) => {
            let salt = cipher.generate_salt(&user.realm, &user.name);
            cipher.generate_key_from_string(&secret, &salt)
        }
        _ => (&user_key.as_bytes()).to_vec(),
    };

    let raw_enc_as_req_part = cipher
        .decrypt(
            &key,
            key_usages::KEY_USAGE_AS_REP_ENC_PART,
            &enc_part.cipher,
        )
        .map_err(|error| {
            format!("Error decrypting KDC response AS-REP: {}", error)
        })?;

    return Ok(raw_enc_as_req_part);
}

/// Decrypts the TGS-REP enc-part by using the session key
pub fn decrypt_tgs_rep_enc_part(
    session_key: &[u8],
    enc_part: &EncryptedData,
) -> Result<Vec<u8>> {
    let cipher = new_kerberos_cipher(enc_part.etype)
        .map_err(|_| format!("Not supported etype: '{}'", enc_part.etype))?;

    let raw_enc_as_req_part = cipher
        .decrypt(
            session_key,
            key_usages::KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY,
            &enc_part.cipher,
        )
        .map_err(|error| format!("Error decrypting TGS-REP: {}", error))?;

    return Ok(raw_enc_as_req_part);
}
