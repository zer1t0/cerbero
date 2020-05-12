use chrono::Utc;
use kerberos_asn1::{
    AsRep, AsReq, Asn1Object, EncAsRepPart, EncryptedData, KrbCred, PaData,
    PaEncTsEnc,
};

use crate::kdc_req_builder::KdcReqBuilder;
use kerberos_constants;
use kerberos_constants::{key_usages, pa_data_types};
use kerberos_crypto::{
    new_kerberos_cipher, AesCipher, AesSizes, KerberosCipher, Key, Rc4Cipher,
};

use crate::cred_format::CredentialFormat;
use crate::error::Result;
use crate::senders::{send_recv, Rep};
use crate::transporter::KerberosTransporter;
use crate::utils::{create_krb_cred, create_krb_error_msg, save_cred_in_file};

pub fn ask_tgt(
    realm: &String,
    username: &String,
    user_key: &Key,
    preauth: bool,
    transporter: &dyn KerberosTransporter,
    cred_format: &CredentialFormat,
    out_file: &str,
) -> Result<()> {
    let krb_cred =
        request_tgt(realm, username, user_key, preauth, transporter)?;

    save_cred_in_file(krb_cred, cred_format, out_file)?;

    return Ok(());
}

fn request_tgt(
    realm: &String,
    username: &String,
    user_key: &Key,
    preauth: bool,
    transporter: &dyn KerberosTransporter,
) -> Result<KrbCred> {
    let as_req = build_as_req(realm, username, user_key, preauth);

    let rep = send_recv_as(transporter, &as_req)?;

    return handle_as_rep(rep, realm, username, user_key);
}

fn send_recv_as(
    transporter: &dyn KerberosTransporter,
    req: &AsReq,
) -> Result<AsRep> {
    let rep = send_recv(transporter, &req.build())
        .map_err(|err| format!("Error sending TGS-REQ: {}", err))?;

    match rep {
        Rep::KrbError(krb_error) => {
            return Err(create_krb_error_msg(&krb_error))?;
        }

        Rep::Raw(_) => {
            return Err("Error parsing response")?;
        }

        Rep::AsRep(as_rep) => {
            return Ok(as_rep);
        }

        Rep::TgsRep(_) => {
            return Err(
                "Unexpected: server responded with a TGS-REQ to an AS-REP",
            )?;
        }
    }
}

fn build_as_req(
    realm: &String,
    username: &String,
    user_key: &Key,
    preauth: bool,
) -> AsReq {
    let mut as_req_builder = KdcReqBuilder::new(realm.clone())
        .username(username.clone())
        .etypes(user_key.etypes())
        .request_pac();

    if preauth {
        let padata =
            generate_padata_encrypted_timestamp(&user_key, &realm, &username);
        as_req_builder = as_req_builder.push_padata(padata);
    }

    return as_req_builder.build_as_req();
}

fn handle_as_rep(
    as_rep: AsRep,
    realm: &String,
    username: &String,
    user_key: &Key,
) -> Result<KrbCred> {
    return extract_krb_cred_from_as_rep(as_rep, user_key, username, realm);
}

fn extract_krb_cred_from_as_rep(
    as_rep: AsRep,
    user_key: &Key,
    username: &String,
    realm: &String,
) -> Result<KrbCred> {
    let raw_enc_as_rep_part =
        decrypt_as_rep_enc_part(user_key, username, realm, &as_rep.enc_part)?;

    let (_, enc_as_rep_part) = EncAsRepPart::parse(&raw_enc_as_rep_part)
        .map_err(|_| format!("Error decoding AS-REP"))?;

    return Ok(create_krb_cred(
        enc_as_rep_part.into(),
        as_rep.ticket,
        as_rep.crealm,
        as_rep.cname,
    ));
}

fn decrypt_as_rep_enc_part(
    user_key: &Key,
    username: &str,
    realm: &str,
    enc_part: &EncryptedData,
) -> Result<Vec<u8>> {
    if !user_key.etypes().contains(&enc_part.etype) {
        return Err("Unable to decrypt KDC response AS-REP: mistmach etypes")?;
    }

    let cipher = new_kerberos_cipher(enc_part.etype).unwrap();

    let key = match &user_key {
        Key::Secret(secret) => {
            let salt = cipher.generate_salt(realm, username);
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

fn generate_padata_encrypted_timestamp(
    user_key: &Key,
    realm: &str,
    client_name: &str,
) -> PaData {
    let (encrypted_timestamp, etype) =
        generate_encrypted_timestamp(user_key, realm, client_name);

    let padata = PaData::new(
        pa_data_types::PA_ENC_TIMESTAMP,
        EncryptedData::new(etype, None, encrypted_timestamp).build(),
    );

    return padata;
}

fn generate_encrypted_timestamp(
    user_key: &Key,
    realm: &str,
    client_name: &str,
) -> (Vec<u8>, i32) {
    let timestamp = PaEncTsEnc::from(Utc::now());
    let (cipher, key) = get_cipher_and_key(user_key, realm, client_name);
    let encrypted_timestamp = cipher.encrypt(
        &key,
        key_usages::KEY_USAGE_AS_REQ_TIMESTAMP,
        &timestamp.build(),
    );

    return (encrypted_timestamp, cipher.etype());
}

fn get_cipher_and_key(
    user_key: &Key,
    realm: &str,
    client_name: &str,
) -> (Box<dyn KerberosCipher>, Vec<u8>) {
    match user_key {
        Key::Secret(secret) => {
            let cipher = AesCipher::new(AesSizes::Aes256);
            let salt = cipher.generate_salt(realm, client_name);
            let key = cipher.generate_key_from_string(&secret, &salt);
            return (Box::new(cipher), key);
        }
        Key::RC4Key(key) => {
            let cipher = Rc4Cipher::new();
            return (Box::new(cipher), key.to_vec());
        }
        Key::AES128Key(key) => {
            let cipher = AesCipher::new(AesSizes::Aes128);
            return (Box::new(cipher), key.to_vec());
        }
        Key::AES256Key(key) => {
            let cipher = AesCipher::new(AesSizes::Aes256);
            return (Box::new(cipher), key.to_vec());
        }
    };
}
