
use chrono::Utc;
use kerberos_asn1::{
    AsRep, AsReq, Asn1Object, EncAsRepPart, EncKrbCredPart, EncryptedData,
    KrbCred, KrbCredInfo, KrbError, PaData, PaEncTsEnc, PrincipalName, Ticket,
};
use std::convert::TryInto;

use crate::args::{Arguments, TicketFormat};
use crate::as_req_builder::KdcReqBuilder;
use kerberos_ccache::CCache;
use kerberos_constants;
use kerberos_constants::{error_codes, etypes, key_usages, pa_data_types};
use kerberos_crypto::{
    new_kerberos_cipher, AesCipher, AesSizes, KerberosCipher, Key, Rc4Cipher,
};
use std::fs;
use std::net::SocketAddr;

use crate::senders::{send_recv_as, Rep};


pub fn ask_tgt(args: Arguments) -> Result<(), String> {
    let as_req =
        build_as_req(&args.realm, &args.username, &args.user_key, args.preauth);

    let socket_addr = SocketAddr::new(args.kdc_ip, args.kdc_port);
    let rep = send_recv_as(&socket_addr, &as_req).expect("Error sending AsReq");

    match rep {
        Rep::KrbError(krb_error) => {
            return handle_krb_error(&krb_error);
        }

        Rep::Raw(_) => {
            return Err(format!("Error parsing response"));
        }

        Rep::AsRep(as_rep) => {
            return handle_as_rep(as_rep, &args);
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

fn handle_krb_error(krb_error: &KrbError) -> Result<(), String> {
    let error_string = error_codes::error_code_to_string(krb_error.error_code);
    return Err(format!("Error {}: {}", krb_error.error_code, error_string));
}

fn handle_as_rep(as_rep: AsRep, args: &Arguments) -> Result<(), String> {
    let krb_cred = extract_krb_cred_from_as_rep(
        as_rep,
        &args.user_key,
        &args.username,
        &args.realm,
    )?;
    save_cred_in_file(krb_cred, &args.ticket_format, &args.out_file)?;
    return Ok(());
}

fn extract_krb_cred_from_as_rep(
    as_rep: AsRep,
    user_key: &Key,
    username: &String,
    realm: &String,
) -> Result<KrbCred, String> {
    let raw_enc_as_rep_part =
        decrypt_as_rep_enc_part(user_key, username, realm, &as_rep.enc_part)?;

    let (_, enc_as_rep_part) = EncAsRepPart::parse(&raw_enc_as_rep_part)
        .map_err(|_| format!("Error decoding AS-REP"))?;

    return Ok(create_krb_cred(
        enc_as_rep_part,
        as_rep.ticket,
        as_rep.crealm,
        as_rep.cname,
    ));
}

fn save_cred_in_file(
    krb_cred: KrbCred,
    cred_format: &TicketFormat,
    out_file: &str,
) -> Result<(), String> {
    let raw_cred = match cred_format {
        TicketFormat::Krb => krb_cred.build(),
        TicketFormat::Ccache => {
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

fn create_krb_cred(
    enc_as_rep_part: EncAsRepPart,
    ticket: Ticket,
    prealm: String,
    pname: PrincipalName,
) -> KrbCred {
    let krb_cred_info = KrbCredInfo {
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

fn decrypt_as_rep_enc_part(
    user_key: &Key,
    username: &str,
    realm: &str,
    enc_part: &EncryptedData,
) -> Result<Vec<u8>, String> {
    if !user_key.etypes().contains(&enc_part.etype) {
        return Err(format!(
            "Unable to decrypt KDC response AS-REP: mistmach etypes"
        ));
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
