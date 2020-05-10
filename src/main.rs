mod args;
mod as_req_builder;
mod senders;

use chrono::Utc;
use kerberos_asn1::{
    Asn1Object, EncAsRepPart, EncKrbCredPart, EncryptedData, KrbCred,
    KrbCredInfo, PaData, PaEncTsEnc,
};
use std::convert::TryInto;

use args::{args, ArgumentsParser, TicketFormat};
use as_req_builder::AsReqBuilder;
use kerberos_ccache::CCache;
use kerberos_constants;
use kerberos_constants::{error_codes, etypes, key_usages, pa_data_types};
use kerberos_crypto::{
    new_kerberos_cipher, AesCipher, AesSizes, KerberosCipher, Key, Rc4Cipher,
};
use std::fs;
use std::net::SocketAddr;

use senders::{send_recv_as, Rep};

fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    let mut as_req_builder = AsReqBuilder::new(args.realm.clone())
        .username(args.username.clone())
        .etypes(args.user_key.etypes())
        .request_pac();

    println!("{:?}", args);
    if args.preauth {
        let padata = generate_padata_encrypted_timestamp(
            &args.user_key,
            &args.realm,
            &args.username,
        );
        as_req_builder = as_req_builder.push_padata(padata);
    }

    let as_req = as_req_builder.build();

    let socket_addr = SocketAddr::new(args.kdc_ip, 88);

    let rep = send_recv_as(&socket_addr, &as_req).expect("Error sending AsReq");

    if let Rep::KrbError(krb_error) = rep {
        let error_string =
            error_codes::error_code_to_string(krb_error.error_code);
        eprintln!(" Error {}: {}", krb_error.error_code, error_string);
        return;
    }

    if let Rep::Raw(_) = rep {
        eprintln!("Error parsing response");
        return;
    }

    if let Rep::AsRep(as_rep) = rep {
        let resp_etype = as_rep.enc_part.etype;

        if !args.user_key.etypes().contains(&resp_etype) {
            eprintln!("Unable to decrypt response AS-REP: mistmach etypes");
            return;
        }

        let cipher = new_kerberos_cipher(resp_etype).unwrap();

        let key = match &args.user_key {
            Key::Secret(secret) => {
                let salt = cipher.generate_salt(&args.realm, &args.username);
                cipher.generate_key_from_string(&secret, &salt)
            }
            _ => (&args.user_key.as_bytes()).to_vec(),
        };

        let raw_enc_as_req_part = cipher
            .decrypt(
                &key,
                key_usages::KEY_USAGE_AS_REP_ENC_PART,
                &as_rep.enc_part.cipher,
            )
            .expect("Unable to decrypt the enc_as_req_part");

        let (_, enc_as_req_part) = EncAsRepPart::parse(&raw_enc_as_req_part)
            .expect("Error parsing EncAsRepPart");

        let krb_cred_info = KrbCredInfo {
            key: enc_as_req_part.key,
            prealm: Some(as_req.req_body.realm),
            pname: as_req.req_body.cname,
            flags: Some(enc_as_req_part.flags),
            authtime: Some(enc_as_req_part.authtime),
            starttime: enc_as_req_part.starttime,
            endtime: Some(enc_as_req_part.endtime),
            renew_till: enc_as_req_part.renew_till,
            srealm: Some(enc_as_req_part.srealm),
            sname: Some(enc_as_req_part.sname),
            caddr: enc_as_req_part.caddr,
        };

        let mut enc_krb_cred_part = EncKrbCredPart::default();
        enc_krb_cred_part.ticket_info.push(krb_cred_info);

        let mut krb_cred = KrbCred::default();
        krb_cred.tickets.push(as_rep.ticket);
        krb_cred.enc_part = EncryptedData {
            etype: etypes::NO_ENCRYPTION,
            kvno: None,
            cipher: enc_krb_cred_part.build(),
        };

        let raw_cred = match args.ticket_format {
            TicketFormat::Krb => krb_cred.build(),
            TicketFormat::Ccache => {
                let ccache: CCache = krb_cred
                    .try_into()
                    .expect("Error converting KrbCred to CCache");
                ccache.build()
            }
        };

        fs::write(args.out_file, raw_cred).expect("Unable to write file");
    }
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
