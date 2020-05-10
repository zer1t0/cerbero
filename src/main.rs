mod args;
mod as_req_builder;
mod senders;

use chrono::Utc;
use kerberos_asn1::{
    Asn1Object, EncAsRepPart, EncKrbCredPart, EncryptedData, KrbCred,
    KrbCredInfo, PaData, PaEncTsEnc,
};
use std::convert::TryInto;

use args::{args, ArgumentsParser};
use as_req_builder::AsReqBuilder;
use kerberos_ccache::CCache;
use kerberos_constants;
use kerberos_constants::{error_codes, etypes, key_usages, pa_data_types};
use kerberos_crypto::{AesCipher, AesSizes, KerberosCipher};
use std::fs;
use std::net::SocketAddr;

use senders::{send_recv_as, Rep};

fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    let mut as_req_builder = AsReqBuilder::new(args.domain.clone())
        .username(args.username.clone())
        .request_pac();

    if let Some(password) = &args.user_password {
        let timestamp = PaEncTsEnc::from(Utc::now());

        let aes256_cipher = AesCipher::new(AesSizes::Aes256);
        let salt = aes256_cipher.generate_salt(&args.domain, &args.username);
        let key = aes256_cipher.generate_key_from_string(password, &salt);
        let encrypted_timestamp = aes256_cipher.encrypt(
            &key,
            key_usages::KEY_USAGE_AS_REQ_TIMESTAMP,
            &timestamp.build(),
        );

        as_req_builder = as_req_builder.push_padata(PaData::new(
            pa_data_types::PA_ENC_TIMESTAMP,
            EncryptedData::new(
                etypes::AES256_CTS_HMAC_SHA1_96,
                None,
                encrypted_timestamp,
            )
            .build(),
        ));
    }

    let as_req = as_req_builder.build();

    let socket_addr = SocketAddr::new(args.kdc_ip, 88);

    let rep = send_recv_as(&socket_addr, &as_req).expect("Error sending AsReq");

    match rep {
        Rep::KrbError(krb_error) => {
            let error_string =
                error_codes::error_code_to_string(krb_error.error_code);
            eprintln!(" Error {}: {}", krb_error.error_code, error_string);
        }

        Rep::AsRep(as_rep) => {
            let ticket = as_rep.ticket;
            let krb_cred_info;

            // decrypt as_rep.enc_part
            if let Some(password) = &args.user_password {
                let aes256_cipher = AesCipher::new(AesSizes::Aes256);
                let salt = aes256_cipher.generate_salt(&args.domain, &args.username);

                let key =
                    aes256_cipher.generate_key_from_string(password, &salt);

                let raw_enc_as_req_part = aes256_cipher
                    .decrypt(
                        &key,
                        key_usages::KEY_USAGE_AS_REP_ENC_PART,
                        &as_rep.enc_part.cipher,
                    )
                    .expect("Unable to decrypt the enc_as_req_part");

                let (_, enc_as_req_part) =
                    EncAsRepPart::parse(&raw_enc_as_req_part)
                        .expect("Error parsing EncAsRepPart");

                krb_cred_info = KrbCredInfo {
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
            } else {
                eprintln!("No way to decrypt the response without credentials");
                return;
            }

            let mut enc_krb_cred_part = EncKrbCredPart::default();
            enc_krb_cred_part.ticket_info.push(krb_cred_info);

            let mut krb_cred = KrbCred::default();
            krb_cred.tickets.push(ticket);
            krb_cred.enc_part = EncryptedData {
                etype: etypes::NO_ENCRYPTION,
                kvno: None,
                cipher: enc_krb_cred_part.build(),
            };

            let ccache: CCache = krb_cred
                .try_into()
                .expect("Error converting KrbCred to CCache");

            fs::write("tatata.ccache", ccache.build())
                .expect("Unable to write file");
        }

        _ => {
            eprintln!("Error parsing response");
        }
    }
}
