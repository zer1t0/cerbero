mod as_req_builder;
mod args;

use std::convert::TryInto;
use chrono::{Utc};
use kerberos_asn1::{
    AsRep, Asn1Object, EncAsRepPart, EncKrbCredPart, EncryptedData,
    KrbCred, KrbCredInfo, KrbError, PaData,
    PaEncTsEnc,
};

use kerberos_ccache::{CCache};
use kerberos_constants;
use kerberos_constants::{
    error_codes, etypes, key_usages, pa_data_types,
};
use kerberos_crypto::{AESCipher, AesSizes, KerberosCipher};
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time;
use as_req_builder::AsReqBuilder;
use args::{ArgumentsParser, args};



fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    let mut as_req_builder = AsReqBuilder::new(args.domain.clone())
        .username(args.username.clone())
        .request_pac();

    if let Some(password) = &args.user_password {
        let timestamp = PaEncTsEnc::from(Utc::now());
        let aes_salt = generate_aes_salt(&args.domain, &args.username);

        let aes256_cipher = AESCipher::new(AesSizes::Aes256);

        let key = aes256_cipher.generate_key_from_password(password, &aes_salt);

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
    let raw_as_req = as_req.build();

    let raw_response = send_recv_tcp(&socket_addr, &raw_as_req)
        .expect("Error in send_recv_tcp");

    match KrbError::parse(&raw_response) {
        Ok((_, krb_error)) => {
            let error_string =
                error_codes::error_code_to_string(krb_error.error_code);
            eprintln!(" Error {}: {}", krb_error.error_code, error_string);
        }
        Err(_) => {
            match AsRep::parse(&raw_response) {
                Ok((_, as_rep)) => {
                    let ticket = as_rep.ticket;
                    let krb_cred_info;

                    // decrypt as_rep.enc_part
                    if let Some(password) = &args.user_password {
                        let aes_salt =
                            generate_aes_salt(&args.domain, &args.username);

                        let aes256_cipher = AESCipher::new(AesSizes::Aes256);

                        let key = aes256_cipher
                            .generate_key_from_password(password, &aes_salt);

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

                    let ccache: CCache = krb_cred.try_into().expect("Error converting KrbCred to CCache");

                    fs::write("tatata.ccache", ccache.build())
                        .expect("Unable to write file");
                }
                Err(err) => {
                    eprintln!("Error parsing server responsed: {}", err);
                }
            }
        }
    }
}


fn send_recv_tcp(
    dst_addr: &SocketAddr,
    raw_request: &[u8],
) -> io::Result<Vec<u8>> {
    let mut tcp_stream =
        TcpStream::connect_timeout(dst_addr, time::Duration::new(5, 0))?;

    let raw_sized_request = set_size_header_to_request(raw_request);
    tcp_stream.write(&raw_sized_request)?;

    let mut len_data_bytes = [0 as u8; 4];
    tcp_stream.read_exact(&mut len_data_bytes)?;
    let data_length = u32::from_be_bytes(len_data_bytes);

    let mut raw_response: Vec<u8> = vec![0; data_length as usize];
    tcp_stream.read_exact(&mut raw_response)?;

    return Ok(raw_response);
}

fn set_size_header_to_request(raw_request: &[u8]) -> Vec<u8> {
    let request_length = raw_request.len() as u32;
    let mut raw_sized_request: Vec<u8> = request_length.to_be_bytes().to_vec();
    raw_sized_request.append(&mut raw_request.to_vec());

    return raw_sized_request;
}

// añadir esta y funcion que devuelva los supported etypes en kerberos cryptox
fn generate_aes_salt(realm: &str, client_name: &str) -> Vec<u8> {
    let mut salt = realm.to_uppercase();
    let mut lowercase_username = client_name.to_lowercase();

    if lowercase_username.ends_with("$") {
        salt.push_str("host");
        lowercase_username.pop();
    }
    salt.push_str(&lowercase_username);

    return salt.as_bytes().to_vec();
}


