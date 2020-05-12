use kerberos_asn1::{
    ApReq, Asn1Object, Authenticator, EncTgsRepPart, EncryptedData, PaData,
    PrincipalName,
};

use kerberos_constants::key_usages;
use kerberos_constants::key_usages::KEY_USAGE_TGS_REQ_AUTHEN;
use kerberos_constants::pa_data_types::PA_TGS_REQ;
use kerberos_constants::principal_names::NT_SRV_INST;
use kerberos_crypto::new_kerberos_cipher;

use crate::kdc_req_builder::KdcReqBuilder;
use crate::senders::{send_recv_tgs, Rep};
use std::net::SocketAddr;

use crate::krb_cred_plain::KrbCredPlain;
use crate::utils::{
    create_krb_cred_info, handle_krb_error, parse_creds_file,
    save_cred_in_file, username_to_principal_name,
};

pub fn ask_tgs(
    creds_file: &str,
    service: String,
    username: String,
    realm: String,
    kdc_addr: &SocketAddr,
) -> Result<(), String> {
    let (krb_cred, cred_format) = parse_creds_file(creds_file)?;

    let cname = username_to_principal_name(username.clone());
    let tgt_service = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: vec!["krbtgt".into(), realm.clone()],
    };
    let mut krb_cred_plain = KrbCredPlain::try_from_krb_cred(krb_cred)?;

    let (ticket, krb_cred_info) = krb_cred_plain
        .look_for_user_creds(&cname, &tgt_service)
        .ok_or(format!("No TGT found for '{}", username))?;

    // crear un default en kerberos_asn1
    let mut authenticator = Authenticator::default();
    authenticator.crealm = realm.clone();
    authenticator.cname = cname;

    let authen_etype = krb_cred_info.key.keytype;
    let cipher = new_kerberos_cipher(authen_etype)
        .map_err(|_| format!("No supported etype: {}", authen_etype))?;

    let session_key = &krb_cred_info.key.keyvalue;
    let encrypted_authenticator = cipher.encrypt(
        session_key,
        KEY_USAGE_TGS_REQ_AUTHEN,
        &authenticator.build(),
    );

    let mut ap_req = ApReq::default();
    ap_req.ticket = ticket.clone();
    ap_req.authenticator = EncryptedData {
        etype: authen_etype,
        kvno: None,
        cipher: encrypted_authenticator,
    };

    let pa_tgs_req = PaData {
        padata_type: PA_TGS_REQ,
        padata_value: ap_req.build(),
    };

    let service_parts: Vec<String> =
        service.split("/").map(|s| s.to_string()).collect();

    let tgs_req = KdcReqBuilder::new(realm)
        .push_padata(pa_tgs_req)
        .sname(Some(PrincipalName {
            name_type: NT_SRV_INST,
            name_string: service_parts,
        }))
        .build_tgs_req();

    let rep = send_recv_tgs(kdc_addr, &tgs_req)
        .map_err(|err| format!("Error sending TgsReq: {}", err))?;

    match rep {
        Rep::KrbError(krb_error) => {
            return handle_krb_error(&krb_error);
        }

        Rep::Raw(_) => {
            return Err(format!("Error parsing response"));
        }

        Rep::AsRep(_) => {
            return Err(format!(
                "Unexpected: server responded with AS-REP to TGS-REQ"
            ));
        }

        Rep::TgsRep(tgs_rep) => {
            let enc_tgs_as_rep_raw =
                decrypt_tgs_rep_enc_part(session_key, &tgs_rep.enc_part)?;

            let (_, enc_tgs_rep_part) =
                EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
                    .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

            let krb_cred_info = create_krb_cred_info(
                enc_tgs_rep_part.into(),
                tgs_rep.crealm,
                tgs_rep.cname,
            );

            krb_cred_plain.cred_part.ticket_info.push(krb_cred_info);
            krb_cred_plain.tickets.push(tgs_rep.ticket);

            save_cred_in_file(krb_cred_plain.into(), &cred_format, creds_file)?;
        }
    }

    return Ok(());
}

fn decrypt_tgs_rep_enc_part(
    session_key: &[u8],
    enc_part: &EncryptedData,
) -> Result<Vec<u8>, String> {
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
