//! Module to provide the operations required
//! in order to retrieve a ticket from the KDC 

use crate::cred_format::CredentialFormat;
use crate::error::Result;
use crate::file::parse_creds_file;
use crate::builders::KdcReqBuilder;
use crate::krb_cred_plain::{KrbCredPlain, TicketCredInfo};
use crate::krb_user::KerberosUser;
use crate::senders::{send_recv_as, send_recv_tgs};
use crate::transporter::KerberosTransporter;
use crate::utils::{
    create_krb_cred, create_krb_cred_info, username_to_principal_name,
};
use chrono::Utc;
use kerberos_asn1::{
    ApReq, AsRep, AsReq, Asn1Object, Authenticator, EncAsRepPart,
    EncTgsRepPart, EncryptedData, KrbCred, PaData, PaEncTsEnc, PaForUser,
    PaPacOptions, PrincipalName, TgsReq, Ticket,
};
use kerberos_constants;
use kerberos_constants::checksum_types;
use kerberos_constants::kdc_options;
use kerberos_constants::key_usages::{
    KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, KEY_USAGE_TGS_REQ_AUTHEN,
};
use kerberos_constants::pa_data_types::{
    PA_FOR_USER, PA_PAC_OPTIONS, PA_TGS_REQ,
};
use kerberos_constants::pa_pac_options;
use kerberos_constants::principal_names::{NT_SRV_INST, NT_UNKNOWN};
use kerberos_constants::{key_usages, pa_data_types};
use kerberos_crypto::{
    checksum_hmac_md5, new_kerberos_cipher, AesCipher, AesSizes,
    KerberosCipher, Key, Rc4Cipher,
};
use log::{info, warn};
use std::convert::TryInto;

/// Uses user credentials to request a TGT
pub fn request_tgt(
    user: &KerberosUser,
    user_key: &Key,
    preauth: bool,
    transporter: &dyn KerberosTransporter,
) -> Result<KrbCred> {
    let rep = request_as_rep(user, user_key, preauth, transporter)?;
    return extract_krb_cred_from_as_rep(rep, user, user_key);
}

/// Uses user credentials to obtain an AS-REP response
pub fn request_as_rep(
    user: &KerberosUser,
    user_key: &Key,
    preauth: bool,
    transporter: &dyn KerberosTransporter,
) -> Result<AsRep> {
    let as_req = build_as_req(user, user_key, preauth);
    return send_recv_as(transporter, &as_req);
}

/// Helper to easily craft an AS-REQ message for asking a TGT
/// from user data
fn build_as_req(user: &KerberosUser, user_key: &Key, preauth: bool) -> AsReq {
    let mut as_req_builder = KdcReqBuilder::new(user.realm.clone())
        .username(user.name.clone())
        .etypes(user_key.etypes())
        .request_pac();

    if preauth {
        let padata = create_pa_data_encrypted_timestamp(
            &user_key,
            &user.realm,
            &user.name,
        );
        as_req_builder = as_req_builder.push_padata(padata);
    }

    return as_req_builder.build_as_req();
}

fn extract_krb_cred_from_as_rep(
    as_rep: AsRep,
    user: &KerberosUser,
    user_key: &Key,
) -> Result<KrbCred> {
    let raw_enc_as_rep_part =
        decrypt_as_rep_enc_part(user, user_key, &as_rep.enc_part)?;

    let (_, enc_as_rep_part) = EncAsRepPart::parse(&raw_enc_as_rep_part)
        .map_err(|_| format!("Error decoding AS-REP"))?;

    return Ok(create_krb_cred(
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

/// Helper to create a PA-DATA that contains a PA-ENC-TS-ENC struct
fn create_pa_data_encrypted_timestamp(
    user_key: &Key,
    realm: &str,
    client_name: &str,
) -> PaData {
    let (encrypted_timestamp, etype) =
        create_encrypted_timestamp(user_key, realm, client_name);

    let padata = PaData::new(
        pa_data_types::PA_ENC_TIMESTAMP,
        EncryptedData::new(etype, None, encrypted_timestamp).build(),
    );

    return padata;
}

/// Helper to create an encrypted timestamp used by AS-REQ
/// to provide Kerberos preauthentication
fn create_encrypted_timestamp(
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

/// Helper to generate a cipher based on user credentials
/// and calculate the key when it is necessary
/// (in case of password)
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

/// Function to get a TGT from the credentials file
/// or request it if it is necessary
pub fn get_user_tgt(
    user: KerberosUser,
    creds_file: &str,
    user_key: Option<&Key>,
    transporter: &dyn KerberosTransporter,
    cred_format: CredentialFormat,
) -> Result<(KrbCredPlain, CredentialFormat, TicketCredInfo)> {
    match get_user_tgt_from_file(user.clone(), creds_file) {
        Ok(ok) => return Ok(ok),
        Err(err) => {
            warn!("No TGT found in {}: {}", creds_file, err);

            match user_key {
                Some(user_key) => {
                    info!("Request TGT for {}", user.name);
                    let krb_cred =
                        request_tgt(&user, user_key, true, transporter)?;
                    let krb_cred_plain: KrbCredPlain = krb_cred.try_into()?;

                    let ticket_cred_info =
                        krb_cred_plain.look_for_tgt(user.clone()).unwrap();

                    return Ok((krb_cred_plain, cred_format, ticket_cred_info));
                }
                None => {
                    return Err(
                        "Unable to request TGT without user credentials",
                    )?;
                }
            }
        }
    }
}

/// Try to get the TGT user from the credentials file
fn get_user_tgt_from_file(
    user: KerberosUser,
    creds_file: &str,
) -> Result<(KrbCredPlain, CredentialFormat, TicketCredInfo)> {
    let (krb_cred, cred_format) = parse_creds_file(creds_file)?;
    let krb_cred_plain: KrbCredPlain = krb_cred.try_into()?;

    let ticket_cred_info = krb_cred_plain
        .look_for_tgt(user.clone())
        .ok_or(format!("No TGT found for '{}", user.name))?;

    return Ok((krb_cred_plain, cred_format, ticket_cred_info));
}

/// Use a TGT to request a TGS
pub fn request_tgs(
    user: KerberosUser,
    service: String,
    ticket_info: TicketCredInfo,
    transporter: &dyn KerberosTransporter,
) -> Result<TicketCredInfo> {
    info!("Request {} TGS for {}", service, user.name);
    let session_key = ticket_info.cred_info.key.keyvalue.clone();
    let tgs_req = build_tgs_req(user, service, ticket_info)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(&session_key, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = create_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs).into());
}

/// Helper to easily craft a TGS-REQ message for asking a TGS
/// from user data and TGT
fn build_tgs_req(
    user: KerberosUser,
    service: String,
    ticket_info: TicketCredInfo,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &ticket_info.cred_info.key.keyvalue;
    let realm = user.realm.clone();

    let service_parts: Vec<String> =
        service.split("/").map(|s| s.to_string()).collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: service_parts,
    };

    padatas.push(create_pa_data_ap_req(
        user,
        ticket_info.ticket,
        session_key,
        ticket_info.cred_info.key.keytype,
    )?);

    let tgs_req = KdcReqBuilder::new(realm)
        .padatas(padatas)
        .sname(Some(sname))
        .build_tgs_req();

    return Ok(tgs_req);
}

/// Decrypts the TGS-REP enc-part by using the session key
fn decrypt_tgs_rep_enc_part(
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

/// Use a TGT to request a TGS for user itself on behalf other user
pub fn request_s4u2self(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    tgt: TicketCredInfo,
    transporter: &dyn KerberosTransporter,
) -> Result<TicketCredInfo> {
    info!(
        "Request {} S4U2Self TGS for {}",
        user.name, impersonate_user.name
    );
    let session_key = tgt.cred_info.key.keyvalue.clone();
    let tgs_req = build_s4u2self_req(user, impersonate_user, tgt)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(&session_key, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = create_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs).into());
}

/// Helper to easily craft a TGS-REQ message for S4U2Self
/// from user data and TGT
fn build_s4u2self_req(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    tgt: TicketCredInfo,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &tgt.cred_info.key.keyvalue;
    let realm = user.realm.clone();

    let sname = PrincipalName {
        name_type: NT_UNKNOWN,
        name_string: vec![user.name.clone()],
    };

    padatas.push(create_pa_data_pa_for_user(impersonate_user, session_key));

    padatas.push(create_pa_data_ap_req(
        user,
        tgt.ticket,
        session_key,
        tgt.cred_info.key.keytype,
    )?);

    let tgs_req = KdcReqBuilder::new(realm)
        .padatas(padatas)
        .sname(Some(sname))
        .build_tgs_req();

    return Ok(tgs_req);
}

/// Function to get a TGS of an impersonated user from file
/// or request it if it is necessary
pub fn get_impersonation_ticket(
    mut krb_cred_plain: KrbCredPlain,
    user: KerberosUser,
    impersonate_user: KerberosUser,
    transporter: &dyn KerberosTransporter,
    tgt: TicketCredInfo,
) -> Result<(KrbCredPlain, TicketCredInfo)> {
    let result = krb_cred_plain.look_for_impersonation_ticket(
        user.name.clone(),
        impersonate_user.name.clone(),
    );

    match result {
        Some(ticket_info) => {
            return Ok((krb_cred_plain, ticket_info));
        }
        None => {
            warn!(
                "No {} S4U2Self TGS for {} found",
                impersonate_user.name, user.name
            );
            let tgs_self =
                request_s4u2self(user, impersonate_user, tgt, transporter)?;
            krb_cred_plain.push(tgs_self.clone());

            return Ok((krb_cred_plain, tgs_self));
        }
    }
}

/// Use a TGT and TGS of impersonated user
/// to request a new TGS for a service on behalf the impersonated user
pub fn request_s4u2proxy(
    user: KerberosUser,
    impersonate_username: &str,
    service: String,
    tgt_info: TicketCredInfo,
    tgs_imp: Ticket,
    transporter: &dyn KerberosTransporter,
) -> Result<TicketCredInfo> {
    info!(
        "Request {} S4U2Proxy TGS for {}",
        service, impersonate_username
    );
    let session_key = tgt_info.cred_info.key.keyvalue.clone();
    let tgs_req = build_s4u2proxy_req(user, service, tgt_info, tgs_imp)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(&session_key, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = create_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs).into());
}

/// Helper to easily craft a TGS-REQ message for S4U2Proxy
/// from user data and TGT
fn build_s4u2proxy_req(
    user: KerberosUser,
    service: String,
    tgt_info: TicketCredInfo,
    tgs_imp: Ticket,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &tgt_info.cred_info.key.keyvalue;
    let realm = user.realm.clone();

    let service_parts: Vec<String> =
        service.split("/").map(|s| s.to_string()).collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: service_parts,
    };

    padatas.push(create_pa_data_pac_options(
        pa_pac_options::RESOURCE_BASED_CONSTRAINED_DELEGATION,
    ));

    padatas.push(create_pa_data_ap_req(
        user,
        tgt_info.ticket,
        session_key,
        tgt_info.cred_info.key.keytype,
    )?);

    let tgs_req = KdcReqBuilder::new(realm)
        .padatas(padatas)
        .sname(Some(sname))
        .push_ticket(tgs_imp)
        .add_kdc_option(kdc_options::CONSTRAINED_DELEGATION)
        .build_tgs_req();

    return Ok(tgs_req);
}

/// Helper to create a PA-DATA that contains a PA-FOR-USER struct
/// used in S4U2Self
fn create_pa_data_pa_for_user(
    impersonate_user: KerberosUser,
    session_key: &[u8],
) -> PaData {
    let pa_for_user = create_pa_for_user(impersonate_user, session_key);
    return PaData::new(PA_FOR_USER, pa_for_user.build());
}

/// Helper to easily create a PA-FOR-USER struct used in S4U2Self
fn create_pa_for_user(user: KerberosUser, session_key: &[u8]) -> PaForUser {
    let mut pa_for_user = PaForUser::default();
    pa_for_user.username = username_to_principal_name(user.name);
    pa_for_user.userrealm = user.realm;
    pa_for_user.auth_package = "Kerberos".to_string();

    let mut ck_value = pa_for_user.username.name_type.to_le_bytes().to_vec();
    ck_value
        .append(&mut pa_for_user.username.name_string[0].clone().into_bytes());
    ck_value.append(&mut pa_for_user.userrealm.clone().into_bytes());
    ck_value.append(&mut pa_for_user.auth_package.clone().into_bytes());

    let cksum = checksum_hmac_md5(
        session_key,
        KEY_USAGE_KERB_NON_KERB_CKSUM_SALT,
        &ck_value,
    );

    pa_for_user.cksum.cksumtype = checksum_types::HMAC_MD5;
    pa_for_user.cksum.checksum = cksum;

    return pa_for_user;
}

/// Helper to create a PA-DATA that contains a PA-PAC-OPTIONS struct
/// used in S4U2Proxy
fn create_pa_data_pac_options(pac_options: u32) -> PaData {
    let pac_options = PaPacOptions {
        kerberos_flags: pac_options.into(),
    };

    return PaData::new(PA_PAC_OPTIONS, pac_options.build());
}

/// Helper to create a PA-DATA that contains an AP-REQ struct
fn create_pa_data_ap_req(
    user: KerberosUser,
    ticket: Ticket,
    session_key: &[u8],
    etype: i32,
) -> Result<PaData> {
    let encrypted_authenticator =
        create_encrypted_authenticator(user, etype, session_key)?;

    let ap_req = create_ap_req(ticket, etype, encrypted_authenticator);
    return Ok(PaData::new(PA_TGS_REQ, ap_req.build()));
}

/// Helper to create an encrypt an Authenticator struct
/// that is contained in AP-REQ
fn create_encrypted_authenticator(
    user: KerberosUser,
    etype: i32,
    session_key: &[u8],
) -> Result<Vec<u8>> {
    let authenticator = create_authenticator(user);

    let cipher = new_kerberos_cipher(etype)
        .map_err(|_| format!("No supported etype: {}", etype))?;

    return Ok(cipher.encrypt(
        session_key,
        KEY_USAGE_TGS_REQ_AUTHEN,
        &authenticator.build(),
    ));
}

/// Helper to create an encrypt an Authenticator struct
fn create_authenticator(user: KerberosUser) -> Authenticator {
    let mut authenticator = Authenticator::default();
    authenticator.crealm = user.realm;
    authenticator.cname = username_to_principal_name(user.name);
    return authenticator;
}

/// Helper to create an AP-REQ struct
fn create_ap_req(ticket: Ticket, etype: i32, cipher: Vec<u8>) -> ApReq {
    let mut ap_req = ApReq::default();
    ap_req.ticket = ticket;
    ap_req.authenticator = EncryptedData {
        etype,
        kvno: None,
        cipher,
    };

    return ap_req;
}
