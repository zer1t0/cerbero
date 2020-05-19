use super::ask_tgt::request_tgt;
use crate::cred_format::CredentialFormat;
use crate::error::Result;
use crate::file::{parse_creds_file, save_cred_in_file};
use crate::kdc_req_builder::KdcReqBuilder;
use crate::krb_cred_plain::KrbCredPlain;
use crate::krb_user::KerberosUser;
use crate::senders::send_recv_tgs;
use crate::transporter::KerberosTransporter;
use crate::utils::{create_krb_cred_info, username_to_principal_name};
use kerberos_asn1::{
    ApReq, Asn1Object, Authenticator, EncTgsRepPart, EncryptedData,
    KrbCredInfo, PaData, PaForUser, PaPacOptions, PrincipalName,
    TgsReq, Ticket,
};
use kerberos_constants::checksum_types;
use kerberos_constants::kdc_options;
use kerberos_constants::key_usages;
use kerberos_constants::key_usages::{
    KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, KEY_USAGE_TGS_REQ_AUTHEN,
};
use kerberos_constants::pa_data_types::PA_PAC_OPTIONS;
use kerberos_constants::pa_data_types::{PA_FOR_USER, PA_TGS_REQ};
use kerberos_constants::pa_pac_options;
use kerberos_constants::principal_names::{NT_SRV_INST, NT_UNKNOWN};
use kerberos_crypto::{checksum_hmac_md5, new_kerberos_cipher, Key};
use log::{info, warn};

/// Main function to request a new TGS for a user for the selected service
pub fn ask_tgs(
    user: KerberosUser,
    service: String,
    creds_file: &str,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredentialFormat,
) -> Result<()> {
    let username = user.name.clone();
    let service_copy = service.clone();
    let (mut krb_cred_plain, cred_format, ticket, krb_cred_info) =
        get_user_tgt(
            user.clone(),
            creds_file,
            user_key,
            transporter,
            cred_format,
        )?;

    let (tgs, krb_cred_info_tgs) = request_tgs(
        user,
        service,
        &krb_cred_info,
        ticket.clone(),
        transporter,
    )?;

    krb_cred_plain.cred_part.ticket_info.push(krb_cred_info_tgs);
    krb_cred_plain.tickets.push(tgs);

    info!(
        "Save {} TGS for {} in {}",
        username, service_copy, creds_file
    );
    save_cred_in_file(creds_file, krb_cred_plain.into(), cred_format)?;

    return Ok(());
}

/// Function to get a TGT from the credentials file
/// or request it if it is necessary
pub fn get_user_tgt(
    user: KerberosUser,
    creds_file: &str,
    user_key: Option<&Key>,
    transporter: &dyn KerberosTransporter,
    cred_format: CredentialFormat,
) -> Result<(KrbCredPlain, CredentialFormat, Ticket, KrbCredInfo)> {
    match get_user_tgt_from_file(user.clone(), creds_file) {
        Ok(ok) => return Ok(ok),
        Err(err) => {
            warn!("No TGT found in {}: {}", creds_file, err);

            match user_key {
                Some(user_key) => {
                    info!("Request TGT for {}", user.name);
                    let krb_cred =
                        request_tgt(&user, user_key, true, transporter)?;
                    let krb_cred_plain =
                        KrbCredPlain::try_from_krb_cred(krb_cred)?;

                    let (ticket, krb_cred_info) =
                        krb_cred_plain.look_for_tgt(user.clone()).unwrap();

                    return Ok((
                        krb_cred_plain,
                        cred_format,
                        ticket,
                        krb_cred_info,
                    ));
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
) -> Result<(KrbCredPlain, CredentialFormat, Ticket, KrbCredInfo)> {
    let (krb_cred, cred_format) = parse_creds_file(creds_file)?;
    let krb_cred_plain = KrbCredPlain::try_from_krb_cred(krb_cred)?;

    let (ticket, krb_cred_info) = krb_cred_plain
        .look_for_tgt(user.clone())
        .ok_or(format!("No TGT found for '{}", user.name))?;

    return Ok((krb_cred_plain, cred_format, ticket, krb_cred_info));
}

/// Use a TGT to request a TGS
pub fn request_tgs(
    user: KerberosUser,
    service: String,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
    transporter: &dyn KerberosTransporter,
) -> Result<(Ticket, KrbCredInfo)> {
    info!("Request {} TGS for {}", service, user.name);
    let session_key = &krb_cred_info.key.keyvalue;
    let tgs_req = build_tgs_req(user, service, krb_cred_info, ticket)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(session_key, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = create_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs));
}

/// Helper to easily craft a TGS-REQ message for asking a TGS
/// from user data and TGT
fn build_tgs_req(
    user: KerberosUser,
    service: String,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &krb_cred_info.key.keyvalue;
    let realm = user.realm.clone();

    let service_parts: Vec<String> =
        service.split("/").map(|s| s.to_string()).collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: service_parts,
    };

    padatas.push(create_pa_data_ap_req(
        user,
        ticket,
        session_key,
        krb_cred_info.key.keytype,
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

/// Main function to perform an S4U2Self operation
pub fn ask_s4u2self(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    creds_file: &str,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredentialFormat,
) -> Result<()> {
    let imp_username = impersonate_user.name.clone();
    let username = user.name.clone();
    let (mut krb_cred_plain, cred_format, ticket, krb_cred_info) =
        get_user_tgt(
            user.clone(),
            creds_file,
            user_key,
            transporter,
            cred_format,
        )?;

    let (tgs, krb_cred_info_tgs) = request_s4u2self(
        user,
        impersonate_user,
        &krb_cred_info,
        ticket.clone(),
        transporter,
    )?;

    krb_cred_plain.cred_part.ticket_info.push(krb_cred_info_tgs);
    krb_cred_plain.tickets.push(tgs);

    info!(
        "Save {} S4U2Self TGS for {} in {}",
        imp_username, username, creds_file
    );
    save_cred_in_file(creds_file, krb_cred_plain.into(), cred_format)?;

    return Ok(());
}

/// Use a TGT to request a TGS for user itself on behalf other user
fn request_s4u2self(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
    transporter: &dyn KerberosTransporter,
) -> Result<(Ticket, KrbCredInfo)> {
    info!(
        "Request {} S4U2Self TGS for {}",
        user.name, impersonate_user.name
    );
    let session_key = &krb_cred_info.key.keyvalue;
    let tgs_req =
        build_s4u2self_req(user, impersonate_user, krb_cred_info, ticket)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(session_key, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = create_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs));
}

/// Helper to easily craft a TGS-REQ message for S4U2Self
/// from user data and TGT
fn build_s4u2self_req(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &krb_cred_info.key.keyvalue;
    let realm = user.realm.clone();

    let sname = PrincipalName {
        name_type: NT_UNKNOWN,
        name_string: vec![user.name.clone()],
    };

    padatas.push(create_pa_data_pa_for_user(impersonate_user, session_key));

    padatas.push(create_pa_data_ap_req(
        user,
        ticket,
        session_key,
        krb_cred_info.key.keytype,
    )?);

    let tgs_req = KdcReqBuilder::new(realm)
        .padatas(padatas)
        .sname(Some(sname))
        .build_tgs_req();

    return Ok(tgs_req);
}

/// Main function to perform an S4U2Proxy operation
pub fn ask_s4u2proxy(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    service: String,
    creds_file: &str,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredentialFormat,
) -> Result<()> {
    let imp_username = impersonate_user.name.clone();
    let service_copy = service.clone();
    let (krb_cred_plain, cred_format, tgt, krb_cred_info) = get_user_tgt(
        user.clone(),
        creds_file,
        user_key,
        transporter,
        cred_format,
    )?;

    let (mut krb_cred_plain, imp_ticket) = get_impersonation_ticket(
        krb_cred_plain,
        user.clone(),
        impersonate_user,
        transporter,
        &krb_cred_info,
        tgt.clone(),
    )?;

    let (tgs, krb_cred_info_tgs) = request_s4u2proxy(
        user,
        &imp_username,
        service,
        &krb_cred_info,
        tgt,
        imp_ticket,
        transporter,
    )?;

    krb_cred_plain.cred_part.ticket_info.push(krb_cred_info_tgs);
    krb_cred_plain.tickets.push(tgs);

    info!(
        "Save {} S4U2Proxy TGS for {} in {}",
        imp_username, service_copy, creds_file
    );
    save_cred_in_file(creds_file, krb_cred_plain.into(), cred_format)?;

    return Ok(());
}

/// Function to get a TGS of an impersonated user from file
/// or request it if it is necessary
fn get_impersonation_ticket(
    mut krb_cred_plain: KrbCredPlain,
    user: KerberosUser,
    impersonate_user: KerberosUser,
    transporter: &dyn KerberosTransporter,
    krb_cred_info: &KrbCredInfo,
    tgt: Ticket,
) -> Result<(KrbCredPlain, Ticket)> {
    let result = krb_cred_plain.look_for_impersonation_ticket(
        user.name.clone(),
        impersonate_user.name.clone(),
    );

    match result {
        Some((imp_ticket, _)) => {
            return Ok((krb_cred_plain, imp_ticket));
        }
        None => {
            warn!(
                "No {} S4U2Self TGS for {} found",
                impersonate_user.name, user.name
            );
            let (imp_ticket, krb_cred_info_tgs) = request_s4u2self(
                user,
                impersonate_user,
                &krb_cred_info,
                tgt,
                transporter,
            )?;

            krb_cred_plain.cred_part.ticket_info.push(krb_cred_info_tgs);
            krb_cred_plain.tickets.push(imp_ticket.clone());

            return Ok((krb_cred_plain, imp_ticket));
        }
    }
}

/// Use a TGT and TGS of impersonated user
/// to request a new TGS for a service on behalf the impersonated user
fn request_s4u2proxy(
    user: KerberosUser,
    impersonate_username: &str,
    service: String,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
    ticket_imp: Ticket,
    transporter: &dyn KerberosTransporter,
) -> Result<(Ticket, KrbCredInfo)> {
    info!(
        "Request {} S4U2Proxy TGS for {}",
        service, impersonate_username
    );
    let session_key = &krb_cred_info.key.keyvalue;
    let tgs_req =
        build_s4u2proxy_req(user, service, krb_cred_info, ticket, ticket_imp)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(session_key, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = create_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs));
}

/// Helper to easily craft a TGS-REQ message for S4U2Proxy
/// from user data and TGT
fn build_s4u2proxy_req(
    user: KerberosUser,
    service: String,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
    ticket_imp: Ticket,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &krb_cred_info.key.keyvalue;
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
        ticket,
        session_key,
        krb_cred_info.key.keytype,
    )?);

    let tgs_req = KdcReqBuilder::new(realm)
        .padatas(padatas)
        .sname(Some(sname))
        .push_ticket(ticket_imp)
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
