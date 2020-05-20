use super::kdc_req::KdcReqBuilder;
use crate::core::krb_cred_plain::TicketCredInfo;
use crate::core::krb_user::KerberosUser;
use crate::error::Result;
use kerberos_asn1::{
    AsRep, AsReq, Asn1Object, EncAsRepPart, EncryptedData, TgsReq, Ticket,
};
use kerberos_asn1::{
    EncKdcRepPart, EncKrbCredPart, KrbCred, KrbCredInfo, PrincipalName,
};
use kerberos_constants;
use kerberos_constants::{
    etypes, kdc_options, key_usages, pa_pac_options, principal_names,
};
use kerberos_crypto::{new_kerberos_cipher, Key};

use super::pa_data::{
    create_pa_data_ap_req, create_pa_data_encrypted_timestamp,
    create_pa_data_pac_options, create_pa_data_pa_for_user
};
use super::principal_name::{
    new_nt_srv_inst
};

pub fn create_krb_cred(
    enc_as_rep_part: EncKdcRepPart,
    ticket: Ticket,
    prealm: String,
    pname: PrincipalName,
) -> KrbCred {
    let krb_cred_info = create_krb_cred_info(enc_as_rep_part, prealm, pname);

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

pub fn create_krb_cred_info(
    enc_as_rep_part: EncKdcRepPart,
    prealm: String,
    pname: PrincipalName,
) -> KrbCredInfo {
    return KrbCredInfo {
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
}

/// Helper to easily craft a TGS-REQ message for asking a TGS
/// from user data and TGT
pub fn build_tgs_req(
    user: KerberosUser,
    service: &str,
    ticket_info: TicketCredInfo,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &ticket_info.cred_info.key.keyvalue;
    let realm = user.realm.clone();
    let sname = new_nt_srv_inst(&service);

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

/// Helper to easily craft an AS-REQ message for asking a TGT
/// from user data
pub fn build_as_req(
    user: &KerberosUser,
    user_key: &Key,
    preauth: bool,
) -> AsReq {
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

pub fn extract_krb_cred_from_as_rep(
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

/// Helper to easily craft a TGS-REQ message for S4U2Proxy
/// from user data and TGT
pub fn build_s4u2proxy_req(
    user: KerberosUser,
    service: &str,
    tgt_info: TicketCredInfo,
    tgs_imp: Ticket,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &tgt_info.cred_info.key.keyvalue;
    let realm = user.realm.clone();
    let sname = new_nt_srv_inst(service);
    

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

/// Helper to easily craft a TGS-REQ message for S4U2Self
/// from user data and TGT
pub fn build_s4u2self_req(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    tgt: TicketCredInfo,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &tgt.cred_info.key.keyvalue;
    let realm = user.realm.clone();

    let sname = PrincipalName {
        name_type: principal_names::NT_UNKNOWN,
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
