use super::principal_name::new_nt_principal;
use crate::core::forge::KerberosUser;
use chrono::Utc;
use kerberos_asn1::{
    ApReq, Asn1Object, Authenticator, EncryptedData, PaData, PaEncTsEnc,
    PaForUser, PaPacOptions, Ticket,
};
use kerberos_constants;
use kerberos_constants::key_usages::{
    KEY_USAGE_AS_REQ_TIMESTAMP, KEY_USAGE_KERB_NON_KERB_CKSUM_SALT,
    KEY_USAGE_TGS_REQ_AUTHEN,
};
use kerberos_constants::pa_data_types::{
    PA_FOR_USER, PA_PAC_OPTIONS, PA_TGS_REQ,
};
use kerberos_constants::{checksum_types, pa_data_types};
use kerberos_crypto::checksum_hmac_md5;

/// Helper to create a PA-DATA that contains a PA-ENC-TS-ENC struct
pub fn new_pa_data_encrypted_timestamp(
    etype: i32,
    encrypt: &dyn Fn(i32, &[u8]) -> Vec<u8>,
) -> PaData {
    let timestamp = PaEncTsEnc::from(Utc::now());
    let encrypted_timestamp =
        encrypt(KEY_USAGE_AS_REQ_TIMESTAMP, &timestamp.build());
    let padata = PaData::new(
        pa_data_types::PA_ENC_TIMESTAMP,
        EncryptedData::new(etype, None, encrypted_timestamp).build(),
    );

    return padata;
}

/// Helper to create a PA-DATA that contains a PA-FOR-USER struct
/// used in S4U2Self
pub fn new_pa_data_pa_for_user(
    impersonate_user: KerberosUser,
    session_key: &[u8],
) -> PaData {
    let pa_for_user = new_pa_for_user(impersonate_user, session_key);
    return PaData::new(PA_FOR_USER, pa_for_user.build());
}

/// Helper to easily create a PA-FOR-USER struct used in S4U2Self
fn new_pa_for_user(user: KerberosUser, session_key: &[u8]) -> PaForUser {
    let mut pa_for_user = PaForUser::default();
    pa_for_user.username = new_nt_principal(&user.name);
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
pub fn new_pa_data_pac_options(pac_options: u32) -> PaData {
    let pac_options = PaPacOptions {
        kerberos_flags: pac_options.into(),
    };

    return PaData::new(PA_PAC_OPTIONS, pac_options.build());
}

/// Helper to create a PA-DATA that contains an AP-REQ struct
pub fn new_pa_data_ap_req(
    user: KerberosUser,
    ticket: Ticket,
    etype: i32,
    encrypt: &dyn Fn(i32, &[u8]) -> Vec<u8>,
) -> PaData {
    let authenticator = new_authenticator(user);

    let encrypted_authenticator =
        encrypt(KEY_USAGE_TGS_REQ_AUTHEN, &authenticator.build());

    let ap_req = new_ap_req(ticket, etype, encrypted_authenticator);
    return PaData::new(PA_TGS_REQ, ap_req.build());
}

/// Helper to create an encrypt an Authenticator struct
fn new_authenticator(user: KerberosUser) -> Authenticator {
    let mut authenticator = Authenticator::default();
    authenticator.crealm = user.realm;
    authenticator.cname = new_nt_principal(&user.name);
    return authenticator;
}

/// Helper to create an AP-REQ struct
fn new_ap_req(ticket: Ticket, etype: i32, cipher: Vec<u8>) -> ApReq {
    let mut ap_req = ApReq::default();
    ap_req.ticket = ticket;
    ap_req.authenticator = EncryptedData {
        etype,
        kvno: None,
        cipher,
    };

    return ap_req;
}
