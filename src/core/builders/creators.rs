use crate::core::krb_user::KerberosUser;
use crate::error::Result;
use chrono::Utc;
use kerberos_asn1::{
    ApReq, Asn1Object, Authenticator, EncryptedData, PaData, PaEncTsEnc,
    PaForUser, PaPacOptions, Ticket,
};
use kerberos_asn1::{
    EncKdcRepPart, EncKrbCredPart, KrbCred, KrbCredInfo, PrincipalName,
};
use kerberos_constants;
use kerberos_constants::key_usages::{
    KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, KEY_USAGE_TGS_REQ_AUTHEN,
};
use kerberos_constants::pa_data_types::{
    PA_FOR_USER, PA_PAC_OPTIONS, PA_TGS_REQ,
};
use kerberos_constants::{
    checksum_types, etypes, key_usages, pa_data_types, principal_names,
};
use kerberos_crypto::{
    checksum_hmac_md5, new_kerberos_cipher, AesCipher, AesSizes,
    KerberosCipher, Key, Rc4Cipher,
};

pub fn username_to_principal_name(username: String) -> PrincipalName {
    return PrincipalName {
        name_type: principal_names::NT_PRINCIPAL,
        name_string: vec![username],
    };
}

pub fn gen_krbtgt_principal_name(
    realm: String,
    name_type: i32,
) -> PrincipalName {
    return PrincipalName {
        name_type,
        name_string: vec!["krbtgt".into(), realm],
    };
}

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
