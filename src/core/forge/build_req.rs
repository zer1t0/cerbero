use super::kdc_req::KdcReqBuilder;
use super::pa_data::{
    new_pa_data_ap_req, new_pa_data_encrypted_timestamp,
    new_pa_data_pa_for_user, new_pa_data_pac_options,
};
use super::principal_name::{new_nt_srv_inst, new_nt_unknown};
use crate::core::krb_cred_plain::TicketCredInfo;
use crate::core::krb_user::KerberosUser;
use crate::error::Result;
use kerberos_asn1::{
    AsReq, TgsReq, Ticket,
};
use kerberos_constants;
use kerberos_constants::{kdc_options, pa_pac_options};
use kerberos_crypto::{
    new_kerberos_cipher, AesCipher, AesSizes, KerberosCipher, Key, Rc4Cipher,
};



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
        let (cipher, key) =
            get_cipher_and_key(&user_key, &user.realm, &user.name);
        let padata =
            new_pa_data_encrypted_timestamp(cipher.etype(), &|u, b| {
                cipher.encrypt(&key, u, b)
            });
        as_req_builder = as_req_builder.push_padata(padata);
    }

    return as_req_builder.build_as_req();
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

/// Helper to easily craft a TGS-REQ message for asking a TGS
/// from user data and TGT
pub fn build_tgs_req(
    user: KerberosUser,
    service: &str,
    ticket_info: TicketCredInfo,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &ticket_info.cred_info.key.keyvalue;
    let etype = ticket_info.cred_info.key.keytype;
    let realm = user.realm.clone();
    let sname = new_nt_srv_inst(&service);

    let cipher = new_kerberos_cipher(etype)
        .map_err(|_| format!("No supported etype: {}", etype))?;

    padatas.push(new_pa_data_ap_req(
        user,
        ticket_info.ticket,
        etype,
        &|u, b| cipher.encrypt(&session_key, u, b),
    ));

    let tgs_req = KdcReqBuilder::new(realm)
        .padatas(padatas)
        .sname(Some(sname))
        .build_tgs_req();

    return Ok(tgs_req);
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
    let realm = user.realm.clone();
    let sname = new_nt_srv_inst(service);

    padatas.push(new_pa_data_pac_options(
        pa_pac_options::RESOURCE_BASED_CONSTRAINED_DELEGATION,
    ));

    let session_key = &tgt_info.cred_info.key.keyvalue;
    let etype = tgt_info.cred_info.key.keytype;
    let cipher = new_kerberos_cipher(etype)
        .map_err(|_| format!("No supported etype: {}", etype))?;

    padatas.push(new_pa_data_ap_req(user, tgt_info.ticket, etype, &|u, b| {
        cipher.encrypt(&session_key, u, b)
    }));

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
    let etype = tgt.cred_info.key.keytype;
    let realm = user.realm.clone();
    let sname = new_nt_unknown(&user.name);

    padatas.push(new_pa_data_pa_for_user(impersonate_user, session_key));

    let cipher = new_kerberos_cipher(etype)
        .map_err(|_| format!("No supported etype: {}", etype))?;

    padatas.push(new_pa_data_ap_req(user, tgt.ticket, etype, &|u, b| {
        cipher.encrypt(&session_key, u, b)
    }));

    let tgs_req = KdcReqBuilder::new(realm)
        .padatas(padatas)
        .sname(Some(sname))
        .build_tgs_req();

    return Ok(tgs_req);
}
