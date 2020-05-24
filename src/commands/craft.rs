use crate::KerberosUser;
use crate::Result;
use kerberos_asn1::{EncryptionKey, EncTicketPart, PrincipalName, Ticket, TransitedEncoding, AuthorizationData};
use kerberos_constants::etypes;
use kerberos_constants::ticket_flags;
use kerberos_crypto::Key;
use crate::core::new_nt_principal;
use chrono::{Duration, Utc};

pub fn craft(
    user: KerberosUser,
    service: Option<String>,
    etype: Option<i32>,
) -> Result<()> {
    let mut ticket_builder = EncTicketPartBuilder::new(&user.name, user.realm);

    if service.is_some() {
        ticket_builder = ticket_builder.add_flag(ticket_flags::INITIAL);
    }

    if let Some(etype) = etype {
        ticket_builder = ticket_builder.random_key(etype);
    }

    return Ok(());
}

pub struct EncTicketPartBuilder {
    ticket_flags: u32,
    key: EncryptionKey,
    crealm: String,
    cname: PrincipalName,
    authorization_data: Option<AuthorizationData> 
}

impl EncTicketPartBuilder {
    pub fn new(username: &str, realm: String) -> Self {
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


    pub fn build(self) -> EncTicketPart {
        let now = Utc::now();
        let expiration_time = now.checked_add_signed(Duration::weeks(20 * 52)).unwrap();
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
        }
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
