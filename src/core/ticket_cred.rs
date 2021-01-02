//! Structs to allow handle easier tickets and their associated KrbCredInfo

use crate::core::forge::{new_nt_principal, new_nt_srv_inst, new_nt_unknown};
use crate::core::KrbUser;
use crate::error::Error;
use kerberos_asn1::{
    Asn1Object, EncKrbCredPart, EncryptedData, KrbCred, KrbCredInfo,
    PrincipalName, Ticket,
};
use kerberos_constants::etypes::NO_ENCRYPTION;
use std::convert::TryFrom;
use std::slice::Iter;

#[derive(Debug)]
pub struct TicketCreds {
    pub ticket_creds: Vec<TicketCred>,
}

impl TicketCreds {
    pub fn new(ticket_creds: Vec<TicketCred>) -> Self {
        return Self { ticket_creds };
    }

    pub fn push(&mut self, ticket_info: TicketCred) {
        self.ticket_creds.push(ticket_info);
    }

    pub fn iter(&self) -> Iter<TicketCred> {
        return self.ticket_creds.iter();
    }

    pub fn len(&self) -> usize {
        return self.ticket_creds.len();
    }

    pub fn is_empty(&self) -> bool {
        return self.ticket_creds.is_empty();
    }

    pub fn get(&self, index: usize) -> Option<&TicketCred> {
        return self.ticket_creds.get(index);
    }

    pub fn filter<P>(&self, predicate: P) -> Self
    where
        P: Fn(&TicketCred) -> bool,
    {
        self.iter()
            .filter(|tci| predicate(tci))
            .cloned()
            .collect::<Vec<TicketCred>>()
            .into()
    }

    /// Filter tickets for etype
    pub fn etype(&self, etype: i32) -> Self {
        self.filter(|tci| tci.cred_info.key.keytype == etype)
    }

    /// Filter tickets for prealm (realm of the client). Case insensitive.
    pub fn prealm(&self, realm: &str) -> Self {
        self.filter(|tci| {
            if let Some(prealm) = tci.cred_info.prealm {
                return prealm.to_lowercase() == realm.to_lowercase();
            }
            return false;
        })
    }

    /// Filter tickets for pname (the name of the client). Case insensitive.
    pub fn pname(&self, name: &PrincipalName) -> Self {
        self.filter(|tci| {
            if let Some(pname) = &tci.cred_info.pname {
                return pname == name;
            }
            return false;
        })
    }

    /// Filter tickets for flags. All the tickets that includes the flags
    /// provided will match. The tickets can also have additional flags.
    pub fn flags(&self, flags: u32) -> Self {
        self.filter(|tci| {
            if let Some(ticket_flags) = &tci.cred_info.flags {
                return (ticket_flags.flags & flags) != 0;
            }
            return false;
        })
    }

    /// Filter tickets for srealm (realm of the service). Case insensitive.
    pub fn srealm(&self, realm: &str) -> Self {
        self.filter(|tci| {
            if let Some(srealm) = tci.cred_info.srealm {
                return srealm.to_lowercase() == realm.to_lowercase();
            }
            return false;
        })
    }

    /// Filter tickets for sname (the name of the service). Case insensitive.
    pub fn sname(&self, name: &PrincipalName) -> Self {
        self.filter(|tci| {
            if let Some(sname) = &tci.cred_info.sname {
                return sname == name;
            }
            return false;
        })
    }

    /// Filter tickets for user_realm. Same as prealm. Case insensitive.
    pub fn user_realm(&self, realm: &str) -> Self {
        return self.prealm(realm);
    }

    /// Filter for the username.
    pub fn username(&self, name: &str) -> Self {
        let pname = new_nt_principal(name);
        return self.pname(&pname);
    }

    /// Filter for the username and the user realm.
    pub fn user(&self, user: &KrbUser) -> Self {
        return self.user_realm(&user.realm).username(&user.name);
    }

    /// Filter to only return tickets that includes a given name in service. It
    /// could be the name of the service (e.g: http, cifs), the hostname or any
    /// other string that appears in the service name. Case insensitive.
    pub fn service_name(&self, name: &str) -> Self {
        let name_lower = name.to_lowercase();
        self.filter(|tci| {
            if let Some(sname) = &tci.cred_info.sname {
                return sname
                    .name_string
                    .iter()
                    .map(|s| s.to_lowercase())
                    .any(|s| s.to_lowercase() == name_lower);
            }
            return false;
        })
    }

    /// Filter to only returns TGTs.
    pub fn tgt(&self) -> Self {
        return self.service_name("krbtgt");
    }

    /// Filter to only returns TGTs for a given realm.
    pub fn tgt_realm(&self, realm: &str) -> Self {
        let tgt_service = new_nt_srv_inst(&format!("krbtgt/{}", realm));
        return self.sname(&tgt_service);
    }

    /// Filter to only returns TGTs for a given realm.
    pub fn user_tgt_realm(&self, user: &KrbUser, realm: &str) -> Self {
        return self.tgt_realm(realm).user(user);
    }

    pub fn look_for_tgt(&self, user: &KrbUser) -> Option<TicketCred> {
        let cname = new_nt_principal(&user.name);
        let tgt_service = new_nt_srv_inst(&format!("krbtgt/{}", user.realm));

        return self.look_for_user_creds(&cname, &tgt_service);
    }

    pub fn look_for_impersonation_ticket(
        &self,
        username: &str,
        impersonate_username: &str,
    ) -> Option<TicketCred> {
        let cname_imp = new_nt_principal(impersonate_username);
        let service_imp = new_nt_unknown(username);

        return self.look_for_user_creds(&cname_imp, &service_imp);
    }

    pub fn look_for_user_creds(
        &self,
        username: &PrincipalName,
        service: &PrincipalName,
    ) -> Option<TicketCred> {
        for tcred in self.ticket_creds.iter() {
            if let Some(pname) = &tcred.cred_info.pname {
                if let Some(sname) = &tcred.cred_info.sname {
                    if pname == username && sname == service {
                        return Some(tcred.clone());
                    }
                }
            }
        }

        return None;
    }
}

impl Into<KrbCred> for TicketCreds {
    fn into(self) -> KrbCred {
        let mut krb_cred = KrbCred::default();
        let mut tickets = Vec::with_capacity(self.ticket_creds.len());
        let mut cred_infos = Vec::with_capacity(self.ticket_creds.len());

        for ticket_cred_info in self.ticket_creds {
            tickets.push(ticket_cred_info.ticket);
            cred_infos.push(ticket_cred_info.cred_info);
        }

        krb_cred.tickets = tickets;
        let mut cred_part = EncKrbCredPart::default();
        cred_part.ticket_info = cred_infos;
        krb_cred.enc_part =
            EncryptedData::new(NO_ENCRYPTION, None, cred_part.build());
        return krb_cred;
    }
}

/// Convert from Kerberos credentials in plain text, the usual way of storing
/// them in machines. In case the credentials are encrypted this will fail.
impl TryFrom<KrbCred> for TicketCreds {
    type Error = Error;

    fn try_from(krb_cred: KrbCred) -> Result<Self, Error> {
        if krb_cred.enc_part.etype != NO_ENCRYPTION {
            return Err(Error::DataError(format!(
                "Unable to decrypt the credentials"
            )));
        }

        let (_, cred_part) = EncKrbCredPart::parse(&krb_cred.enc_part.cipher)
            .map_err(|_| {
            Error::DataError(format!(
                "Error parsing credentials: EncKrbCredPart"
            ))
        })?;

        let tickets = krb_cred.tickets;
        let cred_infos = cred_part.ticket_info;

        return Ok((tickets, cred_infos).into());
    }
}

impl From<(Vec<Ticket>, Vec<KrbCredInfo>)> for TicketCreds {
    fn from((tickets, cred_infos): (Vec<Ticket>, Vec<KrbCredInfo>)) -> Self {
        let mut ticket_cred_infos = Vec::with_capacity(tickets.len());

        for (ticket, cred_info) in
            tickets.into_iter().zip(cred_infos.into_iter())
        {
            ticket_cred_infos.push(TicketCred::new(ticket, cred_info));
        }

        return Self::new(ticket_cred_infos);
    }
}

impl From<Vec<TicketCred>> for TicketCreds {
    fn from(v: Vec<TicketCred>) -> Self {
        return Self::new(v);
    }
}

impl From<TicketCred> for TicketCreds {
    fn from(ticket_info: TicketCred) -> Self {
        return Self::new(vec![ticket_info]);
    }
}

/// Struct to store a ticket and the related user info, like the session key.
#[derive(Debug, Clone)]
pub struct TicketCred {
    pub ticket: Ticket,
    pub cred_info: KrbCredInfo,
}

impl TicketCred {
    pub fn new(ticket: Ticket, cred_info: KrbCredInfo) -> Self {
        return Self { ticket, cred_info };
    }
}

impl From<(Ticket, KrbCredInfo)> for TicketCred {
    fn from((t, kci): (Ticket, KrbCredInfo)) -> Self {
        return Self::new(t, kci);
    }
}
