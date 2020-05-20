use std::slice::Iter;
use crate::core::KerberosUser;
use crate::utils::gen_krbtgt_principal_name;
use crate::utils::username_to_principal_name;
use kerberos_asn1::{
    Asn1Object, EncKrbCredPart, EncryptedData, KrbCred, KrbCredInfo,
    PrincipalName, Ticket,
};
use kerberos_constants::etypes::NO_ENCRYPTION;
use kerberos_constants::principal_names::NT_SRV_INST;
use kerberos_constants::principal_names::NT_UNKNOWN;
use std::convert::TryFrom;

pub struct KrbCredPlain {
    pub ticket_cred_infos: Vec<TicketCredInfo>,
}

impl KrbCredPlain {
    pub fn new(ticket_cred_infos: Vec<TicketCredInfo>) -> Self {
        return Self { ticket_cred_infos };
    }

    pub fn push(&mut self, ticket_info: TicketCredInfo) {
        self.ticket_cred_infos.push(ticket_info);
    }

    pub fn iter(&self) -> Iter<TicketCredInfo> {
        return self.ticket_cred_infos.iter();
    }

    pub fn look_for_user_creds(
        &self,
        username: &PrincipalName,
        service: &PrincipalName,
    ) -> Option<TicketCredInfo> {
        for tcred in self.ticket_cred_infos.iter() {
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

    pub fn look_for_tgt(&self, user: KerberosUser) -> Option<TicketCredInfo> {
        let cname = username_to_principal_name(user.name);
        let tgt_service = gen_krbtgt_principal_name(user.realm, NT_SRV_INST);

        return self.look_for_user_creds(&cname, &tgt_service);
    }

    pub fn look_for_impersonation_ticket(
        &self,
        username: String,
        impersonate_username: String,
    ) -> Option<TicketCredInfo> {
        let cname_imp = username_to_principal_name(impersonate_username);
        let service_imp = PrincipalName {
            name_type: NT_UNKNOWN,
            name_string: vec![username],
        };

        return self.look_for_user_creds(&cname_imp, &service_imp);
    }
}

impl Into<KrbCred> for KrbCredPlain {
    fn into(self) -> KrbCred {
        let mut krb_cred = KrbCred::default();
        let mut tickets = Vec::with_capacity(self.ticket_cred_infos.len());
        let mut cred_infos = Vec::with_capacity(self.ticket_cred_infos.len());

        for ticket_cred_info in self.ticket_cred_infos {
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

impl TryFrom<KrbCred> for KrbCredPlain {
    type Error = String;

    fn try_from(krb_cred: KrbCred) -> Result<Self, String> {
        if krb_cred.enc_part.etype != NO_ENCRYPTION {
            return Err(format!("Unable to decrypt the credentials"));
        }

        let (_, cred_part) = EncKrbCredPart::parse(&krb_cred.enc_part.cipher)
            .map_err(|_| {
            format!("Error parsing credentials: EncKrbCredPart")
        })?;

        let tickets = krb_cred.tickets;
        let cred_infos = cred_part.ticket_info;

        return Ok((tickets, cred_infos).into());
    }
}

impl From<(Vec<Ticket>, Vec<KrbCredInfo>)> for KrbCredPlain {
    fn from((tickets, cred_infos): (Vec<Ticket>, Vec<KrbCredInfo>)) -> Self {
        let mut ticket_cred_infos = Vec::with_capacity(tickets.len());

        for (ticket, cred_info) in
            tickets.into_iter().zip(cred_infos.into_iter())
        {
            ticket_cred_infos.push(TicketCredInfo::new(ticket, cred_info));
        }

        return Self::new(ticket_cred_infos);
    }
}

#[derive(Debug, Clone)]
pub struct TicketCredInfo {
    pub ticket: Ticket,
    pub cred_info: KrbCredInfo,
}

impl TicketCredInfo {
    pub fn new(ticket: Ticket, cred_info: KrbCredInfo) -> Self {
        return Self { ticket, cred_info };
    }
}

impl From<(Ticket, KrbCredInfo)> for TicketCredInfo {
    fn from((t, kci): (Ticket, KrbCredInfo)) -> Self {
        return Self::new(t,kci);
    }
}
