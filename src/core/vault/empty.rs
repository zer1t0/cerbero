use super::Vault;
use crate::core::CredFormat;
use crate::core::{KrbUser, TicketCred, TicketCreds};
use crate::Result;

pub struct EmptyVault {
    ticket_creds: TicketCreds,
}

impl EmptyVault {
    pub fn new() -> Self {
        return Self {
            ticket_creds: TicketCreds::empty(),
        };
    }
}

impl Vault for EmptyVault {
    fn id(&self) -> &str {
        return "Nowhere";
    }

    fn support_cred_format(&self) -> Result<Option<CredFormat>> {
        return Ok(None);
    }

    fn get_user_tgts(&self, user: &KrbUser) -> Result<TicketCreds> {
        return Ok(self.ticket_creds.user_tgt_realm(user, &user.realm));
    }

    fn add(&mut self, ticket_info: TicketCred) -> Result<()> {
        self.ticket_creds.push(ticket_info);
        return Ok(());
    }

    fn dump(&self) -> Result<TicketCreds> {
        return Ok(self.ticket_creds.clone());
    }

    fn save(&self, _: TicketCreds) -> Result<()> {
        return Ok(());
    }

    fn save_as(&self, _: TicketCreds, _: CredFormat) -> Result<()> {
        return Ok(());
    }
}
