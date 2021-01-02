use super::Vault;
use crate::core::CredFormat;
use crate::core::{KrbUser, TicketCreds, TicketCred};
use crate::Result;

pub struct EmptyVault {}

impl EmptyVault {
    pub fn new() -> Self {
        return Self {};
    }
}

impl Vault for EmptyVault {
    fn id(&self) -> &str {
        return "Nowhere";
    }

    fn get_cred_format(&self) -> Result<CredFormat> {
        return Ok(CredFormat::Ccache);
    }

    fn get_user_tgt(&self, _: &KrbUser) -> Result<Option<TicketCred>> {
        return Ok(None);
    }

    fn append_ticket(&mut self, ticket_info: TicketCred) -> Result<()> {
        return Ok(());
    }

    fn dump(&self) -> Result<TicketCreds> {
        return Ok(TicketCreds::new(Vec::new()));
    }

    fn save(&self, _: TicketCreds, _: Option<CredFormat>) -> Result<()> {
        return Ok(());
    }
}
