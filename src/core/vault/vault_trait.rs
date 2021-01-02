use crate::core::{CredFormat, TicketCreds, TicketCred};
use crate::KrbUser;
use crate::Result;

pub trait Vault {
    fn id(&self) -> &str;
    fn get_cred_format(&self) -> Result<CredFormat>;
    fn get_user_tgt(
        &self,
        user: &KrbUser,
    ) -> Result<Option<TicketCred>>;
    fn dump(&self) -> Result<TicketCreds>;

    fn append_ticket(&mut self, ticket_info: TicketCred) -> Result<()>;

    fn save(
        &self,
        creds: TicketCreds,
        cred_format: Option<CredFormat>,
    ) -> Result<()>;
}
