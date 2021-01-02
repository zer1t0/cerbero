use crate::core::{CredFormat, TicketCreds, TicketCred};
use crate::KrbUser;
use crate::Result;

pub trait Vault {
    fn id(&self) -> &str;

    /// Returns the format used to store credentials in the vault support. It
    /// can be ccache or krb.
    fn support_cred_format(&self) -> Result<Option<CredFormat>>;

    /// Retrieves the user TGTs (if many) for the user domain.
    fn get_user_tgts(
        &self,
        user: &KrbUser,
    ) -> Result<TicketCreds>;

    /// Retrieve all the tickets.
    fn dump(&self) -> Result<TicketCreds>;


    /// Add a new ticket.
    fn add(&mut self, ticket_info: TicketCred) -> Result<()>;

    /// Saves the given tickets into the vault. The rest of the tickets are
    /// destroyed.
    fn save(
        &self,
        creds: TicketCreds,
    ) -> Result<()>;

    /// Saves the given tickets in the given format, if possible. The rest
    /// of the tickets are destroyed.
    fn save_as(
        &self,
        creds: TicketCreds,
        cred_format: CredFormat,
    ) -> Result<()>;
}
