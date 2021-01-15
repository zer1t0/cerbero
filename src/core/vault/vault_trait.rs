use crate::core::{CredFormat, TicketCred, TicketCreds};
use crate::KrbUser;
use crate::Result;

pub trait Vault {
    fn id(&self) -> &str;

    /// Returns the format used to store credentials in the vault support. It
    /// can be ccache or krb.
    fn support_cred_format(&self) -> Result<Option<CredFormat>>;

    /// Retrieve all the tickets.
    fn dump(&self) -> Result<TicketCreds>;

    /// Add a new ticket.
    fn add(&mut self, ticket_info: TicketCred) -> Result<()>;

    /// Saves the given tickets into the vault. The rest of the tickets are
    /// destroyed.
    fn save(&self, creds: TicketCreds) -> Result<()>;

    /// Saves the given tickets in the given format, if possible. The rest
    /// of the tickets are destroyed.
    fn save_as(
        &self,
        creds: TicketCreds,
        cred_format: CredFormat,
    ) -> Result<()>;

    /// Changes the support format to the one given.
    fn change_format(
        &self,
        cred_format: CredFormat,
    ) -> Result<()>;

    /// Retrieves the user TGTs (if many) for the user domain.
    fn get_user_tgts(&self, user: &KrbUser) -> Result<TicketCreds>;

    /// Retrieves the TGSs used for impersonation in s4u2self, part of the
    /// constrained delegation.
    fn s4u2self_tgss(
        &self,
        user: &KrbUser,
        impersonate_user: &KrbUser,
        user_service: Option<&String>,
    ) -> Result<TicketCreds>;
}
