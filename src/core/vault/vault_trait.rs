use crate::core::{CredentialFormat, KrbCredPlain};
use crate::Result;

pub trait Vault {
    fn id(&self) -> &str;
    // fn get_user_tgt(
    //    &self,
    //    user: &KerberosUser,
    // ) -> Result<Option<TicketCredInfo>>;
    fn dump(&self) -> Result<(KrbCredPlain, CredentialFormat)>;
    fn save(
        &self,
        creds: KrbCredPlain,
        cred_format: CredentialFormat,
    ) -> Result<()>;
}
