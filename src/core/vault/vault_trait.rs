use crate::core::{CredentialFormat, KrbCredPlain};
use crate::Result;

pub trait Vault {
    fn id(&self) -> &str;
    fn load(&self) -> Result<(KrbCredPlain, CredentialFormat)>;
    fn save(
        &self,
        creds: KrbCredPlain,
        cred_format: CredentialFormat,
    ) -> Result<()>;
}
