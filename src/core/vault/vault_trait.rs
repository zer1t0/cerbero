use crate::Result;
use crate::core::{KrbCredPlain, CredentialFormat};

pub trait Vault {
    fn id(&self) -> &String;
    fn load(&self) -> Result<(KrbCredPlain, CredentialFormat)>;
    fn save(&self, creds: KrbCredPlain, cred_format: CredentialFormat) -> Result<()>;
}
