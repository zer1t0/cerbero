use super::Vault;
use crate::core::CredentialFormat;
use crate::core::KrbCredPlain;
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

    fn load(&self) -> Result<(KrbCredPlain, CredentialFormat)> {
        return Ok((KrbCredPlain::new(Vec::new()), CredentialFormat::Krb));
    }

    fn save(&self, _: KrbCredPlain, _: CredentialFormat) -> Result<()> {
        return Ok(());
    }
}
