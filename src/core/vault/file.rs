use super::Vault;
use crate::core::CredentialFormat;
use crate::core::KrbCredPlain;
use crate::Result;
use kerberos_asn1::{Asn1Object, KrbCred};
use kerberos_ccache::CCache;
use std::convert::{TryInto, TryFrom};
use std::fs;

pub struct FileVault {
    file_path: String,
}

impl FileVault {
    pub fn new(file_path: String) -> Self {
        return Self { file_path };
    }
}

impl Vault for FileVault {
    fn id(&self) -> &String {
        return &self.file_path;
    }
        
    fn load(&self) -> Result<(KrbCredPlain, CredentialFormat)> {
        return load_file_creds(&self.file_path);
    }

    fn save(&self, creds: KrbCredPlain, cred_format: CredentialFormat) -> Result<()> {
        return save_file_creds(&self.file_path, creds, cred_format);
    }
}

pub fn load_file_creds(
    creds_file: &str,
) -> Result<(KrbCredPlain, CredentialFormat)> {
    let (krb_cred, cred_format) = load_file_krb_cred(&creds_file)?;
    let creds = KrbCredPlain::try_from(krb_cred)?;
    return Ok((creds, cred_format));
}

pub fn load_file_krb_cred(
    creds_file: &str,
) -> Result<(KrbCred, CredentialFormat)> {
    let data = fs::read(creds_file).map_err(|err| {
        format!("Unable to read the file '{}': {}", creds_file, err)
    })?;

    match CCache::parse(&data) {
        Ok((_, ccache)) => {
            let krb_cred = ccache.try_into().map_err(|_| {
                format!(
                    "Error parsing ccache data content of file '{}'",
                    creds_file
                )
            })?;

            return Ok((krb_cred, CredentialFormat::Ccache));
        }
        Err(_) => {
            let (_, krb_cred) = KrbCred::parse(&data).map_err(|_| {
                format!("Error parsing content of file '{}'", creds_file)
            })?;
            return Ok((krb_cred, CredentialFormat::Krb));
        }
    }
}

pub fn save_file_creds(
    creds_file: &str,
    creds: KrbCredPlain,
    cred_format: CredentialFormat,
) -> Result<()> {
    let krb_cred = creds.into();
    return save_file_krb_cred(creds_file, krb_cred, cred_format);
}

pub fn save_file_krb_cred(
    creds_file: &str,
    krb_cred: KrbCred,
    cred_format: CredentialFormat,
) -> Result<()> {
    let raw_cred = match cred_format {
        CredentialFormat::Krb => krb_cred.build(),
        CredentialFormat::Ccache => {
            let ccache: CCache = krb_cred
                .try_into()
                .map_err(|_| "Error converting KrbCred to CCache")?;
            ccache.build()
        }
    };

    fs::write(creds_file, raw_cred).map_err(|_| {
        format!("Unable to write credentials in file {}", creds_file)
    })?;

    return Ok(());
}
