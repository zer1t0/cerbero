use super::Vault;
use crate::core::CredFormat;
use crate::core::{TicketCreds, TicketCred};
use crate::error::Error;
use crate::KrbUser;
use crate::Result;
use kerberos_asn1::{Asn1Object, KrbCred};
use kerberos_ccache::CCache;
use std::convert::{TryFrom, TryInto};
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
    fn id(&self) -> &str {
        return &self.file_path;
    }

    fn dump(&self) -> Result<TicketCreds> {
        return load_file_creds(&self.file_path);
    }

    fn get_cred_format(&self) -> Result<CredFormat> {
        return get_file_cred_format(&self.file_path);
    }

    fn get_user_tgt(
        &self,
        user: &KrbUser,
    ) -> Result<Option<TicketCred>> {
        let krb_cred_plain = self.dump()?;
        return Ok(krb_cred_plain.look_for_tgt(&user));
    }

    fn append_ticket(&mut self, ticket_info: TicketCred) -> Result<()> {
        let mut tickets_info = self.dump()?;
        tickets_info.push(ticket_info);
        return self.save(tickets_info, None);
    }

    fn save(
        &self,
        creds: TicketCreds,
        cred_format: Option<CredFormat>,
    ) -> Result<()> {
        let cred_format = match cred_format {
            Some(cf) => cf,
            None => self.get_cred_format()?,
        };
        return save_file_creds(&self.file_path, creds, cred_format);
    }
}

pub fn load_file_creds(creds_file: &str) -> Result<TicketCreds> {
    let (krb_cred, _) = load_file_krb_cred(&creds_file)?;

    // Kerberos credentials are usually stored in plain text so this should
    // work.
    let creds = TicketCreds::try_from(krb_cred)?;
    return Ok(creds);
}

pub fn get_file_cred_format(creds_file: &str) -> Result<CredFormat> {
    return get_file_cred_format_with_default(creds_file, CredFormat::Ccache);
}

pub fn get_file_cred_format_with_default(
    creds_file: &str,
    default: CredFormat,
) -> Result<CredFormat> {
    return Ok(get_cred_format_by_file(creds_file)?.unwrap_or(default));
}

/// Deduce the credentials format based on the file content and file extension.
pub fn get_cred_format_by_file(creds_file: &str) -> Result<Option<CredFormat>> {
    match get_cred_format_by_file_content(creds_file)? {
        Some(cred_format) => return Ok(Some(cred_format)),
        None => {
            return Ok(CredFormat::from_file_extension(creds_file));
        }
    }
}

/// Deduce the credentials format based on the file content.
pub fn get_cred_format_by_file_content(
    creds_file: &str,
) -> Result<Option<CredFormat>> {
    match load_file_krb_cred(creds_file) {
        Ok((_, cred_format)) => return Ok(Some(cred_format)),
        Err(err) => {
            if err.is_not_found_error() || err.is_data_error() {
                return Ok(None);
            }

            return Err(err);
        }
    }
}

/// Load the Kerberos credentials from a file.
pub fn load_file_krb_cred(creds_file: &str) -> Result<(KrbCred, CredFormat)> {
    let data = fs::read(creds_file).map_err(|err| {
        let message = format!("Unable to read the file '{}'", creds_file);
        (message.as_str(), err)
    })?;

    match CCache::parse(&data) {
        Ok((_, ccache)) => {
            let krb_cred = ccache.try_into().map_err(|_| {
                Error::DataError(format!(
                    "Error parsing ccache data content of file '{}'",
                    creds_file
                ))
            })?;

            return Ok((krb_cred, CredFormat::Ccache));
        }
        Err(_) => {
            let (_, krb_cred) = KrbCred::parse(&data).map_err(|_| {
                Error::DataError(format!(
                    "Error parsing content of file '{}'",
                    creds_file
                ))
            })?;
            return Ok((krb_cred, CredFormat::Krb));
        }
    }
}

pub fn save_file_creds(
    creds_file: &str,
    creds: TicketCreds,
    cred_format: CredFormat,
) -> Result<()> {
    let krb_cred = creds.into();
    return save_file_krb_cred(creds_file, krb_cred, cred_format);
}

/// Save the Kerberos credentials in the file with the specified format.
pub fn save_file_krb_cred(
    creds_file: &str,
    krb_cred: KrbCred,
    cred_format: CredFormat,
) -> Result<()> {
    let raw_cred = match cred_format {
        CredFormat::Krb => krb_cred.build(),
        CredFormat::Ccache => {
            let ccache: CCache = krb_cred.try_into().map_err(|_| {
                Error::DataError(format!("Error converting KrbCred to CCache"))
            })?;
            ccache.build()
        }
    };

    fs::write(creds_file, raw_cred).map_err(|err| {
        let message =
            format!("Unable to write credentials in file {}", creds_file);
        (message.as_str(), err)
    })?;

    return Ok(());
}
