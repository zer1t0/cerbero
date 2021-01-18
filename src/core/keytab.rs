use crate::error::Error;
use crate::Result;
pub use kerberos_keytab::Keytab;
use std::env;
use std::fs;

pub const KEYTAB_ENVVAR: &'static str = "KRB5_KTNAME";

pub fn env_keytab_file() -> Option<String> {
    return env::var(KEYTAB_ENVVAR).ok();
}

pub fn load_file_keytab(filepath: &str) -> Result<Keytab> {
    let data = fs::read(filepath).map_err(|err| {
        let message = format!("Unable to read the file '{}'", filepath);
        (message, err)
    })?;

    match Keytab::parse(&data) {
        Ok((_, keytab)) => return Ok(keytab),
        Err(_) => {
            return Err(Error::DataError(format!(
                "Error parsing keytab file '{}'",
                filepath
            )));
        }
    }
}
