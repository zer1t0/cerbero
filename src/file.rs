use crate::cred_format::CredentialFormat;
use crate::Result;
use kerberos_asn1::{Asn1Object, KrbCred};
use kerberos_ccache::CCache;
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn parse_creds_file(
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

pub fn save_cred_in_file(
    out_file: &str,
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

    fs::write(out_file, raw_cred).map_err(|_| {
        format!("Unable to write credentials in file {}", out_file)
    })?;

    return Ok(());
}

pub fn read_file_lines(filename: &str) -> Result<Vec<String>> {
    let fd = File::open(filename).map_err(|error| {
        format!("Unable to read the file '{}': {}", filename, error)
    })?;
    let file_lines: Vec<String> = BufReader::new(fd)
        .lines()
        .filter_map(std::result::Result::ok)
        .collect();

    return Ok(file_lines);
}
