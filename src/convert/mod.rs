use crate::cred_format::CredentialFormat;
use crate::file::{parse_creds_file, save_cred_in_file};
use crate::Result;
use log::info;

pub fn convert(
    in_file: &str,
    out_file: &str,
    cred_format: Option<CredentialFormat>,
) -> Result<()> {
    let (krb_cred, in_cred_format) = parse_creds_file(in_file)?;
    info!("Read {} with {} format", in_file, in_cred_format);

    let cred_format = match cred_format {
        Some(cred_format) => cred_format,
        None => match cred_format_from_file_extension(out_file) {
            Some(cred_format) => {
                info!(
                    "Detected {} format from output file extension",
                    cred_format
                );
                cred_format
            }
            None => in_cred_format.contrary(),
        },
    };

    save_cred_in_file(out_file, krb_cred, cred_format)?;
    info!("Save {} with {} format", out_file, cred_format);

    return Ok(());
}

fn cred_format_from_file_extension(filename: &str) -> Option<CredentialFormat> {
    if filename.ends_with(".ccache") {
        return Some(CredentialFormat::Ccache);
    }

    if filename.ends_with(".krb") {
        return Some(CredentialFormat::Krb);
    }

    if filename.ends_with(".kirbi") {
        return Some(CredentialFormat::Krb);
    }

    return None;
}
