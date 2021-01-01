use crate::core::CredentialFormat;
use crate::core::Vault;
use crate::Result;
use log::info;

pub fn convert(
    in_vault: &dyn Vault,
    out_vault: &dyn Vault,
    cred_format: Option<CredentialFormat>,
) -> Result<()> {
    let (krb_cred, in_cred_format) = in_vault.dump()?;
    info!("Read {} with {} format", in_vault.id(), in_cred_format);

    let cred_format = match cred_format {
        Some(cred_format) => cred_format,
        None => match cred_format_from_file_extension(out_vault.id()) {
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

    out_vault.save(krb_cred, cred_format)?;
    info!("Save {} with {} format", out_vault.id(), cred_format);

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
