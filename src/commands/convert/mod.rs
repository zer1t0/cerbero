use crate::core::CredFormat;
use crate::core::Vault;
use crate::Result;
use log::info;

pub fn convert(
    in_vault: &dyn Vault,
    out_vault: &dyn Vault,
    cred_format: Option<CredFormat>,
) -> Result<()> {
    let krb_cred = in_vault.dump()?;
    let in_cred_format = in_vault.get_cred_format()?;
    info!("Read {} with {} format", in_vault.id(), in_cred_format);

    let cred_format = match cred_format {
        Some(cred_format) => cred_format,
        None => match CredFormat::from_file_extension(out_vault.id()) {
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

    out_vault.save(krb_cred, Some(cred_format))?;
    info!("Save {} with {} format", out_vault.id(), cred_format);

    return Ok(());
}
