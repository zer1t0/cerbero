mod vault_trait;
pub use vault_trait::Vault;

mod file;
pub use file::{FileVault, save_file_creds, load_file_creds};
