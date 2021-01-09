use crate::core::stringifier::ticket_cred_to_string;
use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::TicketCred;
use crate::core::Vault;
use crate::core::{
    get_impersonation_ticket, get_user_tgt, request_tgs, S4u2options,
};
use crate::error::Result;
use crate::transporter::KerberosTransporter;
use crate::utils::resolve_and_get_tranporter;
use kerberos_crypto::Key;
use log::{debug, info};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Main function to request a new TGS for a user for the selected service
pub fn ask_tgs(
    user: KrbUser,
    service: String,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredFormat,
    vault: &mut dyn Vault,
    kdcs: &HashMap<String, IpAddr>,
) -> Result<()> {
    let tgt = get_user_tgt(user.clone(), vault, user_key, transporter, None)?;
    debug!("TGT for {} info\n{}", user, ticket_cred_to_string(&tgt, 0));

    info!("Request {} TGS for {}", service, user);
    let mut tgs = request_tgs(
        user.clone(),
        user.realm.clone(),
        tgt,
        S4u2options::Normal(service.clone()),
        None,
        transporter,
    )?;

    if tgs.is_tgt() {
        tgs = request_inter_realm_tgs(
            tgs,
            user.clone(),
            S4u2options::Normal(service.clone()),
            vault,
            transporter,
            kdcs,
        )?;
    }

    debug!(
        "{} TGS for {}\n{}",
        service,
        user,
        ticket_cred_to_string(&tgs, 0)
    );

    info!("Save {} TGS for {} in {}", user, service, vault.id());
    vault.add(tgs)?;
    vault.change_format(cred_format)?;

    return Ok(());
}

/// Main function to perform an S4U2Self operation
pub fn ask_s4u2self(
    user: KrbUser,
    impersonate_user: KrbUser,
    vault: &mut dyn Vault,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredFormat,
) -> Result<()> {
    let tgt = get_user_tgt(user.clone(), vault, user_key, transporter, None)?;
    debug!("TGT for {} info\n{}", user, ticket_cred_to_string(&tgt, 0));

    info!("Request {} S4U2Self TGS for {}", user, impersonate_user,);
    let s4u2self_tgs = request_tgs(
        user.clone(),
        user.realm.clone(),
        tgt,
        S4u2options::S4u2self(impersonate_user.clone()),
        None,
        transporter,
    )?;

    debug!(
        "{} S4U2Self TGS for {}\n{}",
        user,
        impersonate_user,
        ticket_cred_to_string(&s4u2self_tgs, 0)
    );

    info!(
        "Save {} S4U2Self TGS for {} in {}",
        user,
        impersonate_user,
        vault.id()
    );
    vault.add(s4u2self_tgs)?;
    vault.change_format(cred_format)?;

    return Ok(());
}

/// Main function to perform an S4U2Proxy operation
pub fn ask_s4u2proxy(
    user: KrbUser,
    impersonate_user: KrbUser,
    service: String,
    vault: &mut dyn Vault,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredFormat,
    kdcs: &HashMap<String, IpAddr>,
) -> Result<()> {
    let tgt = get_user_tgt(user.clone(), vault, user_key, transporter, None)?;
    debug!("TGT for {} info\n{}", user, ticket_cred_to_string(&tgt, 0));

    let s4u2self_tgs = get_impersonation_ticket(
        vault,
        user.clone(),
        impersonate_user.clone(),
        transporter,
        tgt.clone(),
    )?;
    debug!(
        "{} S4U2Self TGS for {}\n{}",
        user,
        impersonate_user,
        ticket_cred_to_string(&s4u2self_tgs, 0)
    );

    info!("Request {} S4U2Proxy TGS for {}", service, impersonate_user);
    let mut tgs_proxy = request_tgs(
        user.clone(),
        user.realm.clone(),
        tgt,
        S4u2options::S4u2proxy(s4u2self_tgs.ticket.clone(), service.clone()),
        None,
        transporter,
    )?;

    if tgs_proxy.is_tgt() {
        tgs_proxy = request_inter_realm_tgs(
            tgs_proxy,
            user.clone(),
            S4u2options::S4u2proxy(s4u2self_tgs.ticket, service.clone()),
            vault,
            transporter,
            kdcs,
        )?;
    }

    debug!(
        "{} S4U2Proxy TGS for {}\n{}",
        service,
        impersonate_user,
        ticket_cred_to_string(&tgs_proxy, 0)
    );

    info!(
        "Save {} S4U2Proxy TGS for {} in {}",
        service,
        impersonate_user,
        vault.id()
    );
    vault.add(tgs_proxy)?;
    vault.change_format(cred_format)?;

    return Ok(());
}

pub fn request_inter_realm_tgs(
    inter_tgt: TicketCred,
    user: KrbUser,
    service: S4u2options,
    vault: &mut dyn Vault,
    transporter: &dyn KerberosTransporter,
    kdcs: &HashMap<String, IpAddr>,
) -> Result<TicketCred> {
    let cross_domain = inter_tgt
        .service_host()
        .ok_or("Unable to get the inter-realm TGT domain")?;

    info!("Received inter-realm TGT for domain {}", cross_domain);

    debug!(
        "{} inter-realm TGT for {}\n{}",
        cross_domain,
        user,
        ticket_cred_to_string(&inter_tgt, 0)
    );

    info!(
        "Save {} inter-realm TGT for {} in {}",
        cross_domain,
        user,
        vault.id()
    );
    vault.add(inter_tgt.clone())?;

    let cross_transporter = resolve_and_get_tranporter(
        &cross_domain,
        kdcs.get(&cross_domain.to_lowercase()).map(|v| v.clone()),
        vec![SocketAddr::new(transporter.ip(), 53)],
        88,
        transporter.protocol(),
    )?;

    return request_tgs(
        user,
        cross_domain.to_string(),
        inter_tgt,
        service,
        None,
        &*cross_transporter,
    );
}
