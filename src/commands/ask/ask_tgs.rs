use crate::communication::KdcComm;
use crate::core::stringifier::ticket_cred_to_string;
use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::TicketCred;
use crate::core::Vault;
use crate::core::{
    get_impersonation_ticket, get_user_tgt, request_s4u2self_tgs, request_tgs,
    S4u2options,
};
use crate::error::Result;
use kerberos_crypto::Key;
use log::{debug, info};

/// Main function to request a new TGS for a user for the selected service
pub fn ask_tgs(
    user: KrbUser,
    service: String,
    user_key: Option<&Key>,
    cred_format: CredFormat,
    vault: &mut dyn Vault,
    mut kdccomm: KdcComm,
) -> Result<()> {
    let channel = kdccomm.create_channel(&user.realm)?;

    let tgt = get_user_tgt(user.clone(), user_key, None, vault, &*channel)?;
    debug!("TGT for {} info\n{}", user, ticket_cred_to_string(&tgt, 0));

    request_regular_tgs(user, service, tgt, vault, &mut kdccomm)?;

    vault.change_format(cred_format)?;

    return Ok(());
}

pub fn request_regular_tgs(
    user: KrbUser,
    service: String,
    tgt: TicketCred,
    vault: &mut dyn Vault,
    mut kdccomm: &mut KdcComm,
) -> Result<TicketCred> {
    let channel = kdccomm.create_channel(&user.realm)?;

    info!("Request {} TGS for {}", service, user);
    let mut tgs = request_tgs(
        user.clone(),
        user.realm.clone(),
        tgt,
        S4u2options::Normal(service.clone()),
        None,
        &*channel,
    )?;

    while tgs.is_tgt() && !tgs.is_for_service(&service) {
        tgs = request_inter_realm_tgs(
            tgs,
            user.clone(),
            S4u2options::Normal(service.clone()),
            vault,
            &mut kdccomm,
        )?;
    }

    debug!(
        "{} TGS for {}\n{}",
        service,
        user,
        ticket_cred_to_string(&tgs, 0)
    );

    info!("Save {} TGS for {} in {}", user, service, vault.id());
    vault.add(tgs.clone())?;

    return Ok(tgs);
}

pub fn request_inter_realm_tgs(
    inter_tgt: TicketCred,
    user: KrbUser,
    service: S4u2options,
    vault: &mut dyn Vault,
    kdccomm: &mut KdcComm,
) -> Result<TicketCred> {
    let dst_realm = inter_tgt
        .service_host()
        .ok_or("Unable to get the inter-realm TGT domain")?
        .clone();

    info!("Received inter-realm TGT for domain {}", dst_realm);

    debug!(
        "{} inter-realm TGT for {}\n{}",
        dst_realm,
        user,
        ticket_cred_to_string(&inter_tgt, 0)
    );

    info!(
        "Save {} inter-realm TGT for {} in {}",
        dst_realm,
        user,
        vault.id()
    );
    vault.add(inter_tgt.clone())?;

    let channel = kdccomm.create_channel(&dst_realm)?;

    return request_tgs(
        user,
        dst_realm.to_string(),
        inter_tgt,
        service,
        None,
        &*channel,
    );
}

/// Main function to perform an S4U2Self operation
pub fn ask_s4u2self(
    user: KrbUser,
    impersonate_user: KrbUser,
    vault: &mut dyn Vault,
    user_key: Option<&Key>,
    cred_format: CredFormat,
    mut kdccomm: KdcComm,
) -> Result<()> {
    let channel = kdccomm.create_channel(&user.realm)?;

    let tgt = get_user_tgt(user.clone(), user_key, None, vault, &*channel)?;
    debug!("TGT for {} info\n{}", user, ticket_cred_to_string(&tgt, 0));

    request_s4u2self_tgs(user, impersonate_user, tgt, vault, &mut kdccomm)?;

    vault.change_format(cred_format)?;

    return Ok(());
}

/// Main function to perform an S4U2Proxy operation
pub fn ask_s4u2proxy(
    user: KrbUser,
    impersonate_user: KrbUser,
    service: String,
    vault: &mut dyn Vault,
    user_key: Option<&Key>,
    cred_format: CredFormat,
    mut kdccomm: KdcComm,
) -> Result<()> {
    let channel = kdccomm.create_channel(&user.realm)?;

    let tgt = get_user_tgt(user.clone(), user_key, None, vault, &*channel)?;
    debug!("TGT for {} info\n{}", user, ticket_cred_to_string(&tgt, 0));

    let s4u2self_tgs = get_impersonation_ticket(
        user.clone(),
        impersonate_user.clone(),
        tgt.clone(),
        vault,
        &mut kdccomm,
    )?;

    info!("Request {} S4U2Proxy TGS for {}", service, impersonate_user);
    let mut tgs_proxy = request_tgs(
        user.clone(),
        user.realm.clone(),
        tgt.clone(),
        S4u2options::S4u2proxy(s4u2self_tgs.ticket.clone(), service.clone()),
        None,
        &*channel,
    )?;

    if tgs_proxy.is_tgt() {
        let dst_realm = tgs_proxy
            .service_host()
            .ok_or("Unable to get the inter-realm TGT domain")?
            .clone();

        let inter_tgt = request_regular_tgs(
            user.clone(),
            format!("krbtgt/{}", dst_realm),
            tgt.clone(),
            vault,
            &mut kdccomm,
        )?;

        tgs_proxy = request_inter_realm_tgs(
            inter_tgt.clone(),
            user.clone(),
            S4u2options::S4u2proxy(
                tgs_proxy.ticket,
                service.clone(),
            ),
            vault,
            &mut kdccomm,
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
