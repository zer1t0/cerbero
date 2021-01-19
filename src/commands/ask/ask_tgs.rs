use crate::communication::KdcComm;
use crate::core::forge::new_nt_srv_inst;
use crate::core::stringifier::ticket_cred_to_string;
use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::core::{
    get_impersonation_ticket, get_user_tgt, request_regular_tgs,
    request_s4u2self_tgs, request_tgs, S4u,
};
use crate::error::Result;
use kerberos_crypto::Key;
use log::{debug, info};

/// Main function to request a new TGS for a user for the selected service
pub fn ask_tgs(
    user: KrbUser,
    service: String,
    rename_service: Option<String>,
    user_key: Option<&Key>,
    cred_format: CredFormat,
    vault: &mut dyn Vault,
    mut kdccomm: KdcComm,
) -> Result<()> {
    let channel = kdccomm.create_channel(&user.realm)?;

    let tgt = get_user_tgt(user.clone(), user_key, None, vault, &*channel)?;

    info!("Request {} TGS for {}", user, service);
    let mut tgs = request_regular_tgs(
        user.clone(),
        new_nt_srv_inst(&service),
        tgt,
        None,
        &mut kdccomm,
    )?;

    let target_str;
    if let Some(rename_service) = rename_service {
        info!("Received {} TGS for {}", user, service);
        info!("Rename service from {} to {}", service, rename_service);
        tgs.change_sname(new_nt_srv_inst(&rename_service));

        debug!(
            "{} TGS for {}\n{}",
            user,
            rename_service,
            ticket_cred_to_string(&tgs, 0)
        );
        target_str = rename_service;
    } else {
        target_str = service;
    }

    info!("Save {} TGS for {} in {}", user, target_str, vault.id());
    vault.add(tgs)?;

    vault.change_format(cred_format)?;
    return Ok(());
}

/// Main function to perform an S4U2Self operation
pub fn ask_s4u2self(
    user: KrbUser,
    impersonate_user: KrbUser,
    user_service: Option<String>,
    vault: &mut dyn Vault,
    user_key: Option<&Key>,
    cred_format: CredFormat,
    mut kdccomm: KdcComm,
) -> Result<()> {
    let target_str = user_service.clone().unwrap_or(user.to_string());
    let channel = kdccomm.create_channel(&user.realm)?;

    let tgt = get_user_tgt(user.clone(), user_key, None, vault, &*channel)?;

    info!(
        "Request {} S4U2Self TGS for {}",
        impersonate_user, target_str
    );
    let s4u2self_tgs = request_s4u2self_tgs(
        user.clone(),
        impersonate_user.clone(),
        user_service,
        tgt,
        &mut kdccomm,
    )?;

    info!(
        "Save {} S4U2Self TGS for {} in {}",
        impersonate_user,
        target_str,
        vault.id()
    );
    vault.add(s4u2self_tgs.clone())?;
    vault.change_format(cred_format)?;

    return Ok(());
}

/// Main function to perform an S4U2Proxy operation
pub fn ask_s4u2proxy(
    user: KrbUser,
    impersonate_user: KrbUser,
    service: String,
    user_service: Option<String>,
    rename_service: Option<String>,
    vault: &mut dyn Vault,
    user_key: Option<&Key>,
    cred_format: CredFormat,
    mut kdccomm: KdcComm,
) -> Result<()> {
    let channel = kdccomm.create_channel(&user.realm)?;

    let tgt = get_user_tgt(user.clone(), user_key, None, vault, &*channel)?;

    let s4u2self_tgs = get_impersonation_ticket(
        user.clone(),
        impersonate_user.clone(),
        user_service,
        tgt.clone(),
        vault,
        &mut kdccomm,
    )?;

    info!("Request {} S4U2Proxy TGS for {}", impersonate_user, service);
    let mut dst_realm = user.realm.clone();
    let mut tgs_proxy = request_tgs(
        user.clone(),
        dst_realm.clone(),
        tgt.clone(),
        S4u::S4u2proxy(s4u2self_tgs.ticket.clone(), service.clone()),
        None,
        &*channel,
    )?;

    if tgs_proxy.is_tgt() && !tgs_proxy.is_tgt_for_realm(&dst_realm) {
        dst_realm = tgs_proxy
            .service_host()
            .ok_or("Unable to get the inter-realm TGT domain")?
            .clone();



        let inter_tgt = request_regular_tgs(
            user.clone(),
            new_nt_srv_inst(&format!("krbtgt/{}", dst_realm)),
            tgt.clone(),
            None,
            &mut kdccomm,
        )?;

        let channel = kdccomm.create_channel(&dst_realm)?;

        tgs_proxy = request_tgs(
            user.clone(),
            dst_realm,
            inter_tgt.clone(),
            S4u::S4u2proxy(tgs_proxy.ticket, service.clone()),
            None,
            &*channel,
        )?;
    }

    debug!(
        "{} S4U2proxy TGS for {}\n{}",
        impersonate_user,
        service,
        ticket_cred_to_string(&tgs_proxy, 0)
    );

    let target_str;
    if let Some(rename_service) = rename_service {
        info!(
            "Received {} S4U2proxy TGS for {}",
            impersonate_user, service
        );
        info!("Rename service from {} to {}", service, rename_service);
        tgs_proxy.change_sname(new_nt_srv_inst(&rename_service));

        debug!(
            "{} S4U2proxy TGS for {}\n{}",
            impersonate_user,
            rename_service,
            ticket_cred_to_string(&tgs_proxy, 0)
        );
        target_str = rename_service;
    } else {
        target_str = service;
    }

    info!(
        "Save {} S4U2proxy TGS for {} in {}",
        impersonate_user,
        target_str,
        vault.id()
    );

    vault.add(tgs_proxy)?;
    vault.change_format(cred_format)?;

    return Ok(());
}
