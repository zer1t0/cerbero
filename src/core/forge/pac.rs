use crate::core::Cipher;
use kerberos_constants::key_usages;
use ms_dtyp::FILETIME;
use ms_dtyp::RID_DOMAIN_USERS;
use ms_pac::{
    GROUP_MEMBERSHIP, KERB_VALIDATION_INFO, NOT_EXPIRE_TIME, NOT_SET_TIME,
    PACTYPE, PAC_CLIENT_INFO, PAC_INFO_BUFFER, PAC_SIGNATURE_DATA, PISID,
};
use ms_samr::{
    SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY,
    USER_DONT_EXPIRE_PASSWORD, USER_NORMAL_ACCOUNT,
};

pub fn new_signed_pac(
    username: &str,
    user_rid: u32,
    domain: &str,
    domain_sid: PISID,
    groups: &[u32],
    logon_time: FILETIME,
    cipher: &Cipher,
) -> PACTYPE {
    let mut pactype = new_pactype(
        username,
        user_rid,
        domain,
        domain_sid,
        groups,
        cipher.checksum_type(),
        logon_time,
    );

    let raw_pactype = pactype.build();

    let server_sign = cipher
        .checksum(key_usages::KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, &raw_pactype);
    let privsrv_sign = cipher
        .checksum(key_usages::KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, &server_sign);

    let server_checksum = pactype.server_checksum_mut().unwrap();
    server_checksum.Signature = server_sign;

    let privsrv_checksum = pactype.privsrv_checksum_mut().unwrap();
    privsrv_checksum.Signature = privsrv_sign;

    return pactype;
}

fn new_pactype(
    username: &str,
    user_rid: u32,
    domain: &str,
    domain_sid: PISID,
    groups: &[u32],
    checksum_type: i32,
    logon_time: FILETIME,
) -> PACTYPE {
    return PACTYPE::from(vec![
        PAC_INFO_BUFFER::LOGON_INFO(new_kerb_validation_info(
            username,
            user_rid,
            domain,
            domain_sid,
            groups,
            logon_time.clone(),
        )),
        PAC_INFO_BUFFER::CLIENT_INFO(PAC_CLIENT_INFO::new(
            logon_time, username,
        )),
        PAC_INFO_BUFFER::SERVER_CHECKSUM(new_pac_signature(checksum_type)),
        PAC_INFO_BUFFER::PRIVSRV_CHECKSUM(new_pac_signature(checksum_type)),
    ]);
}

fn new_pac_signature(etype: i32) -> PAC_SIGNATURE_DATA {
    return PAC_SIGNATURE_DATA::new_empty(etype);
}

fn new_kerb_validation_info(
    username: &str,
    user_rid: u32,
    domain: &str,
    domain_sid: PISID,
    groups: &[u32],
    logon_time: FILETIME,
) -> KERB_VALIDATION_INFO {
    let mut kvi = KERB_VALIDATION_INFO::default();

    kvi.LogonTime = logon_time.clone();
    kvi.LogoffTime = NOT_EXPIRE_TIME.into();
    kvi.KickOffTime = NOT_EXPIRE_TIME.into();
    kvi.PasswordLastSet = logon_time;
    kvi.PasswordCanChange = NOT_SET_TIME.into();
    kvi.PasswordMustChange = NOT_EXPIRE_TIME.into();
    kvi.EfectiveName = username.into();
    kvi.LogonCount = 500;
    kvi.BadPasswordCount = 0;
    kvi.UserId = user_rid;
    kvi.PrimaryGroupId = RID_DOMAIN_USERS;

    for group_id in groups.iter() {
        kvi.GroupIds.push(GROUP_MEMBERSHIP::new(
            *group_id,
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT,
        ));
    }

    kvi.LogonDomainName = domain.to_uppercase().as_str().into();
    kvi.LogonDomainId = domain_sid;
    kvi.UserAccountControl = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD;

    return kvi;
}
