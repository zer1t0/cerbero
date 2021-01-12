use crate::core::KrbUser;
use kerberos_asn1::PrincipalName;
use kerberos_constants::principal_names;

pub fn new_principal_or_srv_inst(name: &str, realm: &str) -> PrincipalName {
    let name_parts = spn_to_service_parts(&name);
    let name_type = if name_parts.last().unwrap() == realm {
        principal_names::NT_SRV_INST
    } else {
        principal_names::NT_PRINCIPAL
    };

    return PrincipalName {
        name_type: name_type,
        name_string: name_parts,
    };
}

pub fn new_nt_principal(name: &str) -> PrincipalName {
    return new_principal_name(name, principal_names::NT_PRINCIPAL);
}

pub fn new_nt_srv_inst(service: &str) -> PrincipalName {
    return new_principal_name(service, principal_names::NT_SRV_INST);
}

pub fn new_nt_enterprise(user: &KrbUser) -> PrincipalName {
    return new_principal_name(
        &format!("{}@{}", &user.name, &user.realm),
        principal_names::NT_ENTERPRISE,
    );
}

pub fn new_principal_name(name: &str, name_type: i32) -> PrincipalName {
    return PrincipalName {
        name_type: name_type,
        name_string: spn_to_service_parts(name),
    };
}

pub fn spn_to_service_parts(spn: &str) -> Vec<String> {
    spn.split("/").map(|s| s.to_string()).collect()
}
