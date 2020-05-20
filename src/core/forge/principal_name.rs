use kerberos_asn1::PrincipalName;
use kerberos_constants::principal_names;

pub fn new_nt_principal(name: &str) -> PrincipalName {
    return new_principal_name(name, principal_names::NT_PRINCIPAL);
}

pub fn new_nt_srv_inst(service: &str) -> PrincipalName {
    return new_principal_name(service, principal_names::NT_SRV_INST);
}

pub fn new_nt_unknown(name: &str) -> PrincipalName {
    return new_principal_name(name, principal_names::NT_UNKNOWN);
}

pub fn new_principal_name(name: &str, name_type: i32) -> PrincipalName {
    return PrincipalName {
        name_type: name_type,
        name_string: name.split("/").map(|s| s.to_string()).collect(),
    };
}
