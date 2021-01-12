//! This module provide functionalities to create/parse kerberos structs

mod kdc_req;
pub use kdc_req::KdcReqBuilder;

mod krb_cred;
pub use krb_cred::new_krb_cred_info;

mod krb_user;
pub use krb_user::KrbUser;

mod principal_name;
pub use principal_name::{
    new_nt_principal, new_nt_srv_inst, new_principal_name,
    spn_to_service_parts, new_principal_or_srv_inst, new_nt_enterprise
};

mod pa_data;

mod pac;
pub use pac::new_signed_pac;

mod build_req;
pub use build_req::{build_as_req, build_tgs_req, S4u2options};

mod decrypters;
pub use decrypters::{
    extract_krb_cred_from_as_rep, extract_ticket_from_tgs_rep,
};

mod ticket;
pub use ticket::craft_ticket_info;
