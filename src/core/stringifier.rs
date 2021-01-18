use crate::core::TicketCred;
use chrono::Local;
use kerberos_asn1::{
    ApReq, AsRep, AsReq, Asn1Object, Checksum, EncryptedData, EncryptionKey,
    EtypeInfo2, EtypeInfo2Entry, KdcReqBody, KerbPaPacRequest, KerberosTime,
    KrbCredInfo, KrbError, PaData, PaForUser, PaPacOptions, PrincipalName,
    TgsRep, TgsReq, Ticket,
};
use kerberos_constants::{
    ap_options, checksum_types, error_codes, etypes, kdc_options,
    message_types, pa_data_types, pa_pac_options, principal_names,
    ticket_flags,
};

const NONE: &str = "-";
const UNKNOWN: &str = "???";
const INDENT_STEP: usize = 4;

pub fn ticket_cred_to_string(tc: &TicketCred, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}[Ticket]\n\
         {}\n\
         {}[KrbCredInfo]\n\
         {}",
        indentation,
        ticket_to_string(&tc.ticket, indent_level),
        indentation,
        krb_cred_info_to_string(&tc.cred_info, indent_level)
    )
}

pub fn krb_error_to_string(ke: &KrbError, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}pvno: {}\n\
         {}msg-type: {}\n\
         {}ctime: {}\n\
         {}cusec: {}\n\
         {}stime: {}\n\
         {}susec: {}\n\
         {}error-code: {}\n\
         {}crealm: {}\n\
         {}cname:{}\n\
         {}realm: {}\n\
         {}sname:\n{}\n\
         {}e-text: {}\n\
         {}e-data: {}",
        indentation,
        ke.pvno,
        indentation,
        msg_type_to_string(ke.msg_type),
        indentation,
        ke.ctime
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        ke.cusec.map(|v| format!("{}", v)).unwrap_or(NONE.into()),
        indentation,
        kerberos_time_to_string(&ke.stime),
        indentation,
        ke.susec,
        indentation,
        error_code_to_string(ke.error_code),
        indentation,
        ke.crealm.as_ref().unwrap_or(&NONE.into()),
        indentation,
        ke.cname
            .as_ref()
            .map(|v| format!(
                "\n{}",
                principal_name_to_string(&v, indent_level + INDENT_STEP)
            ))
            .unwrap_or(NONE.into()),
        indentation,
        ke.realm,
        indentation,
        principal_name_to_string(&ke.sname, indent_level + INDENT_STEP),
        indentation,
        ke.e_text.as_ref().unwrap_or(&NONE.into()),
        indentation,
        ke.e_data
            .as_ref()
            .map(|v| octet_string_to_string(&v))
            .unwrap_or(NONE.into()),
    )
}

pub fn error_code_to_string(ec: i32) -> String {
    format!("{} -> {}", ec, error_code_name(ec))
}

pub fn error_code_name(ec: i32) -> &'static str {
    match ec {
        error_codes::KDC_ERR_NONE => "kdc-err-none",
        error_codes::KDC_ERR_NAME_EXP => "kdc-err-name-exp",
        error_codes::KDC_ERR_SERVICE_EXP => "kdc-err-service-exp",
        error_codes::KDC_ERR_BAD_PVNO => "kdc-err-bad-pvno",
        error_codes::KDC_ERR_C_OLD_MAST_KVNO => "kdc-err-c-old-mast-kvno",
        error_codes::KDC_ERR_S_OLD_MAST_KVNO => "kdc-err-s-old-mast-kvno",
        error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN => {
            "kdc-err-c-principal-unknown"
        }
        error_codes::KDC_ERR_S_PRINCIPAL_UNKNOWN => {
            "kdc-err-s-principal-unknown"
        }
        error_codes::KDC_ERR_PRINCIPAL_NOT_UNIQUE => {
            "kdc-err-principal-not-unique"
        }
        error_codes::KDC_ERR_NULL_KEY => "kdc-err-null-key",
        error_codes::KDC_ERR_CANNOT_POSTDATE => "kdc-err-cannot-postdate",
        error_codes::KDC_ERR_NEVER_VALID => "kdc-err-never-valid",
        error_codes::KDC_ERR_POLICY => "kdc-err-policy",
        error_codes::KDC_ERR_BADOPTION => "kdc-err-badoption",
        error_codes::KDC_ERR_ETYPE_NOSUPP => "kdc-err-etype-nosupp",
        error_codes::KDC_ERR_SUMTYPE_NOSUPP => "kdc-err-sumtype-nosupp",
        error_codes::KDC_ERR_PADATA_TYPE_NOSUPP => "kdc-err-padata-type-nosupp",
        error_codes::KDC_ERR_TRTYPE_NOSUPP => "kdc-err-trtype-nosupp",
        error_codes::KDC_ERR_CLIENT_REVOKED => "kdc-err-client-revoked",
        error_codes::KDC_ERR_SERVICE_REVOKED => "kdc-err-service-revoked",
        error_codes::KDC_ERR_TGT_REVOKED => "kdc-err-tgt-revoked",
        error_codes::KDC_ERR_CLIENT_NOTYET => "kdc-err-client-notyet",
        error_codes::KDC_ERR_SERVICE_NOTYET => "kdc-err-service-notyet",
        error_codes::KDC_ERR_KEY_EXPIRED => "kdc-err-key-expired",
        error_codes::KDC_ERR_PREAUTH_FAILED => "kdc-err-preauth-failed",
        error_codes::KDC_ERR_PREAUTH_REQUIRED => "kdc-err-preauth-required",
        error_codes::KDC_ERR_SERVER_NOMATCH => "kdc-err-server-nomatch",
        error_codes::KDC_ERR_MUST_USE_USER2USER => "kdc-err-must-use-user2user",
        error_codes::KDC_ERR_PATH_NOT_ACCEPTED => "kdc-err-path-not-accepted",
        error_codes::KDC_ERR_SVC_UNAVAILABLE => "kdc-err-svc-unavailable",
        error_codes::KRB_AP_ERR_BAD_INTEGRITY => "krb-ap-err-bad-integrity",
        error_codes::KRB_AP_ERR_TKT_EXPIRED => "krb-ap-tkt-expired",
        error_codes::KRB_AP_ERR_TKT_NYV => "krb-ap-err-tkt-nyv",
        error_codes::KRB_AP_ERR_REPEAT => "krb-ap-err-repeat",
        error_codes::KRB_AP_ERR_NOT_US => "krb-ap-err-not-us",
        error_codes::KRB_AP_ERR_BADMATCH => "krb-ap-err-badmatch",
        error_codes::KRB_AP_ERR_SKEW => "krb-ap-err-skew",
        error_codes::KRB_AP_ERR_BADADDR => "krb-ap-err-badaddr",
        error_codes::KRB_AP_ERR_BADVERSION => "krb-ap-err-badversion",
        error_codes::KRB_AP_ERR_MSG_TYPE => "krb-ap-err-msg-type",
        error_codes::KRB_AP_ERR_MODIFIED => "krb-ap-err-modified",
        error_codes::KRB_AP_ERR_BADORDER => "krb-ap-err-badorder",
        error_codes::KRB_AP_ERR_BADKEYVER => "krb-ap-err-badkeyver",
        error_codes::KRB_AP_ERR_NOKEY => "krb-ap-err-nokey",
        error_codes::KRB_AP_ERR_MUT_FAIL => "krb-ap-err-mut-fail",
        error_codes::KRB_AP_ERR_BADDIRECTION => "krb-ap-err-baddirection",
        error_codes::KRB_AP_ERR_METHOD => "krb-ap-err-method",
        error_codes::KRB_AP_ERR_BADSEQ => "krb-ap-err-badseq",
        error_codes::KRB_AP_ERR_INAPP_CKSUM => "krb-ap-err-inapp-cksum",
        error_codes::KRB_AP_PATH_NOT_ACCEPTED => "krb-ap-path-not-accepted",
        error_codes::KRB_ERR_RESPONSE_TOO_BIG => "krb-err-response-too-big",
        error_codes::KRB_ERR_GENERIC => "krb-err-generic",
        error_codes::KRB_ERR_FIELD_TOOLONG => "krb-err-field-toolong",
        error_codes::KDC_ERROR_CLIENT_NOT_TRUSTED => {
            "kdc-error-client-not-trusted"
        }
        error_codes::KDC_ERROR_KDC_NOT_TRUSTED => "kdc-error-kdc-not-trusted",
        error_codes::KDC_ERROR_INVALID_SIG => "kdc-error-invalid-sig",
        error_codes::KDC_ERR_KEY_TOO_WEAK => "kdc-err-key-too-weak",
        error_codes::KDC_ERR_CERTIFICATE_MISMATCH => {
            "kdc-err-certificate-mismatch"
        }
        error_codes::KRB_AP_ERR_NO_TGT => "krb-ap-err-no-tgt",
        error_codes::KDC_ERR_WRONG_REALM => "kdc-err-wrong-realm",
        error_codes::KRB_AP_ERR_USER_TO_USER_REQUIRED => {
            "krb-ap-err-user-to-user-required"
        }
        error_codes::KDC_ERR_CANT_VERIFY_CERTIFICATE => {
            "kdc-err-cant-verify-certificate"
        }
        error_codes::KDC_ERR_INVALID_CERTIFICATE => {
            "kdc-err-invalid-certificate"
        }
        error_codes::KDC_ERR_REVOKED_CERTIFICATE => {
            "kdc-err-revoked-certificate"
        }
        error_codes::KDC_ERR_REVOCATION_STATUS_UNKNOWN => {
            "kdc-err-revocation-status-unknown"
        }
        error_codes::KDC_ERR_REVOCATION_STATUS_UNAVAILABLE => {
            "kdc-err-revocation-status-unavailable"
        }
        error_codes::KDC_ERR_CLIENT_NAME_MISMATCH => {
            "kdc-err-client-name-mismatch"
        }
        error_codes::KDC_ERR_KDC_NAME_MISMATCH => "kdc-err-kdc-name-mismatch",
        _ => UNKNOWN,
    }
}

pub fn as_req_to_string(ar: &AsReq, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}pvno: {}\n\
         {}msg-type: {}\n\
         {}padata: {}\n\
         {}req-body:\n{}",
        indentation,
        ar.pvno,
        indentation,
        msg_type_to_string(ar.msg_type),
        indentation,
        &ar.padata
            .as_ref()
            .map(|pds| format!(
                "\n{}",
                padatas_to_string(&pds, indent_level + INDENT_STEP)
            ))
            .unwrap_or(NONE.into()),
        indentation,
        kdc_req_body_to_string(&ar.req_body, indent_level + INDENT_STEP)
    )
}

pub fn tgs_req_to_string(tr: &TgsReq, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}pvno: {}\n\
         {}msg-type: {}\n\
         {}padata: {}\n\
         {}req-body:\n{}",
        indentation,
        tr.pvno,
        indentation,
        msg_type_to_string(tr.msg_type),
        indentation,
        &tr.padata
            .as_ref()
            .map(|pds| format!(
                "\n{}",
                padatas_to_string(&pds, indent_level + INDENT_STEP)
            ))
            .unwrap_or(NONE.into()),
        indentation,
        kdc_req_body_to_string(&tr.req_body, indent_level + INDENT_STEP)
    )
}

pub fn kdc_req_body_to_string(krb: &KdcReqBody, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}kdc-options: {}\n\
         {}cname:{}\n\
         {}realm: {}\n\
         {}sname:\n{}\n\
         {}from: {}\n\
         {}till: {}\n\
         {}rtime: {}\n\
         {}nonce: {}\n\
         {}etypes:\n{}\n\
         {}addresses: <Not Implemented>\n\
         {}enc-authorization-data:{}\n\
         {}additional-tickets:{}",
        indentation,
        kdc_options_to_string(krb.kdc_options.flags),
        indentation,
        krb.cname
            .as_ref()
            .map(|v| format!(
                "\n{}",
                principal_name_to_string(&v, indent_level + INDENT_STEP)
            ))
            .unwrap_or(format!(" {}", NONE)),
        indentation,
        krb.realm,
        indentation,
        krb.sname
            .as_ref()
            .map(|v| principal_name_to_string(&v, indent_level + INDENT_STEP))
            .unwrap_or(NONE.into()),
        indentation,
        krb.from
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        kerberos_time_to_string(&krb.till),
        indentation,
        krb.rtime
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        krb.nonce,
        indentation,
        etypes_to_string(&krb.etypes, indent_level + INDENT_STEP),
        indentation,
        indentation,
        krb.enc_authorization_data
            .as_ref()
            .map(|v| format!(
                "\n{}",
                encrypted_data_to_string(&v, indent_level + INDENT_STEP)
            ))
            .unwrap_or(format!(" {}", NONE)),
        indentation,
        krb.additional_tickets
            .as_ref()
            .map(|v| format!(
                "\n{}",
                tickets_to_string(&v, indent_level + INDENT_STEP)
            ))
            .unwrap_or(format!(" {}", NONE))
    )
}

pub fn kdc_options_to_string(ko: u32) -> String {
    let options_names = [
        (kdc_options::FORWARDABLE, "forwardable"),
        (kdc_options::FORWARDED, "forwarded"),
        (kdc_options::PROXIABLE, "proxiable"),
        (kdc_options::PROXY, "proxy"),
        (kdc_options::ALLOW_POSTDATE, "allow-postdate"),
        (kdc_options::POSTDATED, "postdated"),
        (kdc_options::RENEWABLE, "renewable"),
        (kdc_options::OPT_HARDWARE_AUTH, "opt-hardware-auth"),
        (
            kdc_options::CONSTRAINED_DELEGATION,
            "constrained-delegation",
        ),
        (kdc_options::CANONICALIZE, "canonicalize"),
        (kdc_options::REQUEST_ANONYMOUS, "request-anonymous"),
        (
            kdc_options::DISABLE_TRANSITED_CHECK,
            "disable-transited-check",
        ),
        (kdc_options::RENEWABLE_OK, "renewable-ok"),
        (kdc_options::ENC_TKT_IN_SKEY, "enc-tkt-in-skey"),
        (kdc_options::RENEW, "renew"),
        (kdc_options::VALIDATE, "validate"),
    ];

    let mut names = Vec::new();

    for option in options_names.iter() {
        if (ko & option.0) != 0 {
            names.push(option.1)
        }
    }

    return format!("{:#06x} -> {}", ko, names.join(" "));
}

pub fn ap_req_to_string(ar: &ApReq, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}pvno: {}\n\
         {}msg-type: {}\n\
         {}ap-options: {}\n\
         {}ticket:\n{}\n\
         {}authenticator:\n{}",
        indentation,
        ar.pvno,
        indentation,
        ar.msg_type,
        indentation,
        ap_options_to_string(*ar.ap_options),
        indentation,
        ticket_to_string(&ar.ticket, indent_level + INDENT_STEP),
        indentation,
        encrypted_data_to_string(&ar.authenticator, indent_level + INDENT_STEP),
    )
}

pub fn ap_options_to_string(ao: u32) -> String {
    let ap_options_names = [
        (ap_options::RESERVED, "reserved"),
        (ap_options::USE_SESSION_KEY, "use-session-key"),
        (ap_options::MUTUAL_REQUIRED, "mutual-required"),
    ];

    let mut names = Vec::new();

    for option in ap_options_names.iter() {
        if (ao & option.0) != 0 {
            names.push(option.1)
        }
    }

    return format!("{:#06x} -> {}", ao, names.join(" "));
}

pub fn as_rep_to_string(ar: &AsRep, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}pvno: {}\n\
         {}msg-type: {}\n\
         {}padata: {}\n\
         {}crealm: {}\n\
         {}cname:\n{}\n\
         {}ticket:\n{}\n\
         {}enc-part:\n{}",
        indentation,
        ar.pvno,
        indentation,
        msg_type_to_string(ar.msg_type),
        indentation,
        &ar.padata
            .as_ref()
            .map(|pds| format!(
                "\n{}",
                padatas_to_string(&pds, indent_level + INDENT_STEP)
            ))
            .unwrap_or(NONE.into()),
        indentation,
        ar.crealm,
        indentation,
        principal_name_to_string(&ar.cname, indent_level + INDENT_STEP),
        indentation,
        ticket_to_string(&ar.ticket, indent_level + INDENT_STEP),
        indentation,
        encrypted_data_to_string(&ar.enc_part, indent_level + INDENT_STEP)
    )
}

pub fn tgs_rep_to_string(tr: &TgsRep, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}pvno: {}\n\
         {}msg-type: {}\n\
         {}padata: {}\n\
         {}crealm: {}\n\
         {}cname:\n{}\n\
         {}ticket:\n{}\n\
         {}enc-part:\n{}",
        indentation,
        tr.pvno,
        indentation,
        msg_type_to_string(tr.msg_type),
        indentation,
        &tr.padata
            .as_ref()
            .map(|pds| format!(
                "\n{}",
                padatas_to_string(&pds, indent_level + INDENT_STEP)
            ))
            .unwrap_or(NONE.into()),
        indentation,
        tr.crealm,
        indentation,
        principal_name_to_string(&tr.cname, indent_level + INDENT_STEP),
        indentation,
        ticket_to_string(&tr.ticket, indent_level + INDENT_STEP),
        indentation,
        encrypted_data_to_string(&tr.enc_part, indent_level + INDENT_STEP)
    )
}

pub fn padatas_to_string(padatas: &Vec<PaData>, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    let mut vs = Vec::new();

    for (i, pd) in padatas.iter().enumerate() {
        vs.push(format!(
            "{}[{}]\n\
             {}",
            indentation,
            i,
            padata_to_string(pd, indent_level)
        ))
    }

    return vs.join("\n");
}

pub fn padata_to_string(padata: &PaData, indent_level: usize) -> String {
    let indentation = indent(indent_level);

    return format!(
        "{}padata-type: {}\n\
         {}padata-value:{}",
        indentation,
        padata_type_to_string(padata.padata_type),
        indentation,
        padata_value_to_string(&padata, indent_level + INDENT_STEP)
            .map(|v| format!("\n{}", v))
            .unwrap_or(format!(
                " {}",
                octet_string_to_string(&padata.padata_value)
            ))
    );
}

pub fn padata_value_to_string(
    padata: &PaData,
    indent_level: usize,
) -> Option<String> {
    match padata.padata_type {
        pa_data_types::PA_ETYPE_INFO2 => {
            if let Ok((_, etype_info2)) =
                EtypeInfo2::parse(&padata.padata_value)
            {
                return Some(etype_info2_to_string(&etype_info2, indent_level));
            }
        }
        pa_data_types::PA_PAC_REQUEST => {
            if let Ok((_, pac_request)) =
                KerbPaPacRequest::parse(&padata.padata_value)
            {
                return Some(pa_pac_request_to_string(
                    &pac_request,
                    indent_level,
                ));
            }
        }
        pa_data_types::PA_ENC_TIMESTAMP => {
            if let Ok((_, pa_enc_timestamp)) =
                EncryptedData::parse(&padata.padata_value)
            {
                return Some(encrypted_data_to_string(
                    &pa_enc_timestamp,
                    indent_level,
                ));
            }
        }
        pa_data_types::PA_TGS_REQ => {
            if let Ok((_, pa_tgs_req)) = ApReq::parse(&padata.padata_value) {
                return Some(ap_req_to_string(&pa_tgs_req, indent_level));
            }
        }
        pa_data_types::PA_PAC_OPTIONS => {
            if let Ok((_, pa_pac_options)) =
                PaPacOptions::parse(&padata.padata_value)
            {
                return Some(pa_pac_options_to_string(
                    &pa_pac_options,
                    indent_level,
                ));
            }
        }
        pa_data_types::PA_FOR_USER => {
            if let Ok((_, pa_for_user)) = PaForUser::parse(&padata.padata_value)
            {
                return Some(pa_for_user_to_string(&pa_for_user, indent_level));
            }
        }
        _ => {}
    };
    return None;
}

fn pa_for_user_to_string(pu: &PaForUser, indent_level: usize) -> String {
    let indentation = indent(indent_level);

    format!(
        "{}userName:\n{}\n\
         {}userRealm: {}\n\
         {}cksum:\n{}\n\
         {}auth-package: {}
         ",
        indentation,
        principal_name_to_string(&pu.username, indent_level + INDENT_STEP),
        indentation,
        pu.userrealm,
        indentation,
        checksum_to_string(&pu.cksum, indent_level + INDENT_STEP),
        indentation,
        pu.auth_package,
    )
}

fn checksum_to_string(ck: &Checksum, indent_level: usize) -> String {
    let indentation = indent(indent_level);

    format!(
        "{}cksumtype: {}\n\
         {}checksum: {}",
        indentation,
        checksum_type_to_string(ck.cksumtype),
        indentation,
        octet_string_to_string(&ck.checksum),
    )
}

fn checksum_type_to_string(ct: i32) -> String {
    return format!("{:#06x} -> {}", ct, checksum_type_name(ct));
}

fn checksum_type_name(ct: i32) -> &'static str {
    match ct {
        checksum_types::HMAC_MD5 => "hmac-md5",
        checksum_types::HMAC_SHA1_96_AES128 => "hmac-sha1-96-aes128",
        checksum_types::HMAC_SHA1_96_AES256 => "hmac-sha1-96-aes256",
        checksum_types::HMAC_SHA1_DES3_KD => "hmac-sha1-des3-kd",
        checksum_types::RSA_MD4_DES => "rsa-md4-des",
        checksum_types::RSA_MD5_DES => "rsa-md5-des",
        _ => UNKNOWN,
    }
}

fn pa_pac_options_to_string(po: &PaPacOptions, indent_level: usize) -> String {
    let indentation = indent(indent_level);

    let pa_pac_options_names = [
        (pa_pac_options::BRANCH_AWARE, "branch-aware"),
        (pa_pac_options::CLAIMS, "claims"),
        (pa_pac_options::FORWARD_TO_FULL_DC, "forward-to-full-dc"),
        (
            pa_pac_options::RESOURCE_BASED_CONSTRAINED_DELEGATION,
            "resource-based-constrained-delegation",
        ),
    ];

    let mut names = Vec::new();

    for option in pa_pac_options_names.iter() {
        if (po.kerberos_flags.flags & option.0) != 0 {
            names.push(option.1)
        }
    }

    return format!(
        "{}kerberos-flags: {:#06x} -> {}",
        indentation,
        po.kerberos_flags.flags,
        names.join(" ")
    );
}

pub fn pa_pac_request_to_string(
    pr: &KerbPaPacRequest,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    format!("{}include-pac: {}", indentation, pr.include_pac)
}

pub fn padata_type_to_string(padata_type: i32) -> String {
    format!("{} -> {}", padata_type, padata_type_name(padata_type))
}

pub fn padata_type_name(padata_type: i32) -> &'static str {
    match padata_type {
        pa_data_types::PA_TGS_REQ => "pa-tgs-req",
        pa_data_types::PA_ENC_TIMESTAMP => "pa-enc-timestamp",
        pa_data_types::PA_PW_SALT => "pa-pw-salt",
        pa_data_types::PA_ENC_UNIX_TIME => "pa-enc-unix-time",
        pa_data_types::PA_SANDIA_SECUREID => "pa-sandia-secureid",
        pa_data_types::PA_SESAME => "pa-sesame",
        pa_data_types::PA_OSF_DCE => "pa-osf-dce",
        pa_data_types::PA_CYBERSAFE_SECUREID => "pa-cybersafe-secureid",
        pa_data_types::PA_AFS3_SALT => "pa-afs3-salt",
        pa_data_types::PA_ETYPE_INFO => "pa-etype-info",
        pa_data_types::PA_SAM_CHALLENGE => "pa-sam-challenge",
        pa_data_types::PA_SAM_RESPONSE => "pa-sam-response",
        pa_data_types::PA_PK_AS_REQ_OLD => "pa-pk-as-req-old",
        pa_data_types::PA_PK_AS_REP_OLD => "pa-pk-as-rep-old",
        pa_data_types::PA_PK_AS_REQ => "pa-pk-as-req",
        pa_data_types::PA_PK_AS_REP => "pa-pk-as-rep",
        pa_data_types::PA_ETYPE_INFO2 => "pa-etype-info2",
        pa_data_types::PA_SVR_REFERRAL_INFO => {
            "pa-srv-referral-info | pa-use-specified-kvno"
        }
        pa_data_types::PA_SAM_REDIRECT => "pa-sam-redirect",
        pa_data_types::PA_GET_FROM_TYPED_DATA => {
            "pa-get-from-typed-data | td-padata"
        }
        pa_data_types::PA_SAM_ETYPE_INFO => "pa-sam-etype-info",
        pa_data_types::PA_ALT_PRINC => "pa-alt-princ",
        pa_data_types::PA_SAM_CHALLENGE2 => "pa-sam-challenge2",
        pa_data_types::PA_SAM_RESPONSE2 => "pa-sam-response2",
        pa_data_types::PA_EXTRA_TGT => "pa-extra-tgt",
        pa_data_types::TD_PKINIT_CMS_CERTIFICATES => {
            "td-pkinit-cms-certificates"
        }
        pa_data_types::TD_KRB_PRINCIPAL => "td-krb-principal",
        pa_data_types::TD_KRB_REALM => "td-krb-realm",
        pa_data_types::TD_TRUSTED_CERTIFIERS => "td-trusted-certifiers",
        pa_data_types::TD_CERTIFICATE_INDEX => "td-certificate-index",
        pa_data_types::TD_APP_DEFINED_ERROR => "td-app-defined-error",
        pa_data_types::TD_REQ_NONCE => "td-req-nonce",
        pa_data_types::TD_REQ_SEQ => "td-req-seq",
        pa_data_types::PA_PAC_REQUEST => "pa-pac-request",
        pa_data_types::PA_FOR_USER => "pa-for-user",
        pa_data_types::PA_FX_COOKIE => "pa-fx-cookien",
        pa_data_types::PA_FX_FAST => "pa-fx-fast",
        pa_data_types::PA_FX_ERROR => "pa-fx-error",
        pa_data_types::PA_ENCRYPTED_CHALLENGE => "pa-encrypted-challenge",
        pa_data_types::KERB_KEY_LIST_REQ => "kerb-key-list-req",
        pa_data_types::KERB_KEY_LIST_REP => "kerb-key-list-rep",
        pa_data_types::PA_SUPPORTED_ENCTYPES => "pa-supported-enctypes",
        pa_data_types::PA_PAC_OPTIONS => "pa-pac-options",
        _ => UNKNOWN,
    }
}

pub fn msg_type_to_string(msg_type: i32) -> String {
    format!("{} -> {}", msg_type, msg_type_name(msg_type))
}

pub fn msg_type_name(msg_type: i32) -> &'static str {
    match msg_type {
        message_types::KRB_AS_REQ => "krb-as-req",
        message_types::KRB_AS_REP => "krb-as-rep",
        message_types::KRB_TGS_REQ => "krb-tgs-req",
        message_types::KRB_TGS_REP => "krb-tgs-rep",
        message_types::KRB_AP_REQ => "krb-ap-req",
        message_types::KRB_AP_REP => "krb-ap-rep",
        message_types::KRB_RESERVED16 => "krb-reserved16",
        message_types::KRB_RESERVED17 => "krb-reserved17",
        message_types::KRB_SAFE => "krb-safe",
        message_types::KRB_PRIV => "krb-priv",
        message_types::KRB_CRED => "krb-cred",
        message_types::KRB_ERROR => "krb-error",
        _ => UNKNOWN,
    }
}

pub fn tickets_to_string(tickets: &Vec<Ticket>, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    let mut vs = Vec::new();

    for (i, ticket) in tickets.iter().enumerate() {
        vs.push(format!(
            "{}[{}]\n\
             {}",
            indentation,
            i,
            ticket_to_string(ticket, indent_level)
        ))
    }

    return vs.join("\n");
}

pub fn ticket_to_string(tkt: &Ticket, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}tkt-vno: {}\n\
         {}realm: {}\n\
         {}sname:\n{}\n\
         {}enc-part:\n{}",
        indentation,
        tkt.tkt_vno,
        indentation,
        tkt.realm,
        indentation,
        principal_name_to_string(&tkt.sname, indent_level + INDENT_STEP),
        indentation,
        encrypted_data_to_string(&tkt.enc_part, indent_level + INDENT_STEP)
    )
}

pub fn encrypted_data_to_string(
    ed: &EncryptedData,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}etype: {}\n\
         {}kvno: {}\n\
         {}cipher: {}",
        indentation,
        etype_to_string(ed.etype),
        indentation,
        ed.kvno.map(|v| format!("{}", v)).unwrap_or(NONE.into()),
        indentation,
        format!("{} bytes", ed.cipher.len())
    )
}

fn indent(level: usize) -> String {
    let mut ind = "".to_string();
    for _ in 0..level {
        ind = format!(" {}", ind);
    }
    return ind;
}

pub fn krb_cred_info_to_string(
    kci: &KrbCredInfo,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}key:\n{}\n\
         {}prealm: {}\n\
         {}pname:\n{}\n\
         {}flags: {}\n\
         {}authtime: {}\n\
         {}starttime: {}\n\
         {}endtime: {}\n\
         {}renew-till: {}\n\
         {}srealm: {}\n\
         {}sname:\n{}\n\
         {}caddr: <Not Implemented>",
        indentation,
        encryption_key_to_string(&kci.key, indent_level + INDENT_STEP),
        indentation,
        &kci.prealm.as_ref().unwrap_or(&NONE.to_string()),
        indentation,
        &kci.pname
            .as_ref()
            .map(|v| principal_name_to_string(&v, indent_level + INDENT_STEP))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.flags
            .as_ref()
            .map(|v| kerberos_flags_to_string(v.flags))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.authtime
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.starttime
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.endtime
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.renew_till
            .as_ref()
            .map(|v| kerberos_time_to_string(&v))
            .unwrap_or(NONE.into()),
        indentation,
        &kci.srealm.as_ref().unwrap_or(&NONE.into()),
        indentation,
        &kci.sname
            .as_ref()
            .map(|v| principal_name_to_string(&v, indent_level + INDENT_STEP))
            .unwrap_or(NONE.into()),
        indentation
    )
}

pub fn encryption_key_to_string(
    ek: &EncryptionKey,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}keytype: {}\n\
         {}keyvalue: {}",
        indentation,
        etype_to_string(ek.keytype),
        indentation,
        octet_string_to_string(&ek.keyvalue)
    )
}

pub fn octet_string_to_string(os: &Vec<u8>) -> String {
    let mut vs = Vec::new();

    for o in os.iter() {
        vs.push(format!("{:02x}", o));
    }
    return vs.join("");
}

pub fn principal_name_to_string(
    pname: &PrincipalName,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}name-type: {}\n\
         {}name-string: {}",
        indentation,
        principal_name_type_to_string(pname.name_type),
        indentation,
        pname.name_string.join("/")
    )
}

pub fn principal_name_type_to_string(name_type: i32) -> String {
    format!("{} -> {}", name_type, name_type_name(name_type))
}

pub fn kerberos_time_to_string(krb_time: &KerberosTime) -> String {
    krb_time
        .with_timezone(&Local)
        .format("%m/%d/%Y %H:%M:%S")
        .to_string()
}

pub fn kerberos_flags_to_string(flags: u32) -> String {
    let mut flags_strs = Vec::new();

    if (flags & ticket_flags::FORWARDABLE) != 0 {
        flags_strs.push("forwardable")
    }
    if (flags & ticket_flags::FORWARDED) != 0 {
        flags_strs.push("forwarded")
    }
    if (flags & ticket_flags::PROXIABLE) != 0 {
        flags_strs.push("proxiable")
    }
    if (flags & ticket_flags::PROXY) != 0 {
        flags_strs.push("proxy")
    }
    if (flags & ticket_flags::MAY_POSTDATE) != 0 {
        flags_strs.push("may_postdate")
    }
    if (flags & ticket_flags::POSTDATE) != 0 {
        flags_strs.push("postdate")
    }
    if (flags & ticket_flags::RENEWABLE) != 0 {
        flags_strs.push("renewable")
    }
    if (flags & ticket_flags::INITIAL) != 0 {
        flags_strs.push("initial")
    }
    if (flags & ticket_flags::INVALID) != 0 {
        flags_strs.push("invalid")
    }
    if (flags & ticket_flags::HW_AUTHENT) != 0 {
        flags_strs.push("hw_authent")
    }
    if (flags & ticket_flags::PRE_AUTHENT) != 0 {
        flags_strs.push("pre_authent")
    }
    if (flags & ticket_flags::TRANSITED_POLICY_CHECKED) != 0 {
        flags_strs.push("transited_policy_checked")
    }
    if (flags & ticket_flags::OK_AS_DELEGATE) != 0 {
        flags_strs.push("ok_as_delegate")
    }
    if (flags & ticket_flags::REQUEST_ANONYMOUS) != 0 {
        flags_strs.push("anonymous")
    }
    if (flags & ticket_flags::NAME_CANONICALIZE) != 0 {
        flags_strs.push("name_canonicalize")
    }

    return format!("{:#06x} -> {}", flags, flags_strs.join(" "));
}

pub fn etypes_to_string(etypes: &Vec<i32>, indent_level: usize) -> String {
    let indentation = indent(indent_level);
    let mut vs = Vec::new();

    for (i, et) in etypes.iter().enumerate() {
        vs.push(format!(
            "{}[{}]\n\
             {}{}",
            indentation,
            i,
            indentation,
            etype_to_string(*et)
        ))
    }

    return vs.join("\n");
}

pub fn etype_to_string(etype: i32) -> String {
    format!("{} -> {}", etype, etype_name(etype))
}

pub fn etype_name(etype: i32) -> &'static str {
    match etype {
        etypes::AES128_CTS_HMAC_SHA1_96 => "aes128-cts-hmac-sha1-96",
        etypes::AES256_CTS_HMAC_SHA1_96 => "aes256-cts-hmac-sha1-96",
        etypes::DES_CBC_CRC => "des-cbc-crc",
        etypes::DES_CBC_MD5 => "des-cbc-md5",
        etypes::NO_ENCRYPTION => "no encryption",
        etypes::RC4_HMAC => "rc4-hmac",
        etypes::RC4_HMAC_EXP => "rc4-hmac-exp",
        etypes::RC4_HMAC_OLD_EXP => "rc4-hmac-old-exp",
        _ => UNKNOWN,
    }
}

pub fn name_type_name(name_type: i32) -> &'static str {
    match name_type {
        principal_names::NT_UNKNOWN => "nt-unknown",
        principal_names::NT_PRINCIPAL => "nt-principal",
        principal_names::NT_SRV_INST => "nt-srv-inst",
        principal_names::NT_SRV_HST => "nt-srv-hst",
        principal_names::NT_SRV_XHST => "nt-srv-xhst",
        principal_names::NT_UID => "nt-uid",
        principal_names::NT_X500_PRINCIPAL => "nt-x500-principal",
        principal_names::NT_SMTP_NAME => "nt-smtp-name",
        principal_names::NT_ENTERPRISE => "nt-enterprise",
        principal_names::NT_MS_PRINCIPAL => "nt-ms-principal",
        principal_names::NT_MS_PRINCIPAL_AND_ID => "nt-ms-principal-and-id",
        principal_names::NT_ENT_PRINCIPAL_AND_ID => "nt-ent-principal-and-id",
        _ => UNKNOWN,
    }
}

pub fn etype_info2_to_string(
    padatas: &EtypeInfo2,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    let mut vs = Vec::new();

    for (i, ei) in padatas.iter().enumerate() {
        vs.push(format!(
            "{}[{}]\n\
             {}",
            indentation,
            i,
            etype_info2_entry_to_string(ei, indent_level)
        ))
    }

    return vs.join("\n");
}

pub fn etype_info2_entry_to_string(
    entry: &EtypeInfo2Entry,
    indent_level: usize,
) -> String {
    let indentation = indent(indent_level);
    format!(
        "{}etype: {}\n\
         {}salt: {}\n\
         {}s2kparams: {}",
        indentation,
        etype_to_string(entry.etype),
        indentation,
        &entry.salt.as_ref().unwrap_or(&NONE.to_string()),
        indentation,
        &entry
            .s2kparams
            .as_ref()
            .map(|v| octet_string_to_string(&v))
            .unwrap_or(NONE.into())
    )
}
