use kerberos_asn1::{EncKdcRepPart, KrbCredInfo, PrincipalName};

pub fn new_krb_cred_info(
    enc_as_rep_part: EncKdcRepPart,
    prealm: String,
    pname: PrincipalName,
) -> KrbCredInfo {
    return KrbCredInfo {
        key: enc_as_rep_part.key,
        prealm: Some(prealm),
        pname: Some(pname),
        flags: Some(enc_as_rep_part.flags),
        authtime: Some(enc_as_rep_part.authtime),
        starttime: enc_as_rep_part.starttime,
        endtime: Some(enc_as_rep_part.endtime),
        renew_till: enc_as_rep_part.renew_till,
        srealm: Some(enc_as_rep_part.srealm),
        sname: Some(enc_as_rep_part.sname),
        caddr: enc_as_rep_part.caddr,
    };
}
