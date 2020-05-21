use kerberos_asn1::{Asn1Object, EncryptedData, Ticket};
use kerberos_asn1::{
    EncKdcRepPart, EncKrbCredPart, KrbCred, KrbCredInfo, PrincipalName,
};
use kerberos_constants;
use kerberos_constants::etypes;

pub fn new_krb_cred(
    enc_as_rep_part: EncKdcRepPart,
    ticket: Ticket,
    prealm: String,
    pname: PrincipalName,
) -> KrbCred {
    let krb_cred_info = new_krb_cred_info(enc_as_rep_part, prealm, pname);

    let mut enc_krb_cred_part = EncKrbCredPart::default();
    enc_krb_cred_part.ticket_info.push(krb_cred_info);

    let mut krb_cred = KrbCred::default();
    krb_cred.tickets.push(ticket);
    krb_cred.enc_part = EncryptedData {
        etype: etypes::NO_ENCRYPTION,
        kvno: None,
        cipher: enc_krb_cred_part.build(),
    };

    return krb_cred;
}

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
