mod args;
mod as_req_builder;
mod ask_tgs;
mod ask_tgt;
mod senders;
mod utils;

use args::{args, Arguments, ArgumentsParser};
use ask_tgt::ask_tgt;
use chrono::{Timelike, Utc};
use kerberos_asn1::{
    ApReq, Asn1Object, Authenticator, EncKrbCredPart, EncryptedData,
    KerberosTime, KrbCred, KrbCredInfo, PaData, PrincipalName, Realm, Ticket,
};
use kerberos_ccache::CCache;
use kerberos_constants::etypes::NO_ENCRYPTION;
use kerberos_constants::key_usages::KEY_USAGE_TGS_REQ_AUTHEN;
use kerberos_constants::pa_data_types::PA_TGS_REQ;
use kerberos_constants::principal_names::NT_SRV_INST;
use kerberos_crypto::new_kerberos_cipher;
use std::convert::TryInto;
use std::fs;

use crate::as_req_builder::KdcReqBuilder;
use crate::senders::send_recv_tgs;
use std::net::SocketAddr;

use utils::username_to_principal_name;

fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    let kdc_address = SocketAddr::new(args.kdc_ip, args.kdc_port);

    if let Some(service) = args.service {
        if let Err(error) = ask_tgs(
            "mickey.ccache",
            service,
            args.username,
            args.realm,
            &kdc_address,
        ) {
            eprintln!("{}", error);
        }
    } else {
        if let Err(error) = ask_tgt(args) {
            eprintln!("{}", error);
        }
    }
}

fn ask_tgs(
    creds_file: &str,
    service: String,
    username: String,
    realm: String,
    kdc_addr: &SocketAddr,
) -> Result<(), String> {
    let krb_cred = parse_creds_file(creds_file)?;

    let cname = username_to_principal_name(username.clone());
    let tgt_service = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: vec!["krbtgt".into(), realm.clone()],
    };
    let krb_cred_plain = KrbCredPlain::try_from_krb_cred(krb_cred)?;

    let (ticket, krb_cred_info) = krb_cred_plain
        .look_for_user_creds(&cname, &tgt_service)
        .ok_or(format!("No TGT found for '{}", username))?;

    // crear un default en kerberos_asn1
    let mut authenticator = Authenticator::default();
    authenticator.crealm = realm.clone();
    authenticator.cname = cname;

    let authen_etype = krb_cred_info.key.keytype;
    let cipher = new_kerberos_cipher(authen_etype)
        .map_err(|_| format!("No supported etype: {}", authen_etype))?;

    let encrypted_authenticator = cipher.encrypt(
        &krb_cred_info.key.keyvalue,
        KEY_USAGE_TGS_REQ_AUTHEN,
        &authenticator.build(),
    );

    // crear default de ApReq en kerberos_asn1, setear el
    let mut ap_req = ApReq::default();
    ap_req.ticket = ticket.clone();
    ap_req.authenticator = EncryptedData {
        etype: authen_etype,
        kvno: None,
        cipher: encrypted_authenticator,
    };

    let pa_tgs_req = PaData {
        padata_type: PA_TGS_REQ,
        padata_value: ap_req.build(),
    };

    let service_parts: Vec<String> =
        service.split("/").map(|s| s.to_string()).collect();

    let tgs_req = KdcReqBuilder::new(realm)
        .push_padata(pa_tgs_req)
        .sname(Some(PrincipalName {
            name_type: NT_SRV_INST,
            name_string: service_parts,
        }))
        .build_tgs_req();

    let rep = send_recv_tgs(kdc_addr, &tgs_req).expect("Error sending AsReq");

    return Ok(());
}

fn parse_creds_file(creds_file: &str) -> Result<KrbCred, String> {
    let data = fs::read(creds_file).map_err(|err| {
        format!("Unable to read the file '{}': {}", creds_file, err)
    })?;

    match CCache::parse(&data) {
        Ok((_, ccache)) => {
            return ccache.try_into().map_err(|_| {
                format!(
                    "Error parsing ccache data content of file '{}'",
                    creds_file
                )
            });
        }
        Err(_) => {
            return Ok(KrbCred::parse(&data)
                .map_err(|_| {
                    format!("Error parsing content of file '{}'", creds_file)
                })?
                .1);
        }
    }
}

struct KrbCredPlain {
    pub tickets: Vec<Ticket>,
    pub cred_part: EncKrbCredPart,
}

impl KrbCredPlain {
    fn try_from_krb_cred(krb_cred: KrbCred) -> Result<Self, String> {
        if krb_cred.enc_part.etype != NO_ENCRYPTION {
            return Err(format!("Unable to decrypt the credentials"));
        }

        let (_, cred_part) = EncKrbCredPart::parse(&krb_cred.enc_part.cipher)
            .map_err(|_| {
            format!("Error parsing credentials: EncKrbCredPart")
        })?;

        return Ok(Self {
            tickets: krb_cred.tickets,
            cred_part: cred_part,
        });
    }

    fn look_for_user_creds<'a>(
        &'a self,
        username: &PrincipalName,
        service: &PrincipalName,
    ) -> Option<(&'a Ticket, &'a KrbCredInfo)> {
        for (ticket, cred_info) in
            self.tickets.iter().zip(self.cred_part.ticket_info.iter())
        {
            if let Some(pname) = &cred_info.pname {
                if let Some(sname) = &cred_info.sname {
                    if pname == username && sname == service {
                        return Some((ticket, cred_info));
                    }
                }
            }
        }

        return None;
    }
}
