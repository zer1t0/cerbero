mod args;
mod as_req_builder;
mod ask_tgs;
mod ask_tgt;
mod senders;
mod utils;

use args::{args, Arguments, ArgumentsParser};
use ask_tgt::ask_tgt;
use kerberos_asn1::{
    Asn1Object, EncKrbCredPart, KrbCred, KrbCredInfo, PrincipalName, Realm,
    Ticket, Authenticator, KerberosTime
};
use kerberos_ccache::CCache;
use kerberos_constants::etypes::NO_ENCRYPTION;
use std::convert::TryInto;
use std::fs;
use chrono::{Timelike, Utc};

use utils::{compose_tgt_service, username_to_principal_name};

fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    if let Some(service) = &args.service {
        if let Err(error) =
            ask_tgs("mickey.ccache", service, args.username, args.realm)
        {
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
    service: &str,
    username: String,
    realm: String,
) -> Result<(), String> {
    let krb_cred = parse_creds_file(creds_file)?;

    let cname = username_to_principal_name(username.clone());
    let tgt_service = compose_tgt_service(realm.clone());
    let krb_cred_plain = KrbCredPlain::try_from_krb_cred(krb_cred)?;

    let (ticket, krb_cred_info) = krb_cred_plain
        .look_for_user_creds(&cname, &tgt_service)
        .ok_or(format!("No TGT found for '{}", username))?;

    let now = Utc::now();
    
    let mut authenticator = Authenticator::default();
    authenticator.authenticator_vno = 5;
    authenticator.crealm = realm;
    authenticator.cname = cname;
    authenticator.cusec = (now.nanosecond() / 1000) as i32;
    authenticator.ctime = KerberosTime::from(now);

    
    

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
