use crate::core::stringifier::{
    etype_to_string, kerberos_flags_to_string, kerberos_time_to_string,
};
use crate::core::{load_file_ticket_creds, CredFormat, TicketCreds};
use crate::utils;
use crate::Result;

pub fn list(
    filepath: Option<String>,
    only_tgts: bool,
    srealm: Option<String>,
) -> Result<()> {
    if let Some(filepath) = filepath {
        match load_file_ticket_creds(&filepath) {
            Ok((ticket_creds, cred_format)) => {
                return Ok(list_ccache(
                    ticket_creds,
                    cred_format,
                    &filepath,
                    only_tgts,
                    srealm,
                ));
            }
            Err(err) => {
                return Err(err);
            }
        }
    }

    let filepath =
        utils::get_env_ticket_file().ok_or("Specify file or set KRB5CCNAME")?;
    let (ticket_creds, cred_format) = load_file_ticket_creds(&filepath)?;
    list_ccache(ticket_creds, cred_format, &filepath, only_tgts, srealm);

    return Ok(());
}

fn list_ccache(
    mut ticket_creds: TicketCreds,
    format: CredFormat,
    filepath: &str,
    only_tgts: bool,
    srealm: Option<String>,
) {
    if only_tgts {
        ticket_creds = ticket_creds.tgt();
    }

    if let Some(srealm) = srealm {
        ticket_creds = ticket_creds.srealm(&srealm);
    }

    print_ccache(ticket_creds, format, &filepath);
}

fn print_ccache(ticket_creds: TicketCreds, format: CredFormat, filepath: &str) {
    println!("Ticket cache ({}): FILE:{}", format, filepath);
    print_ccache_creds(ticket_creds);
}

fn print_ccache_creds(krb_creds: TicketCreds) {
    for ticket_info in krb_creds.iter() {
        println!("");
        let ticket = &ticket_info.ticket;
        let cred_info = &ticket_info.cred_info;

        let realm = &ticket.realm;
        let service = ticket.sname.name_string.join("/");
        let user_name = cred_info.pname.as_ref().unwrap().name_string.join("/");
        let user_realm = cred_info.prealm.as_ref().unwrap();

        println!("{}@{} => {}@{}", user_name, user_realm, service, realm);

        if let Some(starttime) = &cred_info.starttime {
            println!("Valid starting: {}", kerberos_time_to_string(starttime));
        }

        if let Some(endtime) = &cred_info.endtime {
            println!("Expires: {}", kerberos_time_to_string(endtime));
        }

        if let Some(renew_till) = &cred_info.renew_till {
            println!("Renew until: {}", kerberos_time_to_string(renew_till));
        }

        let flags = cred_info.flags.as_ref().unwrap().flags;
        println!("Flags: {}", kerberos_flags_to_string(flags));

        let etype_skey = cred_info.key.keytype;
        let etype_tkt = ticket.enc_part.etype;
        println!(
            "Etype (skey, tkt): {}, {}",
            etype_to_string(etype_skey),
            etype_to_string(etype_tkt)
        )
    }
}
