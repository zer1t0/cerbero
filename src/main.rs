mod args;
mod commands;
mod communication;
mod core;
mod error;
mod utils;

use crate::args::{args, Arguments, ArgumentsParser};
use crate::communication::resolve_host;
use crate::communication::{new_krb_channel, KdcComm};
use crate::core::KrbUser;
use crate::core::{EmptyVault, FileVault, Vault};
use crate::error::Result;
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

    let creds_file = utils::get_ticket_file(
        args.out_file,
        &args.user.name,
        &args.credential_format,
    );

    let mut vault = FileVault::new(creds_file);

    let kdccomm = KdcComm::new(args.kdcs, args.transport_protocol);

    return commands::ask(
        args.user,
        args.user_key,
        args.impersonate_user,
        args.service,
        args.user_service,
        args.rename_service,
        &mut vault,
        args.credential_format,
        kdccomm,
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
    init_log(args.verbosity);
    let creds_file = utils::get_ticket_file(
        args.credential_file,
        &args.user.name,
        &args.credential_format,
    );

    let vault = FileVault::new(creds_file);

    return commands::craft(
        args.user,
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
    return commands::hash(&args.password, args.user.as_ref());
}

fn list(args: args::list::Arguments) -> Result<()> {
    init_log(0);
    return commands::list(args.in_file, args.only_tgts, args.srealm);
}

fn brute(args: args::brute::Arguments) -> Result<()> {
    init_log(args.verbosity);

    let usernames = match utils::read_file_lines(&args.users) {
        Ok(users) => users,
        Err(_) => vec![args.users],
    };

    let passwords = match utils::read_file_lines(&args.passwords) {
        Ok(passwords) => passwords,
        Err(_) => vec![args.passwords],
    };

    let kdc_ip = match args.kdc_ip {
        Some(ip) => ip,
        None => resolve_host(&args.realm, Vec::new())?,
    };
    let channel = new_krb_channel(kdc_ip, args.transport_protocol);

    return commands::brute(
        &args.realm,
        usernames,
        passwords,
        &*channel,
        args.cred_format,
    );
}

fn asreproast(args: args::asreproast::Arguments) -> Result<()> {
    init_log(args.verbosity);

    let usernames = match utils::read_file_lines(&args.users) {
        Ok(users) => users,
        Err(_) => vec![args.users],
    };

    let kdc_ip = match args.kdc_ip {
        Some(ip) => ip,
        None => resolve_host(&args.realm, Vec::new())?,
    };
    let channel = new_krb_channel(kdc_ip, args.transport_protocol);

    return commands::asreproast(
        &args.realm,
        usernames,
        args.crack_format,
        &*channel,
        args.etype,
    );
}

fn kerberoast(args: args::kerberoast::Arguments) -> Result<()> {
    init_log(args.verbosity);

    let kdccomm = KdcComm::new(args.kdcs, args.transport_protocol);

    let creds_file = match args.creds_file {
        Some(filename) => Some(filename),
        None => utils::get_env_ticket_file(),
    };

    let mut in_vault: Box<dyn Vault>;
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

    let out_ref_vault = out_vault.as_ref();

    return commands::kerberoast(
        args.user,
        args.user_services_file,
        &mut *in_vault,
        out_ref_vault.map(|a| a as &dyn Vault),
        args.user_key.as_ref(),
        args.credential_format,
        args.crack_format,
        args.etype,
        kdccomm,
    );
}
