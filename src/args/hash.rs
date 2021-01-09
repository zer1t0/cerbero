use super::validators;
use crate::core::KrbUser;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::convert::TryInto;

pub const COMMAND_NAME: &str = "hash";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Calculate password hashes/Kerberos keys")
        .arg(
            Arg::with_name("password")
                .takes_value(true)
                .help("Password of user")
                .required(true),
        )
        .arg(
            Arg::with_name("user")
                .long("user")
                .short("u")
                .takes_value(true)
                .help(
                    "User in format <domain>/<username> (required for AES keys)",
                )
                .validator(validators::is_krb_user),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
}

#[derive(Debug)]
pub struct Arguments {
    pub user: Option<KrbUser>,
    pub password: String,
    pub verbosity: usize,
}

pub struct ArgumentsParser<'a> {
    matches: &'a ArgMatches<'a>,
}

impl<'a> ArgumentsParser<'a> {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let parser = Self { matches: matches };
        return parser._parse();
    }

    fn _parse(&self) -> Arguments {
        return Arguments {
            user:  self.matches.value_of("user").map(|u| u.try_into().unwrap()),
            password: self.matches.value_of("password").unwrap().into(),
            verbosity: self.matches.occurrences_of("verbosity") as usize,
        };
    }
}
