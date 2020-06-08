pub mod ask;
pub mod asreproast;
pub mod brute;
pub mod convert;
pub mod craft;
pub mod hash;
pub mod kerberoast;
pub mod list;
mod validators;

use clap::{App, AppSettings, ArgMatches};

pub fn args() -> App<'static, 'static> {
    App::new(env!("CARGO_PKG_NAME"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .setting(AppSettings::SubcommandRequired)
        .subcommand(ask::command())
        .subcommand(asreproast::command())
        .subcommand(brute::command())
        .subcommand(convert::command())
        .subcommand(craft::command())
        .subcommand(hash::command())
        .subcommand(kerberoast::command())
        .subcommand(list::command())
}

pub enum Arguments {
    Ask(ask::Arguments),
    AsRepRoast(asreproast::Arguments),
    Brute(brute::Arguments),
    Convert(convert::Arguments),
    Craft(craft::Arguments),
    Hash(hash::Arguments),
    KerbeRoast(kerberoast::Arguments),
    List(list::Arguments),
}

pub struct ArgumentsParser {}

impl ArgumentsParser {
    pub fn parse<'a>(matches: &'a ArgMatches) -> Arguments {
        match matches.subcommand_name().unwrap() {
            name @ ask::COMMAND_NAME => {
                return Arguments::Ask(ask::ArgumentsParser::parse(
                    matches.subcommand_matches(name).unwrap(),
                ));
            }
            name @ asreproast::COMMAND_NAME => {
                return Arguments::AsRepRoast(
                    asreproast::ArgumentsParser::parse(
                        matches.subcommand_matches(name).unwrap(),
                    ),
                );
            }
            name @ brute::COMMAND_NAME => {
                return Arguments::Brute(brute::ArgumentsParser::parse(
                    matches.subcommand_matches(name).unwrap(),
                ));
            }
            name @ convert::COMMAND_NAME => {
                return Arguments::Convert(convert::ArgumentsParser::parse(
                    matches.subcommand_matches(name).unwrap(),
                ));
            }
            name @ craft::COMMAND_NAME => {
                return Arguments::Craft(craft::ArgumentsParser::parse(
                    matches.subcommand_matches(name).unwrap(),
                ));
            }
            name @ hash::COMMAND_NAME => {
                return Arguments::Hash(hash::ArgumentsParser::parse(
                    matches.subcommand_matches(name).unwrap(),
                ));
            }
            name @ kerberoast::COMMAND_NAME => {
                return Arguments::KerbeRoast(
                    kerberoast::ArgumentsParser::parse(
                        matches.subcommand_matches(name).unwrap(),
                    ),
                );
            }
            name @ list::COMMAND_NAME => {
                return Arguments::List(list::ArgumentsParser::parse(
                    matches.subcommand_matches(name).unwrap(),
                ));
            }
            _ => unreachable!("Unknown command"),
        }
    }
}
