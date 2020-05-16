pub mod ask;
pub mod convert;
mod validators;

use clap::{App, AppSettings, ArgMatches};

pub fn args() -> App<'static, 'static> {
    App::new(env!("CARGO_PKG_NAME"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .setting(AppSettings::SubcommandRequired)
        .subcommand(ask::command())
        .subcommand(convert::command())
}

pub enum Arguments {
    Ask(ask::Arguments),
    Convert(convert::Arguments)
}

pub struct ArgumentsParser {}

impl ArgumentsParser {
    pub fn parse<'a>(matches: &'a ArgMatches) -> Arguments {
        match matches.subcommand_name().unwrap() {
            ask::COMMAND_NAME => {
                return Arguments::Ask(ask::ArgumentsParser::parse(
                    matches.subcommand_matches(ask::COMMAND_NAME).unwrap(),
                ));
            }
            convert::COMMAND_NAME => {
                return Arguments::Convert(convert::ArgumentsParser::parse(
                    matches.subcommand_matches(convert::COMMAND_NAME).unwrap(),
                ));
            }
            _ => unreachable!("Unknown command"),
        }
    }
}
