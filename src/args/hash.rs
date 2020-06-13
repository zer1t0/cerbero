use clap::{App, Arg, ArgMatches, SubCommand};

pub const COMMAND_NAME: &str = "hash";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Calculate password hashes")
        .arg(
            Arg::with_name("realm")
                .long("realm")
                .alias("domain")
                .short("d")
                .takes_value(true)
                .help("Domain/Realm for request the ticket")
                .required(true),
        )
        .arg(
            Arg::with_name("user")
                .long("user")
                .short("u")
                .takes_value(true)
                .help("Username for request the ticket")
                .required(true),
        )
        .arg(
            Arg::with_name("password")
                .long("password")
                .short("p")
                .takes_value(true)
                .help("Password of user")
                .required(true),
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
    pub realm: String,
    pub username: String,
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
            realm: self.matches.value_of("realm").unwrap().into(),
            username: self.matches.value_of("user").unwrap().into(),
            password: self.matches.value_of("password").unwrap().into(),
            verbosity: self.matches.occurrences_of("verbosity") as usize,
        };
    }
}
