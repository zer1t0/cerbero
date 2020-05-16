use clap::{App, Arg, ArgMatches, SubCommand};

pub const COMMAND_NAME: &str = "list";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Describe the credentials stored in a file")
        .arg(
            Arg::with_name("in-file")
                .takes_value(true)
                .help("File to be described"),
        )
        .arg(
            Arg::with_name("flags")
                .long("flags")
                .short("f")
                .help("Shows credentials flags"),
        )
        .arg(
            Arg::with_name("etypes")
                .long("etypes")
                .short("e")
                .help("Shows the encryption types"),
        )
}

pub struct Arguments {
    pub in_file: Option<String>,
    pub flags: bool,
    pub etypes: bool,
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
            in_file: self.matches.value_of("in-file").map(|s| s.into()),
            flags: self.matches.is_present("flags"),
            etypes: self.matches.is_present("etypes"),
        };
    }
}
