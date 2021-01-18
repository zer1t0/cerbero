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
            Arg::with_name("tgt")
                .long("tgt")
                .short("t")
                .help("Only show TGTs [ccache only]"),
        )
        .arg(
            Arg::with_name("srealm")
                .long("srealm")
                .takes_value(true)
                .help("Only tickets for services in the given realm [ccache only]")
        )
        .arg(
            Arg::with_name("keytab")
                .long("keytab")
                .short("K")
                .help(
                    "Search keytab file in environment (KRB5_KTNAME) instead of ccache file (KRB5CCNAME)"
                )
        )
}

pub struct Arguments {
    pub in_file: Option<String>,
    pub search_keytab: bool,
    pub only_tgts: bool,
    pub srealm: Option<String>,
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
            search_keytab: self.matches.is_present("keytab"),
            only_tgts: self.matches.is_present("tgt"),
            srealm: self.matches.value_of("srealm").map(|s| s.into()),
        };
    }
}
