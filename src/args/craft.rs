use super::validators;
use clap::{App, Arg, ArgMatches, SubCommand};

pub const COMMAND_NAME: &str = "craft";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Create golden and silver tickets")
        .arg(
            Arg::with_name("realm")
                .long("realm")
                .visible_alias("domain")
                .short("d")
                .takes_value(true)
                .help("Domain/Realm for ticket")
                .required(true),
        )
        .arg(
            Arg::with_name("realm-sid")
                .long("realm-sid")
                .visible_alias("domain-sid")
                .takes_value(true)
                .help("SID of the Domain/Realm for ticket")
                .required(true)
                .validator(validators::is_sid),
        )
        .arg(
            Arg::with_name("user")
                .long("user")
                .short("u")
                .takes_value(true)
                .help("Username for ticket")
                .required(true),
        )
        .arg(
            Arg::with_name("user-rid")
                .long("user-rid")
                .takes_value(true)
                .help("User RID for the ticket")
                .default_value("500")
                .validator(validators::is_u32),
        )
        .arg(
            Arg::with_name("service")
                .long("service")
                .visible_alias("spn")
                .takes_value(true)
                .value_name("spn")
                .help("SPN of the desired service"),
        )
        .arg(
            Arg::with_name("password")
                .long("password")
                .short("p")
                .takes_value(true)
                .help("Password of user"),
        )
        .arg(
            Arg::with_name("rc4")
                .long("rc4")
                .visible_alias("ntlm")
                .takes_value(true)
                .help("RC4 Kerberos key (NTLM hash of user)")
                .validator(validators::is_rc4_key),
        )
        .arg(
            Arg::with_name("aes-128")
                .long("aes-128")
                .takes_value(true)
                .help("AES 128 Kerberos key of user")
                .validator(validators::is_aes_128_key),
        )
        .arg(
            Arg::with_name("aes-256")
                .long("aes-256")
                .takes_value(true)
                .help("AES 256 Kerberos key of user")
                .validator(validators::is_aes_256_key),
        )
        .arg(
            Arg::with_name("groups")
                .long("groups")
                .alias("groups-rid")
                .takes_value(true)
                .use_delimiter(true)
                .help("RIDs of groups to include in ticket")
                .default_value("513,512,520,518,519")
                .validator(validators::is_u32),
        )
        .arg(
            Arg::with_name("cred-format")
                .long("cred-format")
                .alias("ticket-format")
                .takes_value(true)
                .possible_values(&["krb", "ccache"])
                .help("Format to save retrieved tickets.")
                .default_value("ccache"),
        )
        .arg(
            Arg::with_name("cred-file")
                .long("cred-file")
                .visible_alias("ticket-file")
                .takes_value(true)
                .value_name("file")
                .help("File to save ticket"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
}

pub struct Arguments {}

pub struct ArgumentsParser<'a> {
    matches: &'a ArgMatches<'a>,
}

impl<'a> ArgumentsParser<'a> {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let parser = Self { matches: matches };
        return parser._parse();
    }

    fn _parse(&self) -> Arguments {
        return Arguments {};
    }
}
