use crate::core::CredFormat;
use clap::{App, Arg, ArgMatches, SubCommand};

pub const COMMAND_NAME: &str = "convert";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Converts tickets files between ccache and krb")
        .arg(
            Arg::with_name("in-file")
                .long("input")
                .short("i")
                .takes_value(true)
                .help("Input file to be converted. Detected from KRB5CCNAME if not provided"),
        )
        .arg(
            Arg::with_name("out-file")
                .long("output")
                .short("o")
                .takes_value(true)
                .help("Path of file to write.")
                .required(true),
        )
        .arg(
            Arg::with_name("cred-format")
                .long("cred-format")
                .alias("ticket-format")
                .takes_value(true)
                .possible_values(&["krb", "ccache"])
                .help("Format to save the output file.If not specified is detected based on output file extension or input file format")
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
}

pub struct Arguments {
    pub in_file: Option<String>,
    pub out_file: String,
    pub cred_format: Option<CredFormat>,
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
        let in_file = self.matches.value_of("in-file").map(|s| s.into());
        let out_file = self.matches.value_of("out-file").unwrap().into();

        return Arguments {
            in_file,
            out_file,
            cred_format: self.parse_credential_format(),
            verbosity: self.matches.occurrences_of("verbosity") as usize,
        };
    }

    fn parse_credential_format(&self) -> Option<CredFormat> {
        let format = self.matches.value_of("cred-format")?;

        if format == "krb" {
            return Some(CredFormat::Krb);
        }

        return Some(CredFormat::Ccache);
    }
}
