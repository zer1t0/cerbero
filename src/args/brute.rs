use super::validators;
use crate::core::CredFormat;
use crate::communication::TransportProtocol;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::net::IpAddr;

pub const COMMAND_NAME: &str = "brute";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Perform a bruteforce attack against kerberos protocol")
        .arg(
            Arg::with_name("realm")
                .takes_value(true)
                .help("Domain/Realm to brute-force")
                .required(true),
        )
        .arg(
            Arg::with_name("users")
                .takes_value(true)
                .help("Usernames to brute-force")
                .required(true),
        )
        .arg(
            Arg::with_name("passwords")
                .takes_value(true)
                .help("Passwords to brute-force")
                .required(true),
        )
        .arg(
            Arg::with_name("kdc-ip")
                .long("kdc-ip")
                .alias("dc-ip")
                .short("k")
                .value_name("ip")
                .takes_value(true)
                .help("The address of the KDC (usually the Domain Controller)")
                .validator(validators::is_ip),
        )
        .arg(
            Arg::with_name("udp")
                .long("udp")
                .help("Use udp as transport protocol"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
        .arg(
            Arg::with_name("save-tickets")
                .long("save-tickets")
                .help("Save the retrieved TGTs in files"),
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
}

#[derive(Debug)]
pub struct Arguments {
    pub realm: String,
    pub users: String,
    pub passwords: String,
    pub kdc_ip: Option<IpAddr>,
    pub cred_format: Option<CredFormat>,
    pub transport_protocol: TransportProtocol,
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
        let realm = self.matches.value_of("realm").unwrap().into();
        let users = self.matches.value_of("users").unwrap().into();
        let passwords = self.matches.value_of("passwords").unwrap().into();
        let kdc_ip = self.parse_kdc_ip();
        let cred_format = self.parse_cred_format();

        return Arguments {
            realm,
            users,
            passwords,
            kdc_ip,
            cred_format,
            transport_protocol: self.parse_transport_protocol(),
            verbosity: self.matches.occurrences_of("verbosity") as usize,
        };
    }

    fn parse_kdc_ip(&self) -> Option<IpAddr> {
        let kdc_ip = self.matches.value_of("kdc-ip")?;
        return Some(kdc_ip.parse::<IpAddr>().unwrap());
    }

    fn parse_cred_format(&self) -> Option<CredFormat> {
        if !self.matches.is_present("save-tickets") {
            return None;
        }

        let format = self.matches.value_of("cred-format").unwrap();

        if format == "krb" {
            return Some(CredFormat::Krb);
        }

        return Some(CredFormat::Ccache);
    }

    fn parse_transport_protocol(&self) -> TransportProtocol {
        if self.matches.is_present("udp") {
            return TransportProtocol::UDP;
        }

        return TransportProtocol::TCP;
    }
}
