use super::validators;
use crate::crack_format::CrackFormat;
use crate::cred_format::CredentialFormat;
use crate::transporter::TransportProtocol;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::net::IpAddr;

pub const COMMAND_NAME: &str = "asreproast";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Perform a asreproast attack against kerberos protocol")
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
            Arg::with_name("crack-format")
                .long("crack-format")
                .takes_value(true)
                .possible_values(&["hashcat", "john"])
                .help("Format to save non preauth responses.")
                .default_value("hashcat"),
        )
}

#[derive(Debug)]
pub struct Arguments {
    pub realm: String,
    pub users: String,
    pub kdc_ip: Option<IpAddr>,
    pub kdc_port: u16,
    pub transport_protocol: TransportProtocol,
    pub verbosity: usize,
    pub crack_format: CrackFormat,
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
        let kdc_ip = self.parse_kdc_ip();

        return Arguments {
            realm,
            users,
            kdc_ip,
            kdc_port: 88,
            transport_protocol: self.parse_transport_protocol(),
            verbosity: self.matches.occurrences_of("verbosity") as usize,
            crack_format: self.parse_crack_format()
        };
    }

    fn parse_kdc_ip(&self) -> Option<IpAddr> {
        let kdc_ip = self.matches.value_of("kdc-ip")?;
        return Some(kdc_ip.parse::<IpAddr>().unwrap());
    }

    fn parse_crack_format(&self) -> CrackFormat {
        let format = self.matches.value_of("crack-format").unwrap();

        if format == "john" {
            return CrackFormat::John;
        }

        return CrackFormat::Hashcat;
    }

    fn parse_transport_protocol(&self) -> TransportProtocol {
        if self.matches.is_present("udp") {
            return TransportProtocol::UDP;
        }

        return TransportProtocol::TCP;
    }
}
