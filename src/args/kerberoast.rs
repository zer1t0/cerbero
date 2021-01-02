use super::validators;
use crate::core::CrackFormat;
use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::transporter::TransportProtocol;
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use kerberos_constants::etypes;
use kerberos_crypto::Key;
use std::convert::TryInto;
use std::net::IpAddr;

pub const COMMAND_NAME: &str = "kerberoast";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Perform a kerberoast attack")
        .arg(
            Arg::with_name("user")
                .long("user")
                .short("u")
                .takes_value(true)
                .help("User for request the ticket in format <domain>/<username>")
                .required(true)
                .validator(validators::is_kerberos_user),
        )
        .arg(
            Arg::with_name("services")
                .long("services")
                .short("s")
                .takes_value(true)
                .help("Services to request ticket for")
                .required(true),
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
                .alias("ntlm")
                .takes_value(true)
                .help("RC4 Kerberos key (NTLM hash of user)")
                .validator(validators::is_rc4_key),
        )
        .arg(
            Arg::with_name("aes")
                .long("aes")
                .takes_value(true)
                .help("AES Kerberos key of user")
                .validator(validators::is_aes_key),
        )
        .group(
            ArgGroup::with_name("user_key")
                .args(&["password", "rc4", "aes"])
                .multiple(false),
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
            Arg::with_name("etype")
                .long("etype")
                .help("Encryption algorithm requested to server.")
                .possible_values(&["rc4", "aes128", "aes256"])
                .takes_value(true),
        )
        .arg(
            Arg::with_name("crack-format")
                .long("crack-format")
                .takes_value(true)
                .possible_values(&["hashcat", "john"])
                .help("Format to save non preauth responses.")
                .default_value("hashcat"),
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
                .alias("ticket-file")
                .takes_value(true)
                .value_name("file")
                .help("File to load/save tickets"),
        )
        .arg(
            Arg::with_name("save")
                .long("save")
                .help("Retrieved tickets should be saved"),
        )
}

#[derive(Debug)]
pub struct Arguments {
    pub user: KrbUser,
    pub user_key: Option<Key>,
    pub kdc_ip: Option<IpAddr>,
    pub kdc_port: u16,
    pub credential_format: CredFormat,
    pub crack_format: CrackFormat,
    pub services: String,
    pub transport_protocol: TransportProtocol,
    pub verbosity: usize,
    pub etype: Option<i32>,
    pub save_tickets: bool,
    pub creds_file: Option<String>,
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
        let user_key = self.parse_user_key();
        let kdc_ip = self.parse_kdc_ip();
        let credential_format = self.parse_ticket_format();
        let services = self.parse_services();

        return Arguments {
            user: self.matches.value_of("user").unwrap().try_into().unwrap(),
            user_key,
            kdc_ip,
            kdc_port: 88,
            credential_format,
            services,
            transport_protocol: self.parse_transport_protocol(),
            verbosity: self.matches.occurrences_of("verbosity") as usize,
            crack_format: self.parse_crack_format(),
            etype: self.parse_etype(),
            save_tickets: self.matches.is_present("save"),
            creds_file: self.parse_credentials_file(),
        };
    }

    fn parse_kdc_ip(&self) -> Option<IpAddr> {
        let kdc_ip = self.matches.value_of("kdc-ip")?;
        return Some(kdc_ip.parse::<IpAddr>().unwrap());
    }

    fn parse_user_key(&self) -> Option<Key> {
        if let Some(password) = self.matches.value_of("password") {
            return Some(Key::Secret(password.to_string()));
        } else if let Some(ntlm) = self.matches.value_of("rc4") {
            return Some(Key::from_rc4_key_string(ntlm).unwrap());
        } else if let Some(aes_key) = self.matches.value_of("aes") {
            if let Ok(key) = Key::from_aes_128_key_string(aes_key) {
                return Some(key)
            }
            return Some(Key::from_aes_256_key_string(aes_key).unwrap());
        }

        return None;
    }

    fn parse_ticket_format(&self) -> CredFormat {
        let format = self.matches.value_of("cred-format").unwrap();

        if format == "krb" {
            return CredFormat::Krb;
        }

        return CredFormat::Ccache;
    }

    fn parse_credentials_file(&self) -> Option<String> {
        return self.matches.value_of("cred-file").map(|s| s.into());
    }

    fn parse_services(&self) -> String {
        return self.matches.value_of("services").unwrap().into();
    }

    fn parse_transport_protocol(&self) -> TransportProtocol {
        if self.matches.is_present("udp") {
            return TransportProtocol::UDP;
        }

        return TransportProtocol::TCP;
    }

    fn parse_crack_format(&self) -> CrackFormat {
        let format = self.matches.value_of("crack-format").unwrap();

        if format == "john" {
            return CrackFormat::John;
        }

        return CrackFormat::Hashcat;
    }

    fn parse_etype(&self) -> Option<i32> {
        let etype = match self.matches.value_of("etype")? {
            "rc4" => etypes::RC4_HMAC,
            "aes128" => etypes::AES128_CTS_HMAC_SHA1_96,
            "aes256" => etypes::AES256_CTS_HMAC_SHA1_96,
            _ => unreachable!("Unknown etype"),
        };
        return Some(etype);
    }
}
