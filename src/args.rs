use crate::cred_format::CredentialFormat;
use clap::{App, Arg, ArgGroup, ArgMatches};
use kerberos_crypto::Key;
use std::net::IpAddr;
use crate::transporter::TransportProtocol;

pub fn args() -> App<'static, 'static> {
    App::new(env!("CARGO_PKG_NAME"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
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
                .help("Password of user"),
        )
        .arg(
            Arg::with_name("rc4")
                .long("rc4")
                .alias("ntlm")
                .takes_value(true)
                .help("RC4 Kerberos key (NTLM hash of user)")
                .validator(is_rc4_key),
        )
        .arg(
            Arg::with_name("aes-128")
                .long("aes-128")
                .takes_value(true)
                .help("AES 128 Kerberos key of user")
                .validator(is_aes_128_key),
        )
        .arg(
            Arg::with_name("aes-256")
                .long("aes-256")
                .takes_value(true)
                .help("AES 256 Kerberos key of user")
                .validator(is_aes_256_key),
        )
        .group(
            ArgGroup::with_name("user_key")
                .args(&["password", "rc4", "aes-128", "aes-256"])
                .multiple(false)
                .required(true),
        )
        .arg(
            Arg::with_name("kdc-ip")
                .long("kdc-ip")
                .alias("dc-ip")
                .short("k")
                .value_name("ip")
                .takes_value(true)
                .required(true)
                .help("The address of the KDC (usually the Domain Controller)")
                .validator(is_ip),
        )
        .arg(
            Arg::with_name("service")
                .long("service")
                .alias("spn")
                .takes_value(true)
                .value_name("spn")
                .help("SPN of the desired service"),
        )
        .arg(
            Arg::with_name("ticket-format")
                .long("ticket-format")
                .takes_value(true)
                .possible_values(&["krb", "ccache"])
                .help("Format to save retrieved tickets.")
                .default_value("ccache"),
        )
        .arg(
            Arg::with_name("out-file")
                .long("out-file")
                .takes_value(true)
                .value_name("file")
                .help("File to save ticket"),
        )
        .arg(
            Arg::with_name("no-preauth")
                .long("no-preauth")
                .help("Request ticket without send preauthentication data"),
        )
        .arg(
            Arg::with_name("udp")
                .long("udp")
                .help("Use udp as transport protocol"),
        )
}

fn is_rc4_key(v: String) -> Result<(), String> {
    Key::from_rc4_key_string(&v).map_err(|_| {
        format!(
            "Invalid RC4 key '{}', must be a string of 32 hexadecimals",
            v
        )
    })?;

    return Ok(());
}

fn is_aes_128_key(v: String) -> Result<(), String> {
    Key::from_aes_128_key_string(&v).map_err(|_| {
        format!(
            "Invalid AES-128 key '{}', must be a string of 32 hexadecimals",
            v
        )
    })?;

    return Ok(());
}

fn is_aes_256_key(v: String) -> Result<(), String> {
    Key::from_aes_256_key_string(&v).map_err(|_| {
        format!(
            "Invalid AES-256 key '{}', must be a string of 64 hexadecimals",
            v
        )
    })?;

    return Ok(());
}

fn is_ip(v: String) -> Result<(), String> {
    v.parse::<IpAddr>()
        .map_err(|_| format!("Invalid IP address '{}'", v))?;
    return Ok(());
}

#[derive(Debug)]
pub struct Arguments {
    pub realm: String,
    pub username: String,
    pub user_key: Key,
    pub kdc_ip: IpAddr,
    pub kdc_port: u16,
    pub ticket_format: CredentialFormat,
    pub preauth: bool,
    pub out_file: String,
    pub service: Option<String>,
    pub transport_protocol: TransportProtocol
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
        let username: String = self.matches.value_of("user").unwrap().into();
        let user_key = self.parse_user_key();
        let kdc_ip = self.parse_kdc_ip();
        let ticket_format = self.parse_ticket_format();
        let out_file = self.parse_out_file(&username, &ticket_format);
        let service = self.parse_service();

        return Arguments {
            realm,
            username,
            user_key,
            kdc_ip,
            kdc_port: 88,
            ticket_format,
            preauth: !self.matches.is_present("no-preauth"),
            out_file,
            service,
            transport_protocol: self.parse_transport_protocol(),
        };
    }

    fn parse_kdc_ip(&self) -> IpAddr {
        let kdc_ip = self.matches.value_of("kdc-ip").unwrap();
        return kdc_ip.parse::<IpAddr>().unwrap();
    }

    fn parse_user_key(&self) -> Key {
        if let Some(password) = self.matches.value_of("password") {
            return Key::Secret(password.to_string());
        } else if let Some(ntlm) = self.matches.value_of("rc4") {
            return Key::from_rc4_key_string(ntlm).unwrap();
        } else if let Some(aes_128_key) = self.matches.value_of("aes-128") {
            return Key::from_aes_128_key_string(aes_128_key).unwrap();
        } else if let Some(aes_256_key) = self.matches.value_of("aes-256") {
            return Key::from_aes_256_key_string(aes_256_key).unwrap();
        }

        unreachable!("No key specified");
    }

    fn parse_ticket_format(&self) -> CredentialFormat {
        let format = self.matches.value_of("ticket-format").unwrap();

        if format == "krb" {
            return CredentialFormat::Krb;
        }

        return CredentialFormat::Ccache;
    }

    fn parse_out_file(
        &self,
        username: &str,
        ticket_format: &CredentialFormat,
    ) -> String {
        if let Some(filename) = self.matches.value_of("out-file") {
            return filename.into();
        }

        return format!("{}.{}", username, ticket_format);
    }

    fn parse_service(&self) -> Option<String> {
        return self.matches.value_of("service").map(|s| s.into());
    }

    fn parse_transport_protocol(&self) -> TransportProtocol {
        if self.matches.is_present("udp") {
            return TransportProtocol::UDP;
        }

        return TransportProtocol::TCP;
    }
}
