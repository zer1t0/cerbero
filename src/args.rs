use clap::{App, Arg, ArgGroup, ArgMatches};
use std::net::IpAddr;


pub fn args() -> App<'static, 'static> {
    App::new(env!("CARGO_PKG_NAME"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("domain")
                .long("domain")
                .short("d")
                .takes_value(true)
                .help("Domain for request the ticket")
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
            Arg::with_name("ntlm")
                .long("ntlm")
                .takes_value(true)
                .help("NTLM hash of user"),
        )
        .arg(
            Arg::with_name("aes-128")
                .long("aes-128")
                .takes_value(true)
                .help("AES 128 Kerberos key of user"),
        )
        .arg(
            Arg::with_name("aes-256")
                .long("aes-256")
                .takes_value(true)
                .help("AES 256 Kerberos key of user"),
        )
        .group(
            ArgGroup::with_name("user_key")
                .args(&["password", "ntlm", "aes-128", "aes-256"])
                .multiple(false),
        )
        .arg(
            Arg::with_name("kdc-ip")
                .long("kdc-ip")
                .short("k")
                .value_name("ip")
                .takes_value(true)
                .required(true)
                .help("The address of the KDC"),
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
                .help("File to save TGT."),
        )
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TicketFormat {
    Krb,
    Ccache,
}

pub struct Arguments {
    pub domain: String,
    pub username: String,
    pub user_password: Option<String>,
    pub user_key: Option<kerbeiros::Key>,
    pub kdc_ip: IpAddr,
    pub ticket_format: TicketFormat
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
        let domain = self.matches.value_of("domain").unwrap().into();
        let username = self.matches.value_of("user").unwrap().into();
        let user_key = self.parse_user_key();
        let kdc_ip = self.parse_kdc_ip();
        let user_password = self.parse_user_password();

        return Arguments {
            domain,
            username,
            user_key,
            kdc_ip,
            user_password,
            ticket_format: self.parse_ticket_format()
        };
    }

    fn parse_kdc_ip(&self) -> IpAddr {
        let kdc_ip = self.matches.value_of("kdc-ip").unwrap();
        return kdc_ip.parse::<IpAddr>().unwrap();
    }

    fn parse_user_password(&self) -> Option<String> {
        return Some(self.matches.value_of("password")?.into());
    }

    fn parse_user_key(&self) -> Option<kerbeiros::Key> {
        if let Some(password) = self.matches.value_of("password") {
            return Some(kerbeiros::Key::Password(password.to_string()));
        } else if let Some(ntlm) = self.matches.value_of("ntml") {
            return Some(kerbeiros::Key::from_rc4_key_string(ntlm).unwrap());
        } else if let Some(aes_128_key) = self.matches.value_of("aes-128") {
            return Some(
                kerbeiros::Key::from_aes_128_key_string(aes_128_key).unwrap(),
            );
        } else if let Some(aes_256_key) = self.matches.value_of("aes-256") {
            return Some(
                kerbeiros::Key::from_aes_256_key_string(aes_256_key).unwrap(),
            );
        }
        return None;
    }

    fn parse_ticket_format(&self) -> TicketFormat {
        let format = self.matches.value_of("ticket-format").unwrap();

        if format == "krb" {
            return TicketFormat::Krb;
        }

        return TicketFormat::Ccache;
    }
}
