use super::validators;
use crate::communication::{Kdcs, TransportProtocol};
use crate::core::{CredFormat, KrbUser};
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use kerberos_crypto::Key;
use std::convert::{TryFrom, TryInto};
use std::net::IpAddr;

pub const COMMAND_NAME: &str = "ask";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Ask for tickets")
        .arg(
            Arg::with_name("user")
                .long("user")
                .short("u")
                .value_name("domain/username")
                .takes_value(true)
                .help("User for request the ticket")
                .required(true)
                .validator(validators::is_krb_user),
        )
        .arg(
            Arg::with_name("impersonate")
                .long("impersonate")
                .short("i")
                .value_name("[domain/]username")
                .takes_value(true)
                .help("Username to impersonate for request the ticket")
                .validator(validators::is_krb_user_or_username),
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
                .help("RC4 Kerberos key of user (NT hash)")
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
            Arg::with_name("kdc")
                .long("kdc")
                .visible_alias("dc")
                .short("k")
                .value_name("[domain:]ip")
                .takes_value(true)
                .use_delimiter(true)
                .help("The address of the KDC (usually the Domain Controller)")
                .validator(validators::is_kdc_domain_ip),
        )
        .arg(
            Arg::with_name("service")
                .long("service")
                .visible_alias("spn")
                .short("s")
                .takes_value(true)
                .value_name("SPN")
                .help("SPN of the target service"),
        )
        .arg(
            Arg::with_name("user-service")
                .long("user-service")
                .visible_alias("user-spn")
                .takes_value(true)
                .value_name("SPN")
                .help("SPN of a user service to impersonate with S4U2self"),
        )
        .arg(
            Arg::with_name("rename-service")
                .long("rename-service")
                .value_name("SPN")
                .takes_value(true)
                .help("change the target service of the received TGS, useful for S4U2proxy")
        )
        .arg(
            Arg::with_name("cred-format")
                .long("cred-format")
                .visible_alias("ticket-format")
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
                .help("File to save ticket"),
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
}

#[derive(Debug)]
pub struct Arguments {
    pub user: KrbUser,
    pub user_key: Option<Key>,
    pub user_service: Option<String>,
    pub kdcs: Kdcs,
    pub credential_format: CredFormat,
    pub out_file: Option<String>,
    pub service: Option<String>,
    pub rename_service: Option<String>,
    pub transport_protocol: TransportProtocol,
    pub impersonate_user: Option<KrbUser>,
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
        let user: KrbUser =
            self.matches.value_of("user").unwrap().try_into().unwrap();
        let user_key = self.parse_user_key();
        let kdcs = self.parse_kdcs(&user.realm);
        let credential_format = self.parse_ticket_format();
        let out_file = self.parse_credentials_file();
        let service = self.parse_service();
        let imp_user = self.parse_impersonate_user(&user.realm);

        return Arguments {
            user,
            user_key,
            user_service: self
                .matches
                .value_of("user-service")
                .map(|s| s.into()),
            kdcs,
            credential_format,
            out_file,
            service,
            rename_service: self
                .matches
                .value_of("rename-service")
                .map(|s| s.into()),
            transport_protocol: self.parse_transport_protocol(),
            impersonate_user: imp_user,
            verbosity: self.matches.occurrences_of("verbosity") as usize,
        };
    }

    fn parse_kdcs(&self, default_realm: &str) -> Kdcs {
        let mut kdcs = Kdcs::new();
        if let Some(kdcs_str) = self.matches.values_of("kdc") {
            for kdc_str in kdcs_str {
                let mut parts: Vec<&str> = kdc_str.split(":").collect();

                let kdc_ip_str = parts.pop().unwrap();
                let kdc_ip = kdc_ip_str.parse::<IpAddr>().unwrap();
                let kdc_realm;
                if parts.is_empty() {
                    kdc_realm = default_realm.to_string();
                } else {
                    kdc_realm = parts.join(":");
                }
                kdcs.insert(kdc_realm, kdc_ip);
            }
        }
        return kdcs;
    }

    fn parse_user_key(&self) -> Option<Key> {
        if let Some(password) = self.matches.value_of("password") {
            return Some(Key::Secret(password.to_string()));
        } else if let Some(ntlm) = self.matches.value_of("rc4") {
            return Some(Key::from_rc4_key_string(ntlm).unwrap());
        } else if let Some(aes_key) = self.matches.value_of("aes") {
            if let Ok(key) = Key::from_aes_128_key_string(aes_key) {
                return Some(key);
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

    fn parse_service(&self) -> Option<String> {
        return self.matches.value_of("service").map(|s| s.into());
    }

    fn parse_transport_protocol(&self) -> TransportProtocol {
        if self.matches.is_present("udp") {
            return TransportProtocol::UDP;
        }

        return TransportProtocol::TCP;
    }

    fn parse_impersonate_user(&self, default_domain: &str) -> Option<KrbUser> {
        let user_str = self.matches.value_of("impersonate")?;

        let parts: Vec<&str> = user_str.split("/").collect();

        if parts.len() == 1 {
            return Some(KrbUser::new(
                user_str.to_string(),
                default_domain.to_string(),
            ));
        }
        return Some(KrbUser::try_from(user_str).unwrap());
    }
}
