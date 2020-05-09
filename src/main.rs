use chrono::{Duration, Utc};
use clap::{App, Arg, ArgGroup, ArgMatches};
use kerberos_asn1::{
    AsRep, AsReq, Asn1Object, EncAsRepPart, EncryptedData, KerbPaPacRequest,
    KerberosTime, KrbError, PaData, PaEncTsEnc, PrincipalName, KrbCredInfo,
    KrbCred, EncKrbCredPart
};
use kerberos_constants;
use kerberos_constants::{
    error_codes, etypes, kdc_options, key_usages, pa_data_types,
    principal_names,
};
use kerberos_crypto::{AESCipher, AesSizes, KerberosCipher};
use rand;
use rand::Rng;
use std::io;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::net::{SocketAddr, TcpStream};
use std::time;
use std::fs;

fn args() -> App<'static, 'static> {
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
}

fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    let mut as_req_builder = AsReqBuilder::new(args.domain.clone())
        .username(args.username.clone())
        .request_pac();

    if let Some(password) = &args.user_password {
        let timestamp = PaEncTsEnc::from(Utc::now());
        let aes_salt = generate_aes_salt(&args.domain, &args.username);

        let aes256_cipher = AESCipher::new(AesSizes::Aes256);

        let key = aes256_cipher.generate_key_from_password(password, &aes_salt);

        let encrypted_timestamp = aes256_cipher.encrypt(
            &key,
            key_usages::KEY_USAGE_AS_REQ_TIMESTAMP,
            &timestamp.build(),
        );

        as_req_builder = as_req_builder.push_padata(PaData::new(
            pa_data_types::PA_ENC_TIMESTAMP,
            EncryptedData::new(
                etypes::AES256_CTS_HMAC_SHA1_96,
                None,
                encrypted_timestamp,
            )
            .build(),
        ));
    }

    let as_req = as_req_builder.build();

    let socket_addr = SocketAddr::new(args.kdc_ip, 88);
    let raw_as_req = as_req.build();

    let raw_response = send_recv_tcp(&socket_addr, &raw_as_req)
        .expect("Error in send_recv_tcp");

    match KrbError::parse(&raw_response) {
        Ok((_, krb_error)) => {
            let error_string =
                error_codes::error_code_to_string(krb_error.error_code);
            eprintln!(" Error {}: {}", krb_error.error_code, error_string);
        }
        Err(_) => match AsRep::parse(&raw_response) {
            Ok((_, as_rep)) => {
                let ticket = as_rep.ticket;
                let krb_cred_info;

                // decrypt as_rep.enc_part
                if let Some(password) = &args.user_password {
                    let aes_salt =
                        generate_aes_salt(&args.domain, &args.username);

                    let aes256_cipher = AESCipher::new(AesSizes::Aes256);

                    let key = aes256_cipher
                        .generate_key_from_password(password, &aes_salt);

                    let raw_enc_as_req_part = aes256_cipher
                        .decrypt(
                            &key,
                            key_usages::KEY_USAGE_AS_REP_ENC_PART,
                            &as_rep.enc_part.cipher,
                        )
                        .expect("Unable to decrypt the enc_as_req_part");

                    let (_, enc_as_req_part) =
                        EncAsRepPart::parse(&raw_enc_as_req_part)
                        .expect("Error parsing EncAsRepPart");

                    krb_cred_info = KrbCredInfo {
                        key: enc_as_req_part.key,
                        prealm: Some(as_req.req_body.realm),
                        pname: as_req.req_body.cname,
                        flags: Some(enc_as_req_part.flags),
                        authtime: Some(enc_as_req_part.authtime),
                        starttime: enc_as_req_part.starttime,
                        endtime: Some(enc_as_req_part.endtime),
                        renew_till: enc_as_req_part.renew_till,
                        srealm: Some(enc_as_req_part.srealm),
                        sname: Some(enc_as_req_part.sname),
                        caddr: enc_as_req_part.caddr,
                    };
                    
                } else {
                    eprintln!("No way to decrypt the response without credentials");
                    return;
                }

                let mut enc_krb_cred_part = EncKrbCredPart::default();
                enc_krb_cred_part.ticket_info.push(krb_cred_info);
                
                let mut krb_cred = KrbCred::default();
                krb_cred.tickets.push(ticket);
                krb_cred.enc_part = EncryptedData {
                    etype: etypes::NO_ENCRYPTION,
                    kvno: None,
                    cipher: enc_krb_cred_part.build()
                };

                fs::write("tatata.krb", krb_cred.build()).expect("Unable to write file");
                
            }
            Err(err) => {
                eprintln!("Error parsing server responsed: {}", err);
            }
        },
    }
}

struct AsReqBuilder {
    realm: String,
    sname: Option<PrincipalName>,
    etypes: Vec<i32>,
    kdc_options: u32,
    cname: Option<PrincipalName>,
    padatas: Vec<PaData>,
    nonce: u32,
    till: KerberosTime,
    rtime: Option<KerberosTime>,
}

impl AsReqBuilder {
    pub fn new(realm: String) -> Self {
        return Self {
            realm: realm.clone(),
            sname: Some(PrincipalName {
                name_type: principal_names::NT_PRINCIPAL,
                name_string: vec!["krbtgt".into(), realm],
            }),
            etypes: supported_etypes(),
            kdc_options: kdc_options::FORWARDABLE
                | kdc_options::RENEWABLE
                | kdc_options::CANONICALIZE
                | kdc_options::RENEWABLE_OK,
            cname: None,
            padatas: Vec::new(),
            nonce: rand::thread_rng().gen(),
            till: Utc::now()
                .checked_add_signed(Duration::weeks(20 * 52))
                .unwrap()
                .into(),
            rtime: Some(
                Utc::now()
                    .checked_add_signed(Duration::weeks(20 * 52))
                    .unwrap()
                    .into(),
            ),
        };
    }

    pub fn cname(mut self, cname: Option<PrincipalName>) -> Self {
        self.cname = cname;
        self
    }

    pub fn username(self, username: String) -> Self {
        self.cname(Some(PrincipalName {
            name_type: principal_names::NT_PRINCIPAL,
            name_string: vec![username],
        }))
    }

    pub fn push_padata(mut self, padata: PaData) -> Self {
        self.padatas.push(padata);
        self
    }

    pub fn request_pac(self) -> Self {
        self.push_padata(PaData::new(
            pa_data_types::PA_PAC_REQUEST,
            KerbPaPacRequest::new(true).build(),
        ))
    }

    pub fn build(self) -> AsReq {
        let mut as_req = AsReq::default();

        as_req.req_body.kdc_options = self.kdc_options.into();
        as_req.req_body.cname = self.cname;
        as_req.req_body.realm = self.realm;
        as_req.req_body.sname = self.sname;
        as_req.req_body.till = self.till;
        as_req.req_body.rtime = self.rtime;
        as_req.req_body.nonce = self.nonce;
        as_req.req_body.etypes = self.etypes;

        if self.padatas.len() > 0 {
            as_req.padata = Some(self.padatas);
        }

        return as_req;
    }
}

fn send_recv_tcp(
    dst_addr: &SocketAddr,
    raw_request: &[u8],
) -> io::Result<Vec<u8>> {
    let mut tcp_stream =
        TcpStream::connect_timeout(dst_addr, time::Duration::new(5, 0))?;

    let raw_sized_request = set_size_header_to_request(raw_request);
    tcp_stream.write(&raw_sized_request)?;

    let mut len_data_bytes = [0 as u8; 4];
    tcp_stream.read_exact(&mut len_data_bytes)?;
    let data_length = u32::from_be_bytes(len_data_bytes);

    let mut raw_response: Vec<u8> = vec![0; data_length as usize];
    tcp_stream.read_exact(&mut raw_response)?;

    return Ok(raw_response);
}

fn set_size_header_to_request(raw_request: &[u8]) -> Vec<u8> {
    let request_length = raw_request.len() as u32;
    let mut raw_sized_request: Vec<u8> = request_length.to_be_bytes().to_vec();
    raw_sized_request.append(&mut raw_request.to_vec());

    return raw_sized_request;
}

// añadir esta y funcion que devuelva los supported etypes en kerberos cryptox
fn generate_aes_salt(realm: &str, client_name: &str) -> Vec<u8> {
    let mut salt = realm.to_uppercase();
    let mut lowercase_username = client_name.to_lowercase();

    if lowercase_username.ends_with("$") {
        salt.push_str("host");
        lowercase_username.pop();
    }
    salt.push_str(&lowercase_username);

    return salt.as_bytes().to_vec();
}

fn supported_etypes() -> Vec<i32> {
    vec![
        etypes::RC4_HMAC,
        etypes::AES128_CTS_HMAC_SHA1_96,
        etypes::AES256_CTS_HMAC_SHA1_96,
    ]
}
