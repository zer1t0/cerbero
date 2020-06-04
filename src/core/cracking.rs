//! Utilies related with crack formats parsed by john and hashcat
//! used by asreproast and kerberoast

use kerberos_asn1::{AsRep, Ticket};
use kerberos_constants::etypes;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CrackFormat {
    Hashcat,
    John,
}

pub fn as_rep_to_crack_string(
    username: &str,
    as_rep: &AsRep,
    crack_format: CrackFormat,
) -> String {
    let etype = as_rep.enc_part.etype;
    let realm = &as_rep.crealm;

    let (salt, ciphertext) =
        divide_salt_and_ciphertext(etype, as_rep.enc_part.cipher.to_vec());
    let salt_hexa = arr_u8_to_hexa_string(&salt);
    let cipher_hexa = arr_u8_to_hexa_string(&ciphertext);

    match crack_format {
        CrackFormat::Hashcat => format!(
            "$krb5asrep${}${}@{}:{}${}",
            etype, username, realm, salt_hexa, cipher_hexa
        ),
        CrackFormat::John => format!(
            "$krb5asrep${}@{}:{}${}",
            username, realm, salt_hexa, cipher_hexa
        ),
    }
}

pub fn tgs_to_crack_string(
    username: &str,
    service: &str,
    ticket: &Ticket,
    crack_format: CrackFormat,
) -> String {
    let user = username;
    let serv = service.replace(":", "~");
    let etype = ticket.enc_part.etype;
    let realm = &ticket.realm;
    let (salt, ciphertext) =
        divide_salt_and_ciphertext(etype, ticket.enc_part.cipher.to_vec());

    let salt_hexa = arr_u8_to_hexa_string(&salt);
    let cipher_hexa = arr_u8_to_hexa_string(&ciphertext);

    match crack_format {
        CrackFormat::Hashcat => match etype {
            etypes::AES128_CTS_HMAC_SHA1_96
            | etypes::AES256_CTS_HMAC_SHA1_96 => format!(
                "$krb5tgs${}${}${}$*{}*${}${}",
                etype, user, realm, serv, salt_hexa, cipher_hexa
            ),
            _ => format!(
                "$krb5tgs${}$*{}${}${}*${}${}",
                etype, user, realm, serv, salt_hexa, cipher_hexa
            ),
        },
        CrackFormat::John => format!(
            "$krb5tgs${}@{}${}:{}${}",
            user, realm, serv, salt_hexa, cipher_hexa
        ),
    }
}

fn divide_salt_and_ciphertext(
    etype: i32,
    cipher: Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    let mut salt;
    let mut ciphertext;
    if etype == etypes::AES128_CTS_HMAC_SHA1_96
        || etype == etypes::AES256_CTS_HMAC_SHA1_96
    {
        let index = cipher.len() - 12;
        ciphertext = cipher;
        salt = ciphertext.drain(index..).collect();
    } else {
        salt = cipher;
        ciphertext = salt.drain(16..).collect();
    }

    return (salt, ciphertext);
}

fn arr_u8_to_hexa_string(array: &[u8]) -> String {
    let mut hexa_string = String::new();
    for item in array.iter() {
        hexa_string.push_str(&format!("{:02x}", item));
    }
    return hexa_string;
}
