//! Utilies related with crack formats parsed by john and hashcat
//! used by asreproast and kerberoast

use kerberos_asn1::{AsRep, Asn1Object, EtypeInfo2, Ticket};
use kerberos_constants::pa_data_types::PA_ETYPE_INFO2;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CrackFormat {
    Hashcat,
    John
}


pub fn as_rep_to_crack_string(
    username: &str,
    as_rep: &AsRep,
    crack_format: CrackFormat,
) -> String {
    let etype = as_rep.enc_part.etype;
    let realm = &as_rep.crealm;
    let salt = get_encryption_salt(as_rep);
    let ciphertext = &as_rep.enc_part.cipher;
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
    let salt = vec![0];
    let etype = ticket.enc_part.etype;
    let realm = &ticket.realm;
    let ciphertext = &ticket.enc_part.cipher.clone();

    let salt_hexa = arr_u8_to_hexa_string(&salt);
    let cipher_hexa = arr_u8_to_hexa_string(&ciphertext);

    match crack_format {
        CrackFormat::Hashcat => format!(
            "$krb5tgs${}${}${}${}${}${}",
            etype, user, realm, serv, salt_hexa, cipher_hexa
        ),
        CrackFormat::John => format!(
            "$krb5tgs${}@{}${}:{}${}",
            user, realm, serv, salt_hexa, cipher_hexa
        ),
    }
}

fn arr_u8_to_hexa_string(array: &[u8]) -> String {
    let mut hexa_string = String::new();
    for item in array.iter() {
        hexa_string.push_str(&format!("{:x}", item));
    }
    return hexa_string;
}

fn get_encryption_salt(as_rep: &AsRep) -> Vec<u8> {
    if let Some(padata) = &as_rep.padata {
        for entry_data in padata.iter() {
            if entry_data.padata_type == PA_ETYPE_INFO2 {
                match EtypeInfo2::parse(&entry_data.padata_value) {
                    Ok((_, etypeinfo2)) => {
                        for entry in etypeinfo2 {
                            match entry.salt {
                                Some(salt) => return salt.as_bytes().to_vec(),
                                None => {}
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    return Vec::new();
}
