use crate::core::KrbUser;
use crate::Result;
use kerberos_crypto::{aes_hmac_sha1, rc4_hmac_md5, AesSizes};

pub fn hash(password: &str, user: Option<&KrbUser>) -> Result<()> {
    let rc4_key = rc4_hmac_md5::generate_key_from_string(password);
    println!("rc4:{}", get_hex(&rc4_key));

    if let Some(user) = user {
        let aes_salt = aes_hmac_sha1::generate_salt(&user.realm, &user.name);

        let aes_128_key = aes_hmac_sha1::generate_key_from_string(
            password,
            &aes_salt,
            &AesSizes::Aes128,
        );
        let aes_256_key = aes_hmac_sha1::generate_key_from_string(
            password,
            &aes_salt,
            &AesSizes::Aes256,
        );

        println!("aes128:{}", get_hex(&aes_128_key));
        println!("aes256:{}", get_hex(&aes_256_key));
    }

    return Ok(());
}

fn get_hex(v: &[u8]) -> String {
    let mut s = String::new();
    for x in v {
        s = format!("{}{:02x}", s, x)
    }

    return s;
}
